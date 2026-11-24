use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Weak};
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::{FeeRate, Network, OutPoint};
use fedimint_bip39::Mnemonic;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::is_running_in_test_env;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::{TaskGroup, TaskHandle, block_in_place, sleep};
use fedimint_core::util::backoff_util::{self, FibonacciBackoff};
use fedimint_core::util::{FmtCompact, SafeUrl};
use fedimint_core::{Amount, BitcoinAmountOrAll, crit};
use fedimint_gateway_common::{
    ChainSource, ConnectPeerRequest, GetInvoiceRequest, GetInvoiceResponse,
    ListTransactionsResponse, NodeAddress, SetChannelFeesRequest,
};
use fedimint_ln_common::contracts::Preimage;
use fedimint_logging::{LOG_LIGHTNING, LOG_LIGHTNING_LDK};
use ldk_node::config::ChannelConfig;
use ldk_node::external_bolt12::ExternalInvoiceRequest;
use ldk_node::io::sqlite_store::{KV_TABLE_NAME, SQLITE_DB_FILE_NAME, SqliteStore};
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning::routing::gossip::{NodeAlias, NodeId};
use ldk_node::logger::{LogLevel, LogRecord, LogWriter};
use ldk_node::payment::{PaymentDetails, PaymentDirection, PaymentKind, PaymentStatus};
use lightning::blinded_path::message::BlindedMessagePath;
use lightning::blinded_path::payment::BlindedPaymentPath;
use lightning::ln::channelmanager::PaymentId;
use lightning::offers::invoice_request::InvoiceRequest;
use lightning::offers::offer::{Offer, OfferId};
use lightning::routing::router::RouteParametersConfig;
use lightning::types::payment::{PaymentHash, PaymentPreimage};
use lightning::util::persist::KVStoreSync;
use lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use thiserror::Error;
use tokio::sync::mpsc::Sender;
use tokio::sync::{Mutex, RwLock, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tracing::{debug, error, info, trace, warn};

use super::{ChannelInfo, ILnRpcClient, LightningRpcError, ListChannelsResponse, RouteHtlcStream};
use crate::bolt12::{Bolt12Request, Bolt12RequestFilter, MAX_QUEUED_BOLT12_REQUESTS};
use crate::{
    CloseChannelsWithPeerRequest, CloseChannelsWithPeerResponse, CreateInvoiceRequest,
    CreateInvoiceResponse, GetBalancesResponse, GetLnOnchainAddressResponse, GetNodeInfoResponse,
    GetRouteHintsResponse, InterceptPaymentRequest, InterceptPaymentResponse, InvoiceDescription,
    NO_INCOMING_CIRCUIT, OpenChannelRequest, OpenChannelResponse, PayInvoiceResponse,
    PaymentAction, SendOnchainRequest, SendOnchainResponse,
};

/// Forwards `ldk-node`'s log records into the gateway's `tracing` subscriber.
///
/// By default `ldk-node` writes to its own append-only `ldk_node/ldk_node.log`
/// file, which is invisible to stdout/stderr log collectors and grows without
/// bound. Routing the records through `tracing` (under the
/// [`LOG_LIGHTNING_LDK`] target) puts them alongside the rest of gatewayd's
/// logs and makes them filterable via `RUST_LOG`.
struct LdkTracingLogger {
    /// Whether we're running under devimint/tests. When set, some benign LDK
    /// error logs that are expected in regtest are downgraded to avoid spamming
    /// the test output. See [`Self::downgraded_level`].
    in_test_env: bool,
}

impl LdkTracingLogger {
    /// Returns the level to emit `record` at, downgrading benign-but-noisy LDK
    /// errors when running under devimint/tests.
    ///
    /// In regtest there is no fee-rate history, so `ldk-node` logs "Failed to
    /// retrieve fee rate estimates ... Falling back to default" at `Error` on
    /// essentially every sync. This is harmless (LDK falls back to a default
    /// feerate), so in test environments we emit it at `Debug` instead. In
    /// production the original `Error` level is preserved, since a persistent
    /// failure there can indicate a real problem.
    fn downgraded_level(&self, record: &LogRecord<'_>) -> LogLevel {
        if self.in_test_env
            && record.level == LogLevel::Error
            && record.module_path == "ldk_node::chain"
            && format!("{}", record.args).contains("Failed to retrieve fee rate estimates")
        {
            LogLevel::Debug
        } else {
            record.level
        }
    }
}

impl LogWriter for LdkTracingLogger {
    fn log(&self, record: LogRecord<'_>) {
        // `tracing` requires a static level per call-site, so match each LDK level.
        match self.downgraded_level(&record) {
            LogLevel::Gossip | LogLevel::Trace => trace!(
                target: LOG_LIGHTNING_LDK,
                ldk_module = record.module_path, line = record.line, "{}", record.args,
            ),
            LogLevel::Debug => debug!(
                target: LOG_LIGHTNING_LDK,
                ldk_module = record.module_path, line = record.line, "{}", record.args,
            ),
            LogLevel::Info => info!(
                target: LOG_LIGHTNING_LDK,
                ldk_module = record.module_path, line = record.line, "{}", record.args,
            ),
            LogLevel::Warn => warn!(
                target: LOG_LIGHTNING_LDK,
                ldk_module = record.module_path, line = record.line, "{}", record.args,
            ),
            LogLevel::Error => error!(
                target: LOG_LIGHTNING_LDK,
                ldk_module = record.module_path, line = record.line, "{}", record.args,
            ),
        }
    }
}

/// The namespaces of the gateway's held-payment records in the node's store.
/// LDK Node uses neither.
const HELD_PAYMENTS_PRIMARY_NAMESPACE: &str = "fedimint_gateway";
const HELD_PAYMENTS_SECONDARY_NAMESPACE: &str = "held_payments";

/// Where the highest block height the gateway has seen the node reach is
/// kept, next to the held-payment records; see
/// [`HeldPaymentStore::observe_height`].
const OBSERVED_HEIGHT_SECONDARY_NAMESPACE: &str = "observed_height";
const OBSERVED_HEIGHT_KEY: &str = "best_block_height";

/// How long to wait before handling an event again that could not be handled
/// because the store failed to record its held payment.
const HELD_PAYMENT_RECORD_RETRY: Duration = Duration::from_secs(1);

/// How often to check whether the node has processed a new block, after which
/// the records of the payments it can no longer claim are removed.
const HELD_PAYMENT_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

/// How often to check whether the node has synced to the chain since it
/// started.
const CHAIN_SYNC_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// A payment the node holds for the gateway to settle or fail, as reported by
/// its `PaymentClaimable` event.
#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable)]
struct HeldPayment {
    claimable_amount_msat: u64,
    claim_deadline: Option<u32>,
    /// Whether the gateway has started to fail the payment back; see
    /// [`HeldPaymentStore::fail_back`].
    failing_back: bool,
}

impl HeldPayment {
    fn intercept_request(&self, payment_hash: PaymentHash) -> InterceptPaymentRequest {
        InterceptPaymentRequest {
            payment_hash: sha256::Hash::from_byte_array(payment_hash.0),
            // LDK reports the real claimable amount, so the two amounts
            // coincide here.
            amount_msat: self.claimable_amount_msat,
            incoming_amount_msat: self.claimable_amount_msat,
            expiry: self.claim_deadline.unwrap_or_default(),
            short_channel_id: None,
            // LDK claims payments through its own payment store, so it never
            // intercepts forwards for the gateway.
            incoming_chan_id: NO_INCOMING_CIRCUIT.0,
            htlc_id: NO_INCOMING_CIRCUIT.1,
        }
    }
}

/// The payments the node holds that the gateway has not resolved yet.
///
/// LDK emits `PaymentClaimable` when a payment becomes claimable. Once the
/// node has persisted that the event was handled, LDK does not emit it again
/// after a clean restart, but keeps holding the payment until it is claimed,
/// failed, or its claim deadline passes. The gateway must therefore be told
/// about it again after a restart, or a payment it had not resolved yet stays
/// held until LDK fails it back. Each held payment is recorded before its
/// event is marked handled, and after a restart the gateway is told about the
/// recorded payments (see
/// `LdkEventHandler::deliver_held_payments_after_restart`). A record is
/// removed once the gateway has settled or failed back its payment, or once
/// the node can no longer claim it.
///
/// The records live in the node's own SQLite store, under namespaces LDK Node
/// does not use: a write is as durable as the node's own state, and the
/// records stay with the payments they refer to wherever the node's data goes.
///
/// A payment that a gateway without these records acknowledged before it was
/// upgraded has no record, so it is not delivered again after the upgrade:
/// the node keeps holding it until LDK fails it back at its claim deadline.
#[derive(Clone)]
struct HeldPaymentStore {
    store: Arc<dyn KVStoreSync + Send + Sync>,

    /// The highest block height the gateway has seen the node reach; see
    /// [`Self::observe_height`].
    observed_height: Arc<std::sync::Mutex<ObservedHeight>>,

    /// Serializes failing a payment back with recording a payment and with
    /// delivering a payment from its record, so a record is delivered only
    /// while it is current, and a payer's retry recorded once the payment is
    /// failed back is not removed with the payment's record.
    ///
    /// Claiming a payment and removing its record hold it too, so a delivery
    /// from the record either comes before the claim or finds the record
    /// removed.
    ///
    /// It is held only around steps that do not wait for another task:
    /// reading, writing or removing records, sending on room already reserved
    /// on the HTLC stream, and claiming or failing a payment back. So whoever
    /// holds it
    /// never waits for someone else who needs it. In particular, a delivery
    /// waits for room on the stream before it takes the lock, as the gateway
    /// may take an earlier payment off the stream only after it has failed
    /// that payment back.
    delivery_lock: Arc<Mutex<()>>,
}

/// The highest block height the gateway has seen the node reach, and the
/// highest one written to the store.
#[derive(Debug, Default, Clone, Copy)]
struct ObservedHeight {
    highest: u32,
    persisted: u32,
}

/// What became of a payment [`HeldPaymentStore::deliver_if_current`] was
/// asked to deliver.
#[derive(Debug, PartialEq, Eq)]
enum RecordedDelivery {
    Delivered,
    /// The payment was no longer recorded, or the gateway was failing it
    /// back, so it was not delivered.
    NotRecorded,
    /// The node can no longer claim the payment, so it was not delivered.
    NotClaimable,
    /// The HTLC stream is closed, so nothing can be delivered.
    StreamClosed,
}

impl HeldPaymentStore {
    fn new(store: Arc<dyn KVStoreSync + Send + Sync>) -> Self {
        Self {
            store,
            observed_height: Arc::new(std::sync::Mutex::new(ObservedHeight::default())),
            delivery_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Records that the node has reached `height`, and returns the highest
    /// height the gateway has seen it reach, including in earlier runs once
    /// [`Self::load_observed_height`] has read that.
    ///
    /// LDK fails a payment back once its best block reaches the claim
    /// deadline, and does not hold it again if the chain tip later moves back
    /// below the deadline. So a recorded payment is claimable only below the
    /// highest height the node has reached, which is kept in the store so it
    /// holds across restarts. If writing it fails, it is written again at the
    /// next height observed.
    fn observe_height(&self, height: u32) -> u32 {
        let mut observed = self.observed_height.lock().expect("not poisoned");
        observed.highest = observed.highest.max(height);

        if observed.persisted < observed.highest {
            match KVStoreSync::write(
                &*self.store,
                HELD_PAYMENTS_PRIMARY_NAMESPACE,
                OBSERVED_HEIGHT_SECONDARY_NAMESPACE,
                OBSERVED_HEIGHT_KEY,
                observed.highest.consensus_encode_to_vec(),
            ) {
                Ok(()) => observed.persisted = observed.highest,
                Err(err) => {
                    warn!(
                        target: LOG_LIGHTNING,
                        height = observed.highest,
                        err = %err.fmt_compact(),
                        "Could not persist the highest block height the node reached, retrying"
                    );
                }
            }
        }

        observed.highest
    }

    /// Reads the highest block height an earlier run saw the node reach, and
    /// returns the highest one seen so far; see [`Self::observe_height`].
    /// Called before any height is observed, so that height is not written
    /// over the earlier run's. Fails if the store cannot read it, which may
    /// succeed when tried again.
    fn load_observed_height(&self) -> Result<u32, lightning::io::Error> {
        let persisted = match KVStoreSync::read(
            &*self.store,
            HELD_PAYMENTS_PRIMARY_NAMESPACE,
            OBSERVED_HEIGHT_SECONDARY_NAMESPACE,
            OBSERVED_HEIGHT_KEY,
        ) {
            Ok(bytes) => u32::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .inspect_err(|err| {
                    crit!(
                        target: LOG_LIGHTNING,
                        err = %err.fmt_compact(),
                        "Ignoring undecodable highest block height the node reached"
                    );
                })
                .unwrap_or_default(),
            Err(err) if err.kind() == lightning::io::ErrorKind::NotFound => 0,
            Err(err) => return Err(err),
        };

        let mut observed = self.observed_height.lock().expect("not poisoned");
        observed.highest = observed.highest.max(persisted);
        observed.persisted = observed.persisted.max(persisted);

        Ok(observed.highest)
    }

    fn key(payment_hash: PaymentHash) -> String {
        hex::encode(payment_hash.0)
    }

    /// Records `payment` as held for `payment_hash`, replacing any earlier
    /// record of it.
    async fn record(
        &self,
        payment_hash: PaymentHash,
        payment: &HeldPayment,
    ) -> Result<(), lightning::io::Error> {
        let _deliveries = self.delivery_lock.lock().await;

        self.write(payment_hash, payment)
    }

    fn write(
        &self,
        payment_hash: PaymentHash,
        payment: &HeldPayment,
    ) -> Result<(), lightning::io::Error> {
        KVStoreSync::write(
            &*self.store,
            HELD_PAYMENTS_PRIMARY_NAMESPACE,
            HELD_PAYMENTS_SECONDARY_NAMESPACE,
            &Self::key(payment_hash),
            payment.consensus_encode_to_vec(),
        )
    }

    fn remove(&self, payment_hash: PaymentHash) -> Result<(), lightning::io::Error> {
        KVStoreSync::remove(
            &*self.store,
            HELD_PAYMENTS_PRIMARY_NAMESPACE,
            HELD_PAYMENTS_SECONDARY_NAMESPACE,
            &Self::key(payment_hash),
            false,
        )
    }

    /// Reads the record of `payment_hash`, if any. A record that cannot be
    /// decoded is logged and read as none, like in [`Self::list`].
    fn read(&self, payment_hash: PaymentHash) -> Result<Option<HeldPayment>, lightning::io::Error> {
        let key = Self::key(payment_hash);
        let bytes = match KVStoreSync::read(
            &*self.store,
            HELD_PAYMENTS_PRIMARY_NAMESPACE,
            HELD_PAYMENTS_SECONDARY_NAMESPACE,
            &key,
        ) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == lightning::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };

        Ok(Self::decode_logged(&key, &bytes).map(|(_, payment)| payment))
    }

    /// Fails the payment for `payment_hash` back by calling `fail_back`, and
    /// removes its record once that succeeds.
    ///
    /// The record is first marked as failing back. It is then not delivered
    /// again: if the gateway stops before the record is removed, the next
    /// start finishes failing the payment back instead. If marking the record
    /// or `fail_back` fails, the payment stays held and recorded, so the call
    /// can be tried again. All steps hold `delivery_lock`, so a payer's retry,
    /// which LDK reports only once the payment is failed back, is recorded
    /// only after the payment's record is removed.
    ///
    /// LDK persists that it failed the payment back only after `fail_back`
    /// returns. If the gateway stops before that, but after the record was
    /// removed, the node may still hold the payment after a restart, with no
    /// record, until LDK fails it back at its claim deadline. That only delays
    /// failing the payment back.
    async fn fail_back<T, E>(
        &self,
        payment_hash: PaymentHash,
        fail_back: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, lightning::io::Error> {
        let _deliveries = self.delivery_lock.lock().await;

        if let Some(payment) = self.read(payment_hash)?
            && !payment.failing_back
        {
            self.write(
                payment_hash,
                &HeldPayment {
                    failing_back: true,
                    ..payment
                },
            )?;
        }

        let result = fail_back();

        if result.is_ok()
            && let Err(err) = self.remove(payment_hash)
        {
            warn!(
                target: LOG_LIGHTNING,
                payment_hash = %hex::encode(payment_hash.0),
                err = %err.fmt_compact(),
                "Could not remove the record of a payment failed back, removing it on the next start"
            );
        }

        Ok(result)
    }

    /// Delivers the payment recorded for `payment_hash` on the HTLC stream if
    /// it is still recorded, the gateway is not failing it back, and
    /// `may_claim` says the node may still claim it.
    ///
    /// The record is read, and `may_claim` asked, only once there is room on
    /// the stream, right before the payment is sent. Fails if the store cannot
    /// read the record, which may succeed when tried again.
    async fn deliver_if_current(
        &self,
        payment_hash: PaymentHash,
        htlc_stream_sender: &Sender<InterceptPaymentRequest>,
        may_claim: impl FnOnce(&HeldPayment) -> bool,
    ) -> Result<RecordedDelivery, lightning::io::Error> {
        // Room on the stream is reserved before the lock is taken, so the lock
        // is never held while waiting for the gateway; see `delivery_lock`.
        let Ok(permit) = htlc_stream_sender.reserve().await else {
            return Ok(RecordedDelivery::StreamClosed);
        };
        let _deliveries = self.delivery_lock.lock().await;

        let Some(payment) = self
            .read(payment_hash)?
            .filter(|payment| !payment.failing_back)
        else {
            return Ok(RecordedDelivery::NotRecorded);
        };

        if !may_claim(&payment) {
            return Ok(RecordedDelivery::NotClaimable);
        }

        permit.send(payment.intercept_request(payment_hash));

        Ok(RecordedDelivery::Delivered)
    }

    /// Removes the records of the payments `may_claim` says the node can no
    /// longer claim. Fails if the store does, leaving the remaining records to
    /// a later call.
    async fn remove_unclaimable(
        &self,
        may_claim: impl Fn(PaymentHash, &HeldPayment) -> bool,
    ) -> Result<(), lightning::io::Error> {
        let _deliveries = self.delivery_lock.lock().await;

        for (payment_hash, payment) in self.list()? {
            if !may_claim(payment_hash, &payment) {
                debug!(
                    target: LOG_LIGHTNING,
                    payment_hash = %hex::encode(payment_hash.0),
                    claim_deadline = ?payment.claim_deadline,
                    "Removing the record of a held payment the node can no longer claim"
                );
                self.remove(payment_hash)?;
            }
        }

        Ok(())
    }

    /// Lists the recorded payments.
    ///
    /// Fails if the store cannot list or read the records, which may succeed
    /// when tried again. A record that was read but cannot be decoded will not
    /// decode on a later try either, so it is logged and skipped rather than
    /// failing the others, and its payment is not delivered again.
    fn list(&self) -> Result<Vec<(PaymentHash, HeldPayment)>, lightning::io::Error> {
        let keys = KVStoreSync::list(
            &*self.store,
            HELD_PAYMENTS_PRIMARY_NAMESPACE,
            HELD_PAYMENTS_SECONDARY_NAMESPACE,
        )?;
        let mut payments = Vec::with_capacity(keys.len());

        for key in keys {
            let bytes = match KVStoreSync::read(
                &*self.store,
                HELD_PAYMENTS_PRIMARY_NAMESPACE,
                HELD_PAYMENTS_SECONDARY_NAMESPACE,
                &key,
            ) {
                Ok(bytes) => bytes,
                // Removed since it was listed: the gateway resolved it.
                Err(err) if err.kind() == lightning::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            };

            payments.extend(Self::decode_logged(&key, &bytes));
        }

        Ok(payments)
    }

    fn decode_logged(key: &str, bytes: &[u8]) -> Option<(PaymentHash, HeldPayment)> {
        Self::decode(key, bytes)
            .inspect_err(|err| {
                crit!(
                    target: LOG_LIGHTNING,
                    %key,
                    err = err.as_str(),
                    "Skipping undecodable held payment record, its payment is not delivered again"
                );
            })
            .ok()
    }

    fn decode(key: &str, bytes: &[u8]) -> Result<(PaymentHash, HeldPayment), String> {
        let payment_hash = <[u8; 32]>::try_from(hex::decode(key).map_err(|err| err.to_string())?)
            .map_err(|_| "key is not a payment hash".to_string())?;
        let payment = HeldPayment::consensus_decode_whole(bytes, &ModuleDecoderRegistry::default())
            .map_err(|err| err.to_string())?;

        Ok((PaymentHash(payment_hash), payment))
    }

    /// Lists the recorded payments like [`Self::list`], retrying after each
    /// delay of `backoff` while the store fails. Returns `None` if the task
    /// shuts down or `backoff` gives up first.
    async fn list_retrying(
        &self,
        backoff: FibonacciBackoff,
        handle: &TaskHandle,
    ) -> Option<Vec<(PaymentHash, HeldPayment)>> {
        retry_store(backoff, handle, || async { self.list() }).await
    }
}

/// Runs `op` until the store it uses does not fail, retrying after each delay
/// of `backoff`. Returns `None` if the task shuts down or `backoff` gives up
/// first.
async fn retry_store<T, F>(
    mut backoff: FibonacciBackoff,
    handle: &TaskHandle,
    op: impl Fn() -> F,
) -> Option<T>
where
    F: Future<Output = Result<T, lightning::io::Error>>,
{
    loop {
        let err = match op().await {
            Ok(value) => return Some(value),
            Err(err) => err,
        };
        let delay = backoff.next()?;

        warn!(
            target: LOG_LIGHTNING,
            err = %err.fmt_compact(),
            ?delay,
            "Could not access held payment records, retrying"
        );
        tokio::select! {
            () = sleep(delay) => {}
            () = handle.make_shutdown_rx() => return None,
        }
    }
}

/// Decides whether a recorded held payment may still be resolved by the
/// gateway, and so must be delivered to it again.
///
/// `inbound_status` is the status of the node's inbound record for the
/// payment hash, if any, and `best_block_height` the highest height the
/// gateway has seen the node reach; see [`HeldPaymentStore::observe_height`].
/// A payment the node has settled (the gateway stopped after settling it but
/// before removing its record), one the node has no inbound record of, and
/// one whose claim deadline the node has reached are no longer claimable: LDK
/// fails a claimable payment back once its best block reaches the claim
/// deadline.
///
/// A `Failed` payment may be claimable. LDK Node marks a payment `Failed` when
/// the gateway fails it back and keeps that status when the payer retries the
/// invoice, which it accepts unless the payment succeeded, so the status does
/// not tell whether the node holds a retry. The gateway removes a payment's
/// record once it has failed the payment back, and the retry's own
/// `PaymentClaimable` records the payment again.
fn held_payment_is_claimable(
    inbound_status: Option<PaymentStatus>,
    claim_deadline: Option<u32>,
    best_block_height: u32,
) -> bool {
    match inbound_status {
        Some(PaymentStatus::Pending | PaymentStatus::Failed) => {
            claim_deadline.is_none_or(|claim_deadline| best_block_height < claim_deadline)
        }
        Some(PaymentStatus::Succeeded) | None => false,
    }
}

/// Whether the node has finished a Lightning chain sync since the client
/// started it, given the time of its latest sync, and that of its latest sync
/// when the client started it.
///
/// LDK Node loads the time of its latest sync from its store, so a node that
/// was just started reports a sync from before the restart while it still
/// catches up with the blocks mined since. Sync times are in whole seconds,
/// so a first sync that ends in the same second as the last one before the
/// restart is only seen at the next sync.
fn lightning_synced_since_start(latest_sync: Option<u64>, sync_before_start: Option<u64>) -> bool {
    latest_sync.is_some() && latest_sync != sync_before_start
}

pub struct GatewayLdkClient {
    /// The underlying lightning node.
    node: Arc<ldk_node::Node>,

    /// The payments the node holds that the gateway has not resolved yet.
    held_payments: HeldPaymentStore,

    /// The time of the node's latest Lightning chain sync when the client
    /// started it; see [`lightning_synced_since_start`].
    lightning_sync_before_start: Option<u64>,

    task_group: TaskGroup,

    /// The HTLC stream, until it is taken by calling
    /// `ILnRpcClient::route_htlcs`.
    htlc_stream_receiver_or: Option<tokio::sync::mpsc::Receiver<InterceptPaymentRequest>>,

    /// Lock pool used to ensure that our implementation of `ILnRpcClient::pay`
    /// doesn't allow for multiple simultaneous calls with the same invoice to
    /// execute in parallel. This helps ensure that the function is idempotent.
    outbound_lightning_payment_lock_pool: lockable::LockPool<PaymentId>,

    /// Lock pool used to ensure that our implementation of
    /// `ILnRpcClient::pay_offer` doesn't allow for multiple simultaneous
    /// calls with the same offer to execute in parallel. This helps ensure
    /// that the function is idempotent.
    outbound_offer_lock_pool: lockable::LockPool<LdkOfferId>,

    /// A map keyed by the `UserChannelId` of a channel that is currently
    /// opening. The `Sender` is used to communicate the `OutPoint` back to
    /// the API handler from the event handler when the channel has been
    /// opened and is now pending, or the reason it closed before that.
    pending_channels: Arc<RwLock<BTreeMap<UserChannelId, PendingChannelSender>>>,

    /// Waiters for outgoing LDK payments that are woken by terminal payment
    /// events (`PaymentSuccessful` / `PaymentFailed`). This lets `pay()` block
    /// until the payment resolves instead of polling `node.payment()`. The
    /// actual result is still read from `node.payment()` after the wakeup; this
    /// map only signals that a terminal event has arrived.
    pending_payments: Arc<RwLock<HashMap<PaymentId, oneshot::Sender<()>>>>,
    /// Resolves once the client has delivered the payments held from an
    /// earlier run, and starts waiting for the node's events. Tests take it.
    #[cfg(test)]
    #[allow(dead_code)]
    startup_finished: Option<oneshot::Receiver<()>>,
}

/// Sends a channel's funding outpoint once the channel is pending, or the
/// reason the channel closed before that.
type PendingChannelSender = oneshot::Sender<Result<OutPoint, String>>;

impl std::fmt::Debug for GatewayLdkClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayLdkClient").finish_non_exhaustive()
    }
}

/// How the gateway obtained the mnemonic the LDK node derives its keys from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicSource {
    /// Freshly generated by this process, so it controls no historical onchain
    /// funds and the node can start its onchain wallet at the current tip.
    Generated,
    /// Imported or loaded from a previous run, so it may control onchain funds
    /// the node has no record of, e.g. after its data directory was lost. The
    /// node then scans the chain from genesis when it first creates its
    /// onchain wallet, since starting at the tip would leave those funds
    /// undiscovered. This has no effect once the wallet exists.
    Existing,
}

impl GatewayLdkClient {
    /// Creates a new `GatewayLdkClient` instance and starts the underlying
    /// lightning node. All resources, including the lightning node, will be
    /// cleaned up when the returned `GatewayLdkClient` instance is dropped.
    /// There's no need to manually stop the node.
    ///
    /// # Errors
    ///
    /// Fails with [`LdkClientInitError::MissingEsploraHost`] or
    /// [`LdkClientInitError::InvalidDataDir`] if the configuration cannot be
    /// used, with [`LdkClientInitError::Build`] if LDK cannot build the node,
    /// and with [`LdkClientInitError::Start`] if it cannot start it.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        data_dir: &Path,
        chain_source: ChainSource,
        network: Network,
        lightning_port: u16,
        alias: String,
        mnemonic: Mnemonic,
        mnemonic_source: MnemonicSource,
        runtime: Arc<tokio::runtime::Runtime>,
    ) -> Result<Self, LdkClientInitError> {
        let mut bytes = [0u8; 32];
        let alias = if alias.is_empty() {
            "LDK Gateway".to_string()
        } else {
            alias
        };
        let alias_bytes = alias.as_bytes();
        let truncated = &alias_bytes[..alias_bytes.len().min(32)];
        bytes[..truncated.len()].copy_from_slice(truncated);
        let node_alias = Some(NodeAlias(bytes));

        let mut node_builder = ldk_node::Builder::from_config(ldk_node::config::Config {
            network,
            listening_addresses: Some(vec![SocketAddress::TcpIpV4 {
                addr: [0, 0, 0, 0],
                port: lightning_port,
            }]),
            node_alias,
            ..Default::default()
        });

        // Route LDK's logs into the gateway's `tracing` subscriber so they land in
        // the same place (stderr / log file) and honor `RUST_LOG`, instead of LDK's
        // default append-only `ldk_node/ldk_node.log` file.
        node_builder.set_custom_logger(Arc::new(LdkTracingLogger {
            in_test_env: is_running_in_test_env(),
        }));

        node_builder.set_entropy_bip39_mnemonic(mnemonic, None);

        match chain_source.clone() {
            ChainSource::Bitcoind {
                username,
                password,
                server_url,
            } => {
                node_builder.set_chain_source_bitcoind_rpc(
                    server_url
                        .host_str()
                        .expect("Could not retrieve host from bitcoind RPC url")
                        .to_string(),
                    server_url
                        .port()
                        .expect("Could not retrieve port from bitcoind RPC url"),
                    username,
                    password,
                );
            }
            ChainSource::Esplora { server_url } => {
                node_builder.set_chain_source_esplora(get_esplora_url(server_url)?, None);
            }
        };
        let Some(data_dir_str) = data_dir.to_str() else {
            return Err(LdkClientInitError::InvalidDataDir);
        };
        node_builder.set_storage_dir_path(data_dir_str.to_string());
        node_builder.set_runtime(runtime.handle().clone());
        if mnemonic_source == MnemonicSource::Existing {
            info!(
                target: LOG_LIGHTNING,
                "Mnemonic was not generated by this process, recovering onchain wallet from genesis if it does not exist yet"
            );
            node_builder.set_wallet_recovery_mode();
        }

        info!(chain_source = %chain_source, data_dir = %data_dir_str, alias = %alias, "Starting LDK Node...");
        // The same store `NodeBuilder::build` creates, built here so the
        // gateway can keep its held-payment records next to the node's state.
        std::fs::create_dir_all(data_dir).map_err(|_| {
            LdkClientInitError::Build(ldk_node::BuildError::StoragePathAccessFailed)
        })?;
        let store = Arc::new(
            SqliteStore::new(
                data_dir.to_path_buf(),
                Some(SQLITE_DB_FILE_NAME.to_string()),
                Some(KV_TABLE_NAME.to_string()),
            )
            .map_err(|_| LdkClientInitError::Build(ldk_node::BuildError::KVStoreSetupFailed))?,
        );
        let held_payments = HeldPaymentStore::new(store.clone());
        let node = Arc::new(
            node_builder
                .build_with_store(store)
                .map_err(LdkClientInitError::Build)?,
        );
        let lightning_sync_before_start = node.status().latest_lightning_wallet_sync_timestamp;
        node.start().map_err(|err| {
            crit!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Failed to start LDK Node");
            LdkClientInitError::Start(err)
        })?;

        let (htlc_stream_sender, htlc_stream_receiver) = tokio::sync::mpsc::channel(1024);
        let task_group = TaskGroup::new();

        let pending_channels = Arc::new(RwLock::new(BTreeMap::new()));
        let pending_payments = Arc::new(RwLock::new(HashMap::new()));
        let event_handler = LdkEventHandler {
            node: node.clone(),
            htlc_stream_sender,
            pending_channels: pending_channels.clone(),
            pending_payments: pending_payments.clone(),
            held_payments: held_payments.clone(),
            lightning_sync_before_start,
        };
        #[cfg(test)]
        let (startup_finished_sender, startup_finished) = oneshot::channel();
        task_group.spawn("ldk lightning node event handler", |handle| async move {
            // Before handling new events, so the gateway learns of every
            // payment still held from an earlier run first.
            if !event_handler
                .deliver_held_payments_after_restart(&handle)
                .await
            {
                return;
            }
            #[cfg(test)]
            let _ = startup_finished_sender.send(());

            event_handler.handle_events(&handle).await;
        });

        info!("Successfully started LDK Gateway");
        Ok(GatewayLdkClient {
            node,
            held_payments,
            lightning_sync_before_start,
            task_group,
            htlc_stream_receiver_or: Some(htlc_stream_receiver),
            outbound_lightning_payment_lock_pool: lockable::LockPool::new(),
            outbound_offer_lock_pool: lockable::LockPool::new(),
            pending_channels,
            pending_payments,
            #[cfg(test)]
            startup_finished: Some(startup_finished),
        })
    }

    /// Wakes the `pay()` waiter (if any) for `payment_id` once a terminal
    /// payment event has been observed. The actual payment result is read from
    /// `node.payment()` by the woken waiter.
    async fn wake_pending_payment(
        pending_payments: &RwLock<HashMap<PaymentId, oneshot::Sender<()>>>,
        payment_id: PaymentId,
    ) -> PendingPaymentWakeup {
        let Some(sender) = pending_payments.write().await.remove(&payment_id) else {
            return PendingPaymentWakeup::NoWaiter;
        };

        if sender.send(()).is_ok() {
            PendingPaymentWakeup::Woken
        } else {
            PendingPaymentWakeup::ReceiverDropped
        }
    }

    /// Returns the node's payment record for `payment_id`, but only when it is
    /// one of our own outbound attempts.
    ///
    /// LDK keys BOLT11 payments by `PaymentId(payment_hash)` in both
    /// directions, so a registered invoice or a claimed inbound payment for the
    /// same hash shares a slot with our outbound send. Without this direction
    /// check such an inbound record could be mistaken for the result of our
    /// `pay()`: reported as a spurious success (a preimage we never sent for),
    /// a spurious failure, or -- while still pending -- block `pay()` forever.
    fn outbound_payment(&self, payment_id: PaymentId) -> Option<PaymentDetails> {
        self.node
            .payment(&payment_id)
            .filter(|details| details.direction == PaymentDirection::Outbound)
    }

    /// Reads the result of an outgoing payment from `node.payment()`.
    ///
    /// Returns `None` while the payment is still pending (or not yet known to
    /// the node), and `Some` once it has reached a terminal status.
    fn ldk_payment_result(
        &self,
        payment_id: PaymentId,
    ) -> Option<Result<PayInvoiceResponse, LightningRpcError>> {
        let payment_details = self.outbound_payment(payment_id)?;
        match payment_details.status {
            PaymentStatus::Pending => None,
            PaymentStatus::Succeeded => {
                if let PaymentKind::Bolt11 {
                    preimage: Some(preimage),
                    ..
                } = payment_details.kind
                {
                    Some(Ok(PayInvoiceResponse {
                        preimage: Preimage(preimage.0),
                    }))
                } else {
                    Some(Err(LightningRpcError::FailedPayment {
                        failure_reason: "LDK payment succeeded without preimage".to_string(),
                    }))
                }
            }
            PaymentStatus::Failed => Some(Err(LightningRpcError::FailedPayment {
                failure_reason: "LDK payment failed".to_string(),
            })),
        }
    }
}

/// Whether [`LdkEventHandler::handle_event`] delivers a held payment it
/// records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeldPaymentDelivery {
    Deliver,
    /// Only record it: it is delivered from its record.
    FromRecord,
}

/// Handles the node's events for the client, and tells the gateway about the
/// payments the node holds for it.
struct LdkEventHandler {
    node: Arc<ldk_node::Node>,
    htlc_stream_sender: Sender<InterceptPaymentRequest>,
    pending_channels: Arc<RwLock<BTreeMap<UserChannelId, PendingChannelSender>>>,
    pending_payments: Arc<RwLock<HashMap<PaymentId, oneshot::Sender<()>>>>,
    held_payments: HeldPaymentStore,
    /// See [`GatewayLdkClient::lightning_sync_before_start`].
    lightning_sync_before_start: Option<u64>,
}

impl LdkEventHandler {
    /// Delivers the payments the node holds for the gateway again after a
    /// restart. Returns `false` if the task shuts down first.
    ///
    /// It first waits until the node has synced to the chain since it
    /// started, so a payment is delivered only if the node can still claim it
    /// at the chain's current height rather than at the height it had
    /// processed before the restart.
    ///
    /// A queued `PaymentClaimable` event and a record can describe the same
    /// held payment: the gateway may have stopped after recording the payment
    /// but before the node persisted that its event was handled, and LDK Node
    /// loads its queue when the node is built. So the events the node has
    /// queued are handled first, as any event is, except that their held
    /// payments are only recorded. After a restart the records alone decide
    /// what is delivered, so each recorded payment the node may still claim is
    /// delivered once, and a fail-back the gateway had started is finished.
    ///
    /// Delivery after a restart is at least once: LDK may report a payment it
    /// still holds again after a restart on its own, apart from LDK Node's
    /// queue, so the gateway must tolerate being told again about a payment
    /// the node still holds. Recording the queued payments first only keeps
    /// the common case from delivering a payment twice.
    async fn deliver_held_payments_after_restart(&self, handle: &TaskHandle) -> bool {
        if !self.wait_for_chain_sync(handle).await {
            return false;
        }

        // A payment whose claim deadline the node reached before the restart
        // stays expired even if the chain tip has moved back since.
        if retry_store(backoff_util::background_backoff(), handle, || async {
            self.held_payments.load_observed_height()
        })
        .await
        .is_none()
        {
            return false;
        }

        let mut left_to_next_start = HashSet::new();

        while let Some(event) = self.node.next_event() {
            if handle.is_shutting_down() {
                return false;
            }

            if let Some(payment_hash) = self
                .handle_event(event, HeldPaymentDelivery::FromRecord, handle)
                .await
            {
                left_to_next_start.insert(payment_hash);
            }
        }

        self.redeliver_held_payments(handle, &left_to_next_start)
            .await
    }

    /// Waits until the node has finished a Lightning chain sync since the
    /// client started it. Returns `false` if the task shuts down first.
    async fn wait_for_chain_sync(&self, handle: &TaskHandle) -> bool {
        loop {
            let latest_sync = self.node.status().latest_lightning_wallet_sync_timestamp;

            if lightning_synced_since_start(latest_sync, self.lightning_sync_before_start) {
                return true;
            }

            tokio::select! {
                () = sleep(CHAIN_SYNC_POLL_INTERVAL) => {}
                () = handle.make_shutdown_rx() => return false,
            }
        }
    }

    /// Whether the node may still claim a payment held for `payment_hash`
    /// with `claim_deadline`; see [`held_payment_is_claimable`].
    fn may_claim(&self, payment_hash: PaymentHash, claim_deadline: Option<u32>) -> bool {
        let inbound_status = self
            .node
            .payment(&PaymentId(payment_hash.0))
            .filter(|details| details.direction == PaymentDirection::Inbound)
            .map(|details| details.status);
        let best_block_height = self
            .held_payments
            .observe_height(self.node.status().current_best_block.height);

        held_payment_is_claimable(inbound_status, claim_deadline, best_block_height)
    }

    /// Delivers every recorded held payment the node may still claim on the
    /// HTLC stream, except those in `left_to_next_start`, and finishes failing
    /// back the payments the gateway had started to fail back. Returns `false`
    /// if the task shuts down first.
    ///
    /// The gateway may already have relayed a payment delivered here. Relaying
    /// it again does not fund its incoming contract twice, and starts the
    /// completion that settles it if an earlier relay did not. Each payment
    /// is delivered only while its record is current; see
    /// [`HeldPaymentStore::deliver_if_current`].
    ///
    /// A store that fails to read the records is retried until it succeeds or
    /// the task shuts down. The records of payments the node can no longer
    /// claim are left to [`Self::remove_unclaimable_held_payments`].
    async fn redeliver_held_payments(
        &self,
        handle: &TaskHandle,
        left_to_next_start: &HashSet<PaymentHash>,
    ) -> bool {
        let Some(payments) = self
            .held_payments
            .list_retrying(backoff_util::background_backoff(), handle)
            .await
        else {
            return false;
        };

        for (payment_hash, payment) in payments {
            if left_to_next_start.contains(&payment_hash) {
                continue;
            }

            if payment.failing_back {
                self.finish_failing_back(payment_hash).await;
                continue;
            }

            // Waiting for room on the stream stops when the task shuts down.
            let delivery = tokio::select! {
                delivery = retry_store(backoff_util::background_backoff(), handle, || {
                    self.held_payments.deliver_if_current(
                        payment_hash,
                        &self.htlc_stream_sender,
                        |payment| self.may_claim(payment_hash, payment.claim_deadline),
                    )
                }) => delivery,
                () = handle.make_shutdown_rx() => None,
            };
            let Some(delivery) = delivery else {
                return false;
            };

            match delivery {
                RecordedDelivery::Delivered => {
                    info!(
                        target: LOG_LIGHTNING,
                        payment_hash = %hex::encode(payment_hash.0),
                        "Delivered a payment the node still holds"
                    );
                }
                RecordedDelivery::NotRecorded | RecordedDelivery::NotClaimable => {
                    debug!(
                        target: LOG_LIGHTNING,
                        payment_hash = %hex::encode(payment_hash.0),
                        ?delivery,
                        "Not delivering a recorded payment"
                    );
                }
                RecordedDelivery::StreamClosed => {
                    warn!(
                        target: LOG_LIGHTNING,
                        "HTLC stream closed, not delivering the remaining held payments"
                    );
                    break;
                }
            }
        }

        true
    }

    /// Fails back a payment the gateway had started to fail back before it
    /// stopped, and removes its record; see [`HeldPaymentStore::fail_back`].
    ///
    /// If this fails, the payment stays held, and is not delivered, until the
    /// next start or until LDK fails it back at its claim deadline. That only
    /// delays failing the payment back.
    async fn finish_failing_back(&self, payment_hash: PaymentHash) {
        let result = self
            .held_payments
            .fail_back(payment_hash, || {
                self.node.bolt11_payment().fail_for_hash(payment_hash)
            })
            .await;

        match result {
            Ok(Ok(())) => {
                info!(
                    target: LOG_LIGHTNING,
                    payment_hash = %hex::encode(payment_hash.0),
                    "Failed back a held payment the gateway had started to fail back"
                );
            }
            Ok(Err(err)) => {
                warn!(
                    target: LOG_LIGHTNING,
                    payment_hash = %hex::encode(payment_hash.0),
                    err = %err.fmt_compact(),
                    "Could not fail back a held payment, retrying on the next start"
                );
            }
            Err(err) => {
                warn!(
                    target: LOG_LIGHTNING,
                    payment_hash = %hex::encode(payment_hash.0),
                    err = %err.fmt_compact(),
                    "Could not read held payment record, failing it back on the next start"
                );
            }
        }
    }

    /// Handles the node's events until the task shuts down. Each time the node
    /// has processed a new block, it also removes the records of the held
    /// payments the node can no longer claim.
    async fn handle_events(&self, handle: &TaskHandle) {
        let mut cleanup = tokio::time::interval(HELD_PAYMENT_CLEANUP_INTERVAL);
        let mut cleaned_at_height = None;

        loop {
            // An event that arrives is handled to the end even if the task
            // shuts down meanwhile, except for waiting for room on the HTLC
            // stream.
            tokio::select! {
                event = self.node.next_event_async() => {
                    self.handle_event(event, HeldPaymentDelivery::Deliver, handle).await;
                }
                _ = cleanup.tick() => {
                    cleaned_at_height = self
                        .remove_unclaimable_held_payments(cleaned_at_height)
                        .await;
                }
                () = handle.make_shutdown_rx() => return,
            }
        }
    }

    /// Removes the records of the held payments the node can no longer claim,
    /// unless the node has processed no block since `cleaned_at_height`.
    /// Returns the height of the latest cleanup that succeeded, so one that
    /// failed is retried.
    async fn remove_unclaimable_held_payments(
        &self,
        cleaned_at_height: Option<u32>,
    ) -> Option<u32> {
        let height = self.node.status().current_best_block.height;

        self.held_payments.observe_height(height);

        if cleaned_at_height == Some(height) {
            return cleaned_at_height;
        }

        match self
            .held_payments
            .remove_unclaimable(|payment_hash, payment| {
                self.may_claim(payment_hash, payment.claim_deadline)
            })
            .await
        {
            Ok(()) => Some(height),
            Err(err) => {
                warn!(
                    target: LOG_LIGHTNING,
                    err = %err.fmt_compact(),
                    "Could not remove the records of held payments the node can no longer claim, retrying"
                );
                cleaned_at_height
            }
        }
    }

    /// Handles `event`, the node's next event, and marks it handled.
    ///
    /// A held payment that cannot be recorded leaves the event unhandled, to
    /// be handled again. Returns the payment hash of a held payment that was
    /// recorded but whose event could not be marked handled.
    async fn handle_event(
        &self,
        event: ldk_node::Event,
        delivery: HeldPaymentDelivery,
        handle: &TaskHandle,
    ) -> Option<PaymentHash> {
        match event {
            ldk_node::Event::PaymentClaimable {
                payment_id: _,
                payment_hash,
                claimable_amount_msat,
                claim_deadline,
                custom_records: _,
            } => {
                let payment = HeldPayment {
                    claimable_amount_msat,
                    claim_deadline,
                    failing_back: false,
                };

                return self
                    .handle_payment_claimable(payment_hash, payment, delivery, handle)
                    .await;
            }
            ldk_node::Event::PaymentReceived { payment_hash, .. } => {
                // Also removed once `claim_for_hash` returned, unless that
                // failed.
                if let Err(err) = self.held_payments.remove(payment_hash) {
                    warn!(
                        target: LOG_LIGHTNING,
                        payment_hash = %hex::encode(payment_hash.0),
                        err = %err.fmt_compact(),
                        "Could not remove the record of a received payment"
                    );
                }
            }
            ldk_node::Event::ChannelPending {
                channel_id,
                user_channel_id,
                former_temporary_channel_id: _,
                counterparty_node_id: _,
                funding_txo,
            } => {
                info!(target: LOG_LIGHTNING, %channel_id, "LDK Channel is pending");
                let mut channels = self.pending_channels.write().await;
                if let Some(sender) = channels.remove(&UserChannelId(user_channel_id)) {
                    let _ = sender.send(Ok(funding_txo));
                } else {
                    debug!(
                        ?user_channel_id,
                        "No channel pending channel open for user channel id"
                    );
                }
            }
            ldk_node::Event::ChannelClosed {
                channel_id,
                user_channel_id,
                counterparty_node_id: _,
                reason,
            } => {
                info!(target: LOG_LIGHTNING, %channel_id, "LDK Channel is closed");
                let mut channels = self.pending_channels.write().await;
                if let Some(sender) = channels.remove(&UserChannelId(user_channel_id)) {
                    let reason = if let Some(reason) = reason {
                        reason.to_string()
                    } else {
                        "Channel has been closed".to_string()
                    };
                    let _ = sender.send(Err(reason));
                } else {
                    debug!(
                        ?user_channel_id,
                        "No channel pending channel open for user channel id"
                    );
                }
            }
            ldk_node::Event::PaymentSuccessful {
                payment_id: Some(payment_id),
                ..
            }
            | ldk_node::Event::PaymentFailed {
                payment_id: Some(payment_id),
                ..
            } => {
                GatewayLdkClient::wake_pending_payment(&self.pending_payments, payment_id).await;
            }
            _ => {}
        }

        // `PaymentClaimable`, `PaymentReceived`, `ChannelPending` /
        // `ChannelClosed`, and terminal outgoing payment events
        // (`PaymentSuccessful` / `PaymentFailed`) are the only event types
        // that we are interested in. We can safely ignore all other events.
        self.mark_event_handled();

        None
    }

    /// Records the held `payment` its `PaymentClaimable` event reports, marks
    /// the event handled, and then delivers the payment if `delivery` says
    /// so; see [`Self::handle_event`].
    async fn handle_payment_claimable(
        &self,
        payment_hash: PaymentHash,
        payment: HeldPayment,
        delivery: HeldPaymentDelivery,
        handle: &TaskHandle,
    ) -> Option<PaymentHash> {
        // An event queued before a restart may report a payment that the node
        // has since been paid, or whose claim deadline it has since reached.
        if !self.may_claim(payment_hash, payment.claim_deadline) {
            debug!(
                target: LOG_LIGHTNING,
                payment_hash = %hex::encode(payment_hash.0),
                claim_deadline = ?payment.claim_deadline,
                "Not recording a held payment the node can no longer claim"
            );
            self.mark_event_handled();
            return None;
        }

        // Recorded before the event is marked handled; see
        // `HeldPaymentStore`. If the record cannot be written the event stays
        // unhandled and is handled again.
        if let Err(err) = self.held_payments.record(payment_hash, &payment).await {
            warn!(
                target: LOG_LIGHTNING,
                payment_hash = %hex::encode(payment_hash.0),
                err = %err.fmt_compact(),
                "Could not record held payment, retrying"
            );
            sleep(HELD_PAYMENT_RECORD_RETRY).await;
            return None;
        }

        // Marked handled before the payment is delivered, so that after a
        // restart the payment is delivered from its record alone. If the
        // node cannot persist that the event was handled, it may report the
        // payment again after a restart, so the payment is delivered only
        // then, from its record. Until then, or until LDK fails it back at its
        // claim deadline, it stays held, which only delays resolving it.
        if !self.mark_event_handled() {
            return Some(payment_hash);
        }

        if delivery == HeldPaymentDelivery::Deliver {
            // A payment not delivered before the task shuts down is
            // delivered from its record on the next start.
            tokio::select! {
                sent = self.htlc_stream_sender.send(payment.intercept_request(payment_hash)) => {
                    if let Err(err) = sent {
                        warn!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Failed send InterceptHtlcRequest to stream");
                    }
                }
                () = handle.make_shutdown_rx() => {}
            }
        }

        None
    }

    /// Marks the node's current event handled. Returns whether the node
    /// persisted that.
    fn mark_event_handled(&self) -> bool {
        if let Err(err) = self.node.event_handled() {
            warn!(err = %err.fmt_compact(), "LDK could not mark event handled");
            return false;
        }

        true
    }
}

/// A failure to create the LDK Lightning node behind a [`GatewayLdkClient`].
///
/// Creating the client configures an LDK node from the gateway's settings,
/// builds it on top of the data directory and starts it.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LdkClientInitError {
    /// The Esplora chain source's URL names no host to connect to.
    #[error("Missing esplora host")]
    MissingEsploraHost,

    /// The data directory's path is not valid UTF-8, which LDK needs for its
    /// storage path.
    #[error("Invalid data dir path")]
    InvalidDataDir,

    /// LDK could not build the node, for example because its storage could
    /// not be read or was created for another network.
    #[error("The LDK node could not be built")]
    Build(#[source] ldk_node::BuildError),

    /// LDK built the node but could not start it.
    #[error("The LDK node could not be started")]
    Start(#[source] ldk_node::NodeError),
}

/// Why an invoice must not be registered for a payment hash on the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundRegistrationRefusal {
    /// `pay()` holds the per-hash lock, so an outbound payment for the hash
    /// is being dispatched or awaited right now.
    OutboundInFlight,
    /// The node holds an outbound record for the hash, pending or terminal.
    OutboundRecorded,
    /// The node already holds an inbound record for the hash; overwriting it
    /// would allow a colliding BOLT11/BOLT12 registration to hijack an existing
    /// invoice.
    InboundRecorded,
}

impl std::fmt::Display for InboundRegistrationRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OutboundInFlight => {
                write!(f, "an outbound payment for this hash is in flight")
            }
            Self::OutboundRecorded => {
                write!(f, "the node holds an outbound payment for this hash")
            }
            Self::InboundRecorded => {
                write!(f, "the node already holds an inbound payment for this hash")
            }
        }
    }
}

/// Decides whether an invoice may be registered for a payment hash the node
/// may already know as an outbound or inbound payment.
///
/// `ldk-node` keys payments by `PaymentId(payment_hash)` across both
/// directions and across BOLT11/BOLT12, and registering an invoice overwrites
/// whatever record shares the key. Refusing any existing record prevents
/// erasing an outbound payment result or letting a colliding BOLT11/BOLT12
/// registration overwrite an active inbound invoice.
fn check_inbound_registration(
    outbound_lock_acquired: bool,
    existing_direction: Option<PaymentDirection>,
) -> Result<(), InboundRegistrationRefusal> {
    if !outbound_lock_acquired {
        return Err(InboundRegistrationRefusal::OutboundInFlight);
    }

    match existing_direction {
        Some(PaymentDirection::Outbound) => Err(InboundRegistrationRefusal::OutboundRecorded),
        Some(PaymentDirection::Inbound) => Err(InboundRegistrationRefusal::InboundRecorded),
        None => Ok(()),
    }
}

/// Classifies an `ldk-node` claim or fail error for the gateway's completion
/// retry loop.
///
/// `claim_for_hash` and `fail_for_hash` fail deterministically for an unknown
/// payment hash, a preimage that does not hash to it, or an amount below the
/// registered one. Retrying cannot change any of those, so they are reported
/// as [`LightningRpcError::HtlcCompletionRejected`] and the completion state
/// machine records the outcome instead of retrying forever. Everything else,
/// today only a failed store write, is treated as transient: the incoming
/// contract is already funded by the time this runs, so an error this list
/// does not know must keep retrying rather than be recorded as final.
fn htlc_completion_error(err: &ldk_node::NodeError, payment_hash: &str) -> LightningRpcError {
    match err {
        ldk_node::NodeError::InvalidPaymentHash
        | ldk_node::NodeError::InvalidPaymentPreimage
        | ldk_node::NodeError::InvalidAmount => LightningRpcError::HtlcCompletionRejected {
            failure_reason: format!(
                "LDK rejected completion of payment with hash {payment_hash}: {err}"
            ),
        },
        _ => LightningRpcError::FailedToCompleteHtlc {
            failure_reason: format!(
                "Failed to complete LDK payment with hash {payment_hash}: {err}"
            ),
        },
    }
}

impl Drop for GatewayLdkClient {
    fn drop(&mut self) {
        self.task_group.shutdown();

        info!(target: LOG_LIGHTNING, "Stopping LDK Node...");
        match self.node.stop() {
            Err(err) => {
                warn!(target: LOG_LIGHTNING, err = %err.fmt_compact(), "Failed to stop LDK Node");
            }
            _ => {
                info!(target: LOG_LIGHTNING, "LDK Node stopped.");
            }
        }
    }
}

#[async_trait]
impl ILnRpcClient for GatewayLdkClient {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        let node_status = self.node.status();
        let ldk_block_height = node_status.current_best_block.height;
        let onchain_sync = node_status.latest_onchain_wallet_sync_timestamp;
        let lightning_sync = node_status.latest_lightning_wallet_sync_timestamp;
        let is_running = node_status.is_running;
        debug!(target: LOG_LIGHTNING, ?onchain_sync, ?lightning_sync, ?is_running, "LDK Sync Status");

        Ok(GetNodeInfoResponse {
            pub_key: self.node.node_id(),
            alias: match self.node.node_alias() {
                Some(alias) => alias.to_string(),
                None => format!("LDK Fedimint Gateway Node {}", self.node.node_id()),
            },
            network: self.node.config().network.to_string(),
            block_height: ldk_block_height,
            // `synced_to_chain` is used for determining if the Lightning node is ready, so we care
            // about the `lightning_sync` status. A sync from before the node was
            // started does not count: the node may still be catching up with
            // the blocks mined since.
            synced_to_chain: lightning_synced_since_start(
                lightning_sync,
                self.lightning_sync_before_start,
            ),
        })
    }

    async fn routehints(
        &self,
        _num_route_hints: usize,
    ) -> Result<GetRouteHintsResponse, LightningRpcError> {
        // `ILnRpcClient::routehints()` is currently only ever used for LNv1 payment
        // receives and will be removed when we switch to LNv2. The LDK gateway will
        // never support LNv1 payment receives, only LNv2 payment receives, which
        // require that the gateway's lightning node generates invoices rather than the
        // fedimint client, so it is able to insert the proper route hints on its own.
        Ok(GetRouteHintsResponse {
            route_hints: vec![],
        })
    }

    async fn pay(
        &self,
        invoice: Bolt11Invoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        let payment_id = PaymentId(*invoice.payment_hash().as_byte_array());

        // Lock by the payment hash to prevent multiple simultaneous calls with the same
        // invoice from executing. This prevents `ldk-node::Bolt11Payment::send()` from
        // being called multiple times with the same invoice. This is important because
        // `ldk-node::Bolt11Payment::send()` is not idempotent, but this function must
        // be idempotent.
        let _payment_lock_guard = self
            .outbound_lightning_payment_lock_pool
            .async_lock(payment_id)
            .await;

        // Register a waiter before initiating the payment so that a terminal
        // payment event firing immediately after `send()` returns still wakes
        // us, rather than racing ahead of the registration.
        let (payment_sender, payment_receiver) = oneshot::channel();
        self.pending_payments
            .write()
            .await
            .insert(payment_id, payment_sender);

        // If no outbound attempt of ours is known to the node we can initiate
        // it, and if one is known we can skip calling
        // `ldk-node::Bolt11Payment::send()` and wait for the payment to
        // complete. Checking specifically for an outbound record matters because
        // an inbound payment shares `PaymentId(payment_hash)` with our send: a
        // registered invoice for the same hash must not make us skip `send()`.
        // The lock guard above guarantees that this block is only executed once
        // at a time for a given payment hash, ensuring that there is no race
        // condition between checking if a payment is known and initiating a new
        // payment if it isn't.
        if self.outbound_payment(payment_id).is_none() {
            let sent_payment_id = match self.node.bolt11_payment().send(
                &invoice,
                Some(
                    RouteParametersConfig::default()
                        .with_max_total_routing_fee_msat(max_fee.msats)
                        .with_max_total_cltv_expiry_delta(max_delay as u32),
                ),
            ) {
                Ok(sent_payment_id) => sent_payment_id,
                Err(err) => {
                    self.pending_payments.write().await.remove(&payment_id);
                    // TODO: Investigate whether all error types returned by
                    // `Bolt11Payment::send()` result in idempotency.
                    return Err(LightningRpcError::FailedPayment {
                        failure_reason: format!("LDK payment failed to initialize: {err:?}"),
                    });
                }
            };
            assert_eq!(sent_payment_id, payment_id);
        }

        // The payment may already be in a terminal state (a known/resumed
        // payment, or an event that fired before we registered the waiter), so
        // check once up front before waiting.
        if let Some(result) = self.ldk_payment_result(payment_id) {
            self.pending_payments.write().await.remove(&payment_id);
            return result;
        }

        // Otherwise wait for the event handler to wake us when a terminal
        // `PaymentSuccessful` / `PaymentFailed` event arrives, instead of
        // polling. A wakeup is delivered exactly once; the payment status is
        // terminal by the time it fires.
        let _ = payment_receiver.await;

        self.pending_payments.write().await.remove(&payment_id);
        self.ldk_payment_result(payment_id).unwrap_or_else(|| {
            Err(LightningRpcError::FailedPayment {
                failure_reason: "LDK payment event fired without terminal payment status"
                    .to_string(),
            })
        })
    }

    async fn outbound_payment_exists(
        &self,
        payment_hash: sha256::Hash,
    ) -> Result<bool, LightningRpcError> {
        Ok(self
            .outbound_payment(PaymentId(payment_hash.to_byte_array()))
            .is_some())
    }

    async fn route_htlcs<'a>(
        mut self: Box<Self>,
        _task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        let route_htlc_stream = match self.htlc_stream_receiver_or.take() {
            Some(stream) => Ok(Box::pin(ReceiverStream::new(stream))),
            None => Err(LightningRpcError::FailedToRouteHtlcs {
                failure_reason:
                    "Stream does not exist. Likely was already taken by calling `route_htlcs()`."
                        .to_string(),
            }),
        }?;

        Ok((route_htlc_stream, Arc::new(*self)))
    }

    async fn complete_htlc(&self, htlc: InterceptPaymentResponse) -> Result<(), LightningRpcError> {
        let InterceptPaymentResponse {
            action,
            payment_hash,
            incoming_chan_id: _,
            htlc_id: _,
        } = htlc;

        let ph = PaymentHash(*payment_hash.clone().as_byte_array());

        // TODO: Get the actual amount from the LDK node. Probably makes the
        // most sense to pipe it through the `InterceptHtlcResponse` struct.
        // This value is only used by `ldk-node` to ensure that the amount
        // claimed isn't less than the amount expected, but we've already
        // verified that the amount is correct when we intercepted the payment.
        let claimable_amount_msat = 999_999_999_999_999;

        let ph_hex_str = hex::encode(payment_hash);

        let PaymentAction::Settle(preimage) = action else {
            warn!(target: LOG_LIGHTNING, payment_hash = %ph_hex_str, "Unwinding payment because the action was not `Settle`");

            // See `HeldPaymentStore::fail_back`. If the record cannot be marked,
            // or the node cannot fail the payment back, the payment stays held
            // and recorded, and the call can be retried.
            return self
                .held_payments
                .fail_back(ph, || {
                    self.node
                        .bolt11_payment()
                        .fail_for_hash(ph)
                        .map_err(|err| htlc_completion_error(&err, &ph_hex_str))
                })
                .await
                .map_err(|err| {
                    warn!(
                        target: LOG_LIGHTNING,
                        payment_hash = %ph_hex_str,
                        err = %err.fmt_compact(),
                        "Could not mark held payment record, leaving the payment held"
                    );
                    LightningRpcError::FailedToCompleteHtlc {
                        failure_reason: format!(
                            "Could not mark held payment record: {}",
                            err.fmt_compact()
                        ),
                    }
                })?;
        };

        // Claimed and removed under `delivery_lock`, like a fail-back, so a
        // delivery from the record either comes before the claim or finds the
        // record removed. Neither step waits for room on the HTLC stream.
        let _deliveries = self.held_payments.delivery_lock.lock().await;

        let result = self
            .node
            .bolt11_payment()
            .claim_for_hash(ph, claimable_amount_msat, PaymentPreimage(preimage.0))
            .map_err(|err| htlc_completion_error(&err, &ph_hex_str));

        // The gateway has resolved the payment once the node claimed it or
        // rejected the claim for good, so it is not delivered again: LDK
        // persists the preimage before `claim_for_hash` returns, and finishes
        // the claim after a restart on its own. A transient failure keeps the
        // record, so the payment is delivered again when the node next starts
        // unless a retry claims it first. A record that cannot be removed here
        // is removed once LDK Node reports the payment received, or the node
        // can no longer claim it.
        if matches!(
            result,
            Ok(()) | Err(LightningRpcError::HtlcCompletionRejected { .. })
        ) && let Err(err) = self.held_payments.remove(ph)
        {
            warn!(
                target: LOG_LIGHTNING,
                payment_hash = %ph_hex_str,
                err = %err.fmt_compact(),
                "Could not remove held payment record"
            );
        }

        result
    }

    async fn create_invoice(
        &self,
        create_invoice_request: CreateInvoiceRequest,
    ) -> Result<CreateInvoiceResponse, LightningRpcError> {
        let payment_hash_or = if let Some(payment_hash) = create_invoice_request.payment_hash {
            let ph = PaymentHash(*payment_hash.as_byte_array());
            Some(ph)
        } else {
            None
        };

        let description = match create_invoice_request.description {
            Some(InvoiceDescription::Direct(desc)) => {
                Bolt11InvoiceDescription::Direct(Description::new(desc).map_err(|_| {
                    LightningRpcError::FailedToGetInvoice {
                        failure_reason: "Invalid description".to_string(),
                    }
                })?)
            }
            Some(InvoiceDescription::Hash(hash)) => {
                Bolt11InvoiceDescription::Hash(lightning_invoice::Sha256(hash))
            }
            None => Bolt11InvoiceDescription::Direct(Description::empty()),
        };

        let invoice = match payment_hash_or {
            Some(payment_hash) => {
                // `pay()` holds this lock for the whole life of an outbound
                // payment, so failing to take it means a payment for this hash
                // is in flight right now. Keeping it until `receive_for_hash()`
                // has run means `pay()` cannot write its outbound record between
                // our check and the registration's insert, which would
                // overwrite it.
                let payment_id = PaymentId(payment_hash.0);
                let outbound_lock_guard = self
                    .outbound_lightning_payment_lock_pool
                    .try_lock(payment_id);
                let existing_direction = self
                    .node
                    .payment(&payment_id)
                    .map(|details| details.direction);
                if let Err(refusal) =
                    check_inbound_registration(outbound_lock_guard.is_some(), existing_direction)
                {
                    warn!(
                        target: LOG_LIGHTNING,
                        payment_hash = %hex::encode(payment_hash.0),
                        %refusal,
                        "Refusing to register an invoice for a payment hash we pay outbound"
                    );
                    return Err(LightningRpcError::FailedToGetInvoice {
                        failure_reason: format!(
                            "Payment hash cannot be registered for an invoice: {refusal}"
                        ),
                    });
                }

                self.node.bolt11_payment().receive_for_hash(
                    create_invoice_request.amount_msat,
                    &description,
                    create_invoice_request.expiry_secs,
                    payment_hash,
                )
            }
            None => self.node.bolt11_payment().receive(
                create_invoice_request.amount_msat,
                &description,
                create_invoice_request.expiry_secs,
            ),
        }
        .map_err(|e| LightningRpcError::FailedToGetInvoice {
            failure_reason: e.to_string(),
        })?;

        Ok(CreateInvoiceResponse {
            invoice: invoice.to_string(),
        })
    }

    async fn get_ln_onchain_address(
        &self,
    ) -> Result<GetLnOnchainAddressResponse, LightningRpcError> {
        self.node
            .onchain_payment()
            .new_address()
            .map(|address| GetLnOnchainAddressResponse {
                address: address.to_string(),
            })
            .map_err(|e| LightningRpcError::FailedToGetLnOnchainAddress {
                failure_reason: e.to_string(),
            })
    }

    async fn send_onchain(
        &self,
        SendOnchainRequest {
            address,
            amount,
            fee_rate_sats_per_vbyte,
        }: SendOnchainRequest,
    ) -> Result<SendOnchainResponse, LightningRpcError> {
        let onchain = self.node.onchain_payment();

        let retain_reserves = false;
        let txid = match amount {
            BitcoinAmountOrAll::All => onchain.send_all_to_address(
                &address.assume_checked(),
                retain_reserves,
                FeeRate::from_sat_per_vb(fee_rate_sats_per_vbyte),
            ),
            BitcoinAmountOrAll::Amount(amount_sats) => onchain.send_to_address(
                &address.assume_checked(),
                amount_sats.to_sat(),
                FeeRate::from_sat_per_vb(fee_rate_sats_per_vbyte),
            ),
        }
        .map_err(|e| LightningRpcError::FailedToWithdrawOnchain {
            failure_reason: e.to_string(),
        })?;

        Ok(SendOnchainResponse {
            txid: txid.to_string(),
        })
    }

    async fn open_channel(
        &self,
        OpenChannelRequest {
            pubkey,
            host,
            channel_size_sats,
            push_amount_sats,
            fee_rate_sats_per_vbyte,
            base_fee_msat,
            parts_per_million,
        }: OpenChannelRequest,
    ) -> Result<OpenChannelResponse, LightningRpcError> {
        let push_amount_msats_or = if push_amount_sats == 0 {
            None
        } else {
            Some(push_amount_sats * 1000)
        };

        if fee_rate_sats_per_vbyte.is_some() {
            // LDK manages its own fee estimation for funding transactions; the
            // user-supplied rate cannot be applied here.
            warn!(
                target: LOG_LIGHTNING,
                "Ignoring fee_rate_sats_per_vbyte on LDK channel open; LDK uses its built-in fee estimator"
            );
        }

        let channel_config = match (base_fee_msat, parts_per_million) {
            (None, None) => None,
            (base, ppm) => {
                let mut config = ChannelConfig::default();
                if let Some(base) = base {
                    config.forwarding_fee_base_msat = u32::try_from(base).map_err(|_| {
                        LightningRpcError::FailedToOpenChannel {
                            failure_reason: format!(
                                "base_fee_msat {base} does not fit in u32 (LDK limit)"
                            ),
                        }
                    })?;
                }
                if let Some(ppm) = ppm {
                    config.forwarding_fee_proportional_millionths =
                        u32::try_from(ppm).map_err(|_| LightningRpcError::FailedToOpenChannel {
                            failure_reason: format!(
                                "parts_per_million {ppm} does not fit in u32 (LDK limit)"
                            ),
                        })?;
                }
                Some(config)
            }
        };

        let (tx, rx) = oneshot::channel::<Result<OutPoint, String>>();

        {
            let mut channels = self.pending_channels.write().await;
            let user_channel_id = self
                .node
                .open_announced_channel(
                    pubkey,
                    SocketAddress::from_str(&host).map_err(|e| {
                        LightningRpcError::FailedToConnectToPeer {
                            failure_reason: e.to_string(),
                        }
                    })?,
                    channel_size_sats,
                    push_amount_msats_or,
                    channel_config,
                )
                .map_err(|e| LightningRpcError::FailedToOpenChannel {
                    failure_reason: e.to_string(),
                })?;

            channels.insert(UserChannelId(user_channel_id), tx);
        }

        match rx
            .await
            .map_err(|err| LightningRpcError::FailedToOpenChannel {
                failure_reason: err.to_string(),
            })? {
            Ok(outpoint) => {
                let funding_txid = outpoint.txid;

                Ok(OpenChannelResponse {
                    funding_txid: funding_txid.to_string(),
                })
            }
            Err(failure_reason) => Err(LightningRpcError::FailedToOpenChannel { failure_reason }),
        }
    }

    async fn connect_peer(&self, payload: ConnectPeerRequest) -> Result<(), LightningRpcError> {
        let NodeAddress { pubkey, address } = payload.node_address;
        // Persist the peer so ldk-node automatically reconnects after restarts
        // and connection drops. Without this a gateway whose only channel was
        // opened inbound (e.g. bought from an LSP) has no stored peer address
        // and the channel stays inactive after any disconnect until an
        // operator manually reconnects.
        self.node.connect(pubkey, address, true).map_err(|e| {
            LightningRpcError::FailedToConnectToPeer {
                failure_reason: e.to_string(),
            }
        })
    }

    async fn close_channels_with_peer(
        &self,
        CloseChannelsWithPeerRequest {
            pubkey,
            force,
            sats_per_vbyte: _,
        }: CloseChannelsWithPeerRequest,
    ) -> Result<CloseChannelsWithPeerResponse, LightningRpcError> {
        let mut num_channels_closed = 0;

        info!(%pubkey, "Closing all channels with peer");
        for channel_with_peer in self
            .node
            .list_channels()
            .iter()
            .filter(|channel| channel.counterparty_node_id == pubkey)
        {
            if force {
                match self.node.force_close_channel(
                    &channel_with_peer.user_channel_id,
                    pubkey,
                    Some("User initiated force close".to_string()),
                ) {
                    Ok(()) => num_channels_closed += 1,
                    Err(err) => {
                        error!(%pubkey, err = %err.fmt_compact(), "Could not force close channel");
                    }
                }
            } else {
                match self
                    .node
                    .close_channel(&channel_with_peer.user_channel_id, pubkey)
                {
                    Ok(()) => {
                        num_channels_closed += 1;
                    }
                    Err(err) => {
                        error!(%pubkey, err = %err.fmt_compact(), "Could not close channel");
                    }
                }
            }
        }

        Ok(CloseChannelsWithPeerResponse {
            num_channels_closed,
        })
    }

    async fn list_channels(&self) -> Result<ListChannelsResponse, LightningRpcError> {
        let mut channels = Vec::new();
        let network_graph = self.node.network_graph();

        // Build a map of peer pubkey -> address from connected/known peers
        let peer_addresses: std::collections::HashMap<_, _> = self
            .node
            .list_peers()
            .into_iter()
            .map(|peer| (peer.node_id, peer.address.to_string()))
            .collect();

        for channel_details in self.node.list_channels().iter() {
            let node_id = NodeId::from_pubkey(&channel_details.counterparty_node_id);
            let node_info = network_graph.node(&node_id);

            // Look up peer alias from network graph
            let remote_node_alias = node_info.as_ref().and_then(|info| {
                info.announcement_info.as_ref().and_then(|announcement| {
                    let alias = announcement.alias().to_string();
                    if alias.is_empty() { None } else { Some(alias) }
                })
            });

            let remote_address = peer_addresses
                .get(&channel_details.counterparty_node_id)
                .cloned();

            channels.push(ChannelInfo {
                remote_pubkey: channel_details.counterparty_node_id,
                channel_size_sats: channel_details.channel_value_sats,
                outbound_liquidity_sats: channel_details.outbound_capacity_msat / 1000,
                inbound_liquidity_sats: channel_details.inbound_capacity_msat / 1000,
                is_active: channel_details.is_usable,
                funding_outpoint: channel_details.funding_txo,
                remote_node_alias,
                remote_address,
                base_fee_msat: Some(u64::from(channel_details.config.forwarding_fee_base_msat)),
                parts_per_million: Some(u64::from(
                    channel_details
                        .config
                        .forwarding_fee_proportional_millionths,
                )),
            });
        }

        Ok(ListChannelsResponse { channels })
    }

    async fn set_channel_fees(
        &self,
        payload: SetChannelFeesRequest,
    ) -> Result<(), LightningRpcError> {
        // ldk-node's `update_channel_config` is keyed by `UserChannelId` +
        // counterparty pubkey, so resolve the funding outpoint to those by
        // scanning the live channel list.
        let channel = self
            .node
            .list_channels()
            .into_iter()
            .find(|c| c.funding_txo == Some(payload.funding_outpoint))
            .ok_or_else(|| LightningRpcError::FailedToSetChannelFees {
                failure_reason: format!(
                    "No channel found with funding outpoint {}",
                    payload.funding_outpoint,
                ),
            })?;

        let forwarding_fee_base_msat = u32::try_from(payload.base_fee_msat).map_err(|_| {
            LightningRpcError::FailedToSetChannelFees {
                failure_reason: format!(
                    "base_fee_msat {} does not fit in u32 (LDK limit)",
                    payload.base_fee_msat,
                ),
            }
        })?;
        let forwarding_fee_proportional_millionths = u32::try_from(payload.parts_per_million)
            .map_err(|_| LightningRpcError::FailedToSetChannelFees {
                failure_reason: format!(
                    "parts_per_million {} does not fit in u32 (LDK limit)",
                    payload.parts_per_million,
                ),
            })?;

        // Copy the channel's current config so we only change the two fee
        // fields and preserve cltv_expiry_delta, dust limits, etc.
        let new_config = ChannelConfig {
            forwarding_fee_base_msat,
            forwarding_fee_proportional_millionths,
            ..channel.config
        };

        self.node
            .update_channel_config(
                &channel.user_channel_id,
                channel.counterparty_node_id,
                new_config,
            )
            .map_err(|e| LightningRpcError::FailedToSetChannelFees {
                failure_reason: e.to_string(),
            })?;

        Ok(())
    }

    async fn get_balances(&self) -> Result<GetBalancesResponse, LightningRpcError> {
        let balances = self.node.list_balances();
        let channel_lists = self
            .node
            .list_channels()
            .into_iter()
            .filter(|chan| chan.is_usable)
            .collect::<Vec<_>>();
        // map and get the total inbound_capacity_msat in the channels
        let total_inbound_liquidity_balance_msat: u64 = channel_lists
            .iter()
            .map(|channel| channel.inbound_capacity_msat)
            .sum();

        Ok(GetBalancesResponse {
            onchain_balance_sats: balances.total_onchain_balance_sats,
            lightning_balance_msats: balances.total_lightning_balance_sats * 1000,
            inbound_lightning_liquidity_msats: total_inbound_liquidity_balance_msat,
        })
    }

    async fn get_invoice(
        &self,
        get_invoice_request: GetInvoiceRequest,
    ) -> Result<Option<GetInvoiceResponse>, LightningRpcError> {
        let invoices = self
            .node
            .list_payments_with_filter(|details| {
                details.direction == PaymentDirection::Inbound
                    && details.id == PaymentId(get_invoice_request.payment_hash.to_byte_array())
                    && !matches!(details.kind, PaymentKind::Onchain { .. })
            })
            .iter()
            .map(|details| {
                let (preimage, payment_hash, _) = get_preimage_and_payment_hash(&details.kind);
                let status = match details.status {
                    PaymentStatus::Failed => fedimint_gateway_common::PaymentStatus::Failed,
                    PaymentStatus::Succeeded => fedimint_gateway_common::PaymentStatus::Succeeded,
                    PaymentStatus::Pending => fedimint_gateway_common::PaymentStatus::Pending,
                };
                GetInvoiceResponse {
                    preimage: preimage.map(|p| p.to_string()),
                    payment_hash,
                    amount: Amount::from_msats(
                        details
                            .amount_msat
                            .expect("amountless invoices are not supported"),
                    ),
                    created_at: UNIX_EPOCH + Duration::from_secs(details.latest_update_timestamp),
                    status,
                }
            })
            .collect::<Vec<_>>();

        Ok(invoices.first().cloned())
    }

    async fn list_transactions(
        &self,
        start_secs: u64,
        end_secs: u64,
    ) -> Result<ListTransactionsResponse, LightningRpcError> {
        let transactions = self
            .node
            .list_payments_with_filter(|details| {
                !matches!(details.kind, PaymentKind::Onchain { .. })
                    && details.latest_update_timestamp >= start_secs
                    && details.latest_update_timestamp < end_secs
            })
            .iter()
            .map(|details| {
                let (preimage, payment_hash, payment_kind) =
                    get_preimage_and_payment_hash(&details.kind);
                let direction = match details.direction {
                    PaymentDirection::Outbound => {
                        fedimint_gateway_common::PaymentDirection::Outbound
                    }
                    PaymentDirection::Inbound => fedimint_gateway_common::PaymentDirection::Inbound,
                };
                let status = match details.status {
                    PaymentStatus::Failed => fedimint_gateway_common::PaymentStatus::Failed,
                    PaymentStatus::Succeeded => fedimint_gateway_common::PaymentStatus::Succeeded,
                    PaymentStatus::Pending => fedimint_gateway_common::PaymentStatus::Pending,
                };
                fedimint_gateway_common::PaymentDetails {
                    payment_hash,
                    preimage: preimage.map(|p| p.to_string()),
                    payment_kind,
                    amount: Amount::from_msats(
                        details
                            .amount_msat
                            .expect("amountless invoices are not supported"),
                    ),
                    direction,
                    status,
                    timestamp_secs: details.latest_update_timestamp,
                }
            })
            .collect::<Vec<_>>();
        Ok(ListTransactionsResponse { transactions })
    }

    fn create_offer(
        &self,
        amount: Option<Amount>,
        description: Option<String>,
        expiry_secs: Option<u32>,
        quantity: Option<u64>,
    ) -> Result<String, LightningRpcError> {
        let description = description.unwrap_or_default();
        let offer = if let Some(amount) = amount {
            self.node
                .bolt12_payment()
                .receive(amount.msats, &description, expiry_secs, quantity)
                .map_err(|err| LightningRpcError::Bolt12Error {
                    failure_reason: err.to_string(),
                })?
        } else {
            self.node
                .bolt12_payment()
                .receive_variable_amount(&description, expiry_secs)
                .map_err(|err| LightningRpcError::Bolt12Error {
                    failure_reason: err.to_string(),
                })?
        };

        Ok(offer.to_string())
    }

    async fn pay_offer(
        &self,
        offer: String,
        quantity: Option<u64>,
        amount: Option<Amount>,
        payer_note: Option<String>,
    ) -> Result<Preimage, LightningRpcError> {
        let offer = Offer::from_str(&offer).map_err(|_| LightningRpcError::Bolt12Error {
            failure_reason: "Failed to parse Bolt12 Offer".to_string(),
        })?;

        let _offer_lock_guard = self
            .outbound_offer_lock_pool
            .blocking_lock(LdkOfferId(offer.id()));

        let payment_id = if let Some(amount) = amount {
            self.node
                .bolt12_payment()
                .send_using_amount(&offer, amount.msats, quantity, payer_note, None)
                .map_err(|err| LightningRpcError::Bolt12Error {
                    failure_reason: err.to_string(),
                })?
        } else {
            self.node
                .bolt12_payment()
                .send(&offer, quantity, payer_note, None)
                .map_err(|err| LightningRpcError::Bolt12Error {
                    failure_reason: err.to_string(),
                })?
        };

        loop {
            if let Some(payment_details) = self.node.payment(&payment_id) {
                match payment_details.status {
                    PaymentStatus::Pending => {}
                    PaymentStatus::Succeeded => match payment_details.kind {
                        PaymentKind::Bolt12Offer {
                            preimage: Some(preimage),
                            ..
                        } => {
                            info!(target: LOG_LIGHTNING, offer = %offer, payment_id = %payment_id, preimage = %preimage, "Successfully paid offer");
                            return Ok(Preimage(preimage.0));
                        }
                        _ => {
                            return Err(LightningRpcError::FailedPayment {
                                failure_reason: "Unexpected payment kind".to_string(),
                            });
                        }
                    },
                    PaymentStatus::Failed => {
                        return Err(LightningRpcError::FailedPayment {
                            failure_reason: "Bolt12 payment failed".to_string(),
                        });
                    }
                }
            }
            fedimint_core::runtime::sleep(Duration::from_millis(100)).await;
        }
    }

    fn sync_wallet(&self) -> Result<(), LightningRpcError> {
        block_in_place(|| {
            let _ = self.node.sync_wallets();
        });
        Ok(())
    }

    // The node hands a request it does not claim back by value, once per
    // onion message; boxing it would allocate for every request the node
    // answers itself.
    #[allow(clippy::result_large_err)]
    fn bolt12_requests(
        &self,
        filter: Bolt12RequestFilter,
    ) -> Result<tokio::sync::mpsc::Receiver<Bolt12Request>, LightningRpcError> {
        let (sender, receiver) = tokio::sync::mpsc::channel(MAX_QUEUED_BOLT12_REQUESTS);
        // The node owns the handler, so the handler must not own the node.
        let node = Arc::downgrade(&self.node);

        self.node.set_external_bolt12_request_handler(Arc::new(
            move |request: ExternalInvoiceRequest| {
                if !filter(request.invoice_request()) {
                    return Err(request);
                }

                let invoice_request = request.invoice_request().clone();
                let node: Weak<ldk_node::Node> = node.clone();

                let request = Bolt12Request::new(invoice_request, move |invoice| {
                    node.upgrade()
                        .ok_or_else(|| LightningRpcError::Bolt12Error {
                            failure_reason: "The Lightning node has stopped".to_string(),
                        })?
                        .respond_external_bolt12(request, invoice)
                        .map_err(|err| LightningRpcError::Bolt12Error {
                            failure_reason: format!("Cannot queue the invoice: {err}"),
                        })
                });

                if sender.try_send(request).is_err() {
                    debug!(target: LOG_LIGHTNING, "Dropping a BOLT12 invoice request: the queue is full");
                }

                Ok(())
            },
        ));

        Ok(receiver)
    }

    async fn bolt12_message_path(&self) -> Result<BlindedMessagePath, LightningRpcError> {
        Ok(self.node.external_bolt12_message_path())
    }

    async fn register_bolt12_payment(
        &self,
        payment_hash: sha256::Hash,
        amount: Amount,
        invoice_request: &InvoiceRequest,
        offer_id: [u8; 32],
    ) -> Result<BlindedPaymentPath, LightningRpcError> {
        // The same guard as `create_invoice`: a registration must not
        // overwrite the record of a payment we send for this hash.
        let payment_id = PaymentId(payment_hash.to_byte_array());
        let outbound_lock_guard = self
            .outbound_lightning_payment_lock_pool
            .try_lock(payment_id);
        let existing_direction = self
            .node
            .payment(&payment_id)
            .map(|details| details.direction);

        check_inbound_registration(outbound_lock_guard.is_some(), existing_direction).map_err(
            |refusal| LightningRpcError::Bolt12Error {
                failure_reason: format!("Payment hash cannot be registered: {refusal}"),
            },
        )?;

        self.node
            .register_external_bolt12_payment(
                PaymentHash(payment_hash.to_byte_array()),
                amount.msats,
                invoice_request,
                OfferId(offer_id),
            )
            .map_err(|err| LightningRpcError::Bolt12Error {
                failure_reason: format!("Cannot register the payment: {err}"),
            })
    }
}

/// Maps LDK's `PaymentKind` to an optional preimage and an optional payment
/// hash depending on the type of payment.
fn get_preimage_and_payment_hash(
    kind: &PaymentKind,
) -> (
    Option<Preimage>,
    Option<sha256::Hash>,
    fedimint_gateway_common::PaymentKind,
) {
    match kind {
        PaymentKind::Bolt11 {
            hash,
            preimage,
            secret: _,
        } => (
            preimage.map(|p| Preimage(p.0)),
            Some(sha256::Hash::from_slice(&hash.0).expect("Failed to convert payment hash")),
            fedimint_gateway_common::PaymentKind::Bolt11,
        ),
        PaymentKind::Bolt11Jit { hash, preimage, .. } => (
            preimage.map(|p| Preimage(p.0)),
            Some(sha256::Hash::from_slice(&hash.0).expect("Failed to convert payment hash")),
            fedimint_gateway_common::PaymentKind::Bolt11,
        ),
        PaymentKind::Bolt12Offer {
            hash,
            preimage,
            secret: _,
            offer_id: _,
            payer_note: _,
            quantity: _,
        } => (
            preimage.map(|p| Preimage(p.0)),
            hash.map(|h| sha256::Hash::from_slice(&h.0).expect("Failed to convert payment hash")),
            fedimint_gateway_common::PaymentKind::Bolt12Offer,
        ),
        PaymentKind::Bolt12Refund {
            hash,
            preimage,
            secret: _,
            payer_note: _,
            quantity: _,
        } => (
            preimage.map(|p| Preimage(p.0)),
            hash.map(|h| sha256::Hash::from_slice(&h.0).expect("Failed to convert payment hash")),
            fedimint_gateway_common::PaymentKind::Bolt12Refund,
        ),
        PaymentKind::Spontaneous { hash, preimage } => (
            preimage.map(|p| Preimage(p.0)),
            Some(sha256::Hash::from_slice(&hash.0).expect("Failed to convert payment hash")),
            fedimint_gateway_common::PaymentKind::Bolt11,
        ),
        PaymentKind::Onchain { .. } => (None, None, fedimint_gateway_common::PaymentKind::Onchain),
    }
}

/// When a port is specified in the Esplora URL, the esplora client inside LDK
/// node cannot connect to the lightning node when there is a trailing slash.
/// The `SafeUrl::Display` function will always serialize the `SafeUrl` with a
/// trailing slash, which causes the connection to fail.
///
/// To handle this, we explicitly construct the esplora URL when a port is
/// specified.
fn get_esplora_url(server_url: SafeUrl) -> Result<String, LdkClientInitError> {
    // Esplora client cannot handle trailing slashes
    let host = server_url
        .host_str()
        .ok_or(LdkClientInitError::MissingEsploraHost)?;
    let server_url = if let Some(port) = server_url.port() {
        format!("{}://{}:{}", server_url.scheme(), host, port)
    } else {
        server_url.to_string()
    };
    Ok(server_url)
}

/// Outcome of attempting to wake a `pay()` waiter for a terminal payment event.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum PendingPaymentWakeup {
    /// No waiter was registered for the payment id.
    NoWaiter,
    /// A waiter was registered and successfully woken.
    Woken,
    /// A waiter was registered but its receiver had already been dropped.
    ReceiverDropped,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct LdkOfferId(OfferId);

impl std::hash::Hash for LdkOfferId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0.0);
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UserChannelId(pub ldk_node::UserChannelId);

impl PartialOrd for UserChannelId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for UserChannelId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.0.cmp(&other.0.0)
    }
}

#[cfg(test)]
mod tests;
