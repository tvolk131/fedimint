//! Federated BOLT12: answering invoice requests for offers the federation
//! issues, and funding the recipient's claim when the payment arrives.
//!
//! See `docs/federated_bolt12.md` for the protocol.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, ensure};
use bitcoin::hashes::{Hash as _, sha256};
use fedimint_bolt12_common::gateway_api::{Bolt12Ingress, PaymentFee};
use fedimint_bolt12_common::invoice::{is_routing_metadata, parse_routing_metadata};
use fedimint_bolt12_common::protocol::INVOICE_LIFETIME;
use fedimint_core::config::FederationId;
use fedimint_core::task::{TaskGroup, timeout};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::FmtCompact as _;
use fedimint_core::{Amount, crit};
use fedimint_gateway_server_db::{GatewayDbtxNcExt as _, PaymentHashOwner, PaymentHashProtocol};
use fedimint_gw_bolt12_client::receive::{Bolt12InvoiceRequest, Bolt12PaymentPathError};
use fedimint_gw_bolt12_client::{GatewayClientModuleBolt12, IncomingCircuitKey};
use fedimint_lightning::bolt12::{Bolt12Request, Bolt12RequestFilter};
use fedimint_lightning::{
    ILnRpcClient, InterceptPaymentRequest, InterceptPaymentResponse, LightningContext,
    PaymentAction,
};
use fedimint_logging::LOG_GATEWAY;
use lightning::offers::invoice_request::InvoiceRequest;
use lightning::util::ser::Writeable as _;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::error::FederationNotConnected;
use crate::{Gateway, PublicGatewayError, Result, metrics};

/// Invoice requests answered at once. Each one waits on a consensus round
/// and two signing rounds, so they must overlap; beyond this many the
/// gateway drops requests and payers retry.
const MAX_CONCURRENT_REQUESTS: usize = 16;

/// How long the gateway works on one invoice request. Payers give up on an
/// unanswered request after about this long.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Extra margin kept on `PaymentHashOwner` rows past `INVOICE_LIFETIME` before
/// background pruning may remove them.
const BOLT12_OWNER_RETENTION_SECS: u64 = 3600;

/// Invoice requests being answered, by the hash of their bytes. Payers resend
/// a request they have no answer to yet; a resend that overlapped the first
/// attempt would reserve a second stock item for the same payment.
#[derive(Default)]
struct InProgress(Mutex<HashSet<sha256::Hash>>);

impl InProgress {
    /// Claim `request`, or `None` if it is already being answered. The claim
    /// ends when the returned guard drops.
    fn claim(self: &Arc<Self>, request: &InvoiceRequest) -> Option<InProgressGuard> {
        let key = sha256::Hash::hash(&request.encode());

        self.0
            .lock()
            .expect("not poisoned")
            .insert(key)
            .then(|| InProgressGuard(self.clone(), key))
    }
}

struct InProgressGuard(Arc<InProgress>, sha256::Hash);

impl Drop for InProgressGuard {
    fn drop(&mut self) {
        self.0.0.lock().expect("not poisoned").remove(&self.1);
    }
}

fn is_federated(request: &InvoiceRequest) -> bool {
    request
        .metadata()
        .is_some_and(|metadata| is_routing_metadata(metadata))
}

impl Gateway {
    async fn bolt12_receive_config(
        &self,
        federation_id: FederationId,
    ) -> Result<(PaymentFee, bool)> {
        let mut dbtx = self.gateway_db.begin_transaction_nc().await;
        let fed_config = dbtx.load_federation_config(federation_id).await.ok_or(
            PublicGatewayError::FederationNotConnected(FederationNotConnected {
                federation_id_prefix: federation_id.to_prefix(),
            }),
        )?;

        let fee = fed_config.transaction_fee;
        Ok((
            PaymentFee {
                base: fee.base,
                parts_per_million: fee.parts_per_million,
            },
            fed_config.receive_enabled(),
        ))
    }

    /// How payers reach this gateway for a federation's BOLT12 offers, or
    /// `None` if it does not serve them there.
    pub async fn bolt12_ingress(
        &self,
        federation_id: &FederationId,
    ) -> Result<Option<Bolt12Ingress>> {
        let (receive_fee, receive_enabled) = self.bolt12_receive_config(*federation_id).await?;

        let client = self.select_client(*federation_id).await?;
        let Ok(module) = client
            .value()
            .get_first_module::<GatewayClientModuleBolt12>()
        else {
            return Ok(None);
        };

        if !receive_enabled {
            return Ok(None);
        }

        let context = self.get_lightning_context().await?;

        match context.lnrpc.bolt12_message_path().await {
            Ok(path) => Ok(Some(Bolt12Ingress::new(
                *federation_id,
                &path,
                &module.keypair,
                receive_fee,
            ))),
            Err(err) => {
                debug!(target: LOG_GATEWAY, err = %err.fmt_compact(), "No BOLT12 message path");
                Ok(None)
            }
        }
    }

    /// Answer federated invoice requests the Lightning node receives until
    /// `task_group` shuts down. Does nothing if the node cannot serve them.
    pub fn spawn_bolt12_request_handler(
        &self,
        task_group: &TaskGroup,
        lnrpc: Arc<dyn ILnRpcClient>,
    ) {
        let filter: Bolt12RequestFilter = Arc::new(is_federated);

        let mut requests = match lnrpc.bolt12_requests(filter) {
            Ok(requests) => requests,
            Err(err) => {
                debug!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Not serving federated BOLT12 offers");
                return;
            }
        };

        for outcome in [
            "issued",
            "error",
            "timeout",
            "dropped_duplicate",
            "dropped_busy",
        ] {
            let _ = metrics::BOLT12_INVOICE_REQUESTS_TOTAL.with_label_values(&[outcome]);
        }

        let gateway = self.clone();
        let request_tasks = task_group.clone();

        task_group.spawn_cancellable("bolt12 invoice requests", async move {
            let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
            let in_progress = Arc::new(InProgress::default());

            while let Some(request) = requests.recv().await {
                // The first attempt answers over its own reply path, which
                // reaches the same payer.
                let Some(claim) = in_progress.claim(&request.invoice_request) else {
                    metrics::BOLT12_INVOICE_REQUESTS_TOTAL
                        .with_label_values(&["dropped_duplicate"])
                        .inc();
                    debug!(target: LOG_GATEWAY, "Dropping a resent BOLT12 invoice request that is still being answered");
                    continue;
                };

                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    metrics::BOLT12_INVOICE_REQUESTS_TOTAL
                        .with_label_values(&["dropped_busy"])
                        .inc();
                    debug!(target: LOG_GATEWAY, "Dropping a BOLT12 invoice request: too many in progress");
                    continue;
                };

                let gateway = gateway.clone();
                let lnrpc = lnrpc.clone();

                request_tasks.spawn_cancellable_silent("bolt12 invoice request", async move {
                    let _permit = permit;
                    let _claim = claim;

                    match timeout(REQUEST_TIMEOUT, gateway.answer_bolt12_request(request, lnrpc))
                        .await
                    {
                        Ok(Ok(())) => {
                            metrics::BOLT12_INVOICE_REQUESTS_TOTAL
                                .with_label_values(&["issued"])
                                .inc();
                        }
                        Ok(Err(err)) => {
                            metrics::BOLT12_INVOICE_REQUESTS_TOTAL
                                .with_label_values(&["error"])
                                .inc();
                            info!(target: LOG_GATEWAY, err = %(&*err).fmt_compact(), "Did not answer a BOLT12 invoice request");
                        }
                        Err(_) => {
                            metrics::BOLT12_INVOICE_REQUESTS_TOTAL
                                .with_label_values(&["timeout"])
                                .inc();
                            info!(target: LOG_GATEWAY, "Timed out answering a BOLT12 invoice request");
                        }
                    }
                });
            }
        });
    }

    /// Answer one claimed invoice request with a federation-signed invoice.
    pub async fn answer_bolt12_request(
        &self,
        request: Bolt12Request,
        lnrpc: Arc<dyn ILnRpcClient>,
    ) -> anyhow::Result<()> {
        // Every request costs the federation a reservation and the node a
        // registered payment, so it shares the invoice rate limit.
        ensure!(
            self.invoice_rate_limiter.try_acquire(),
            "BOLT12 invoice requests are rate limited"
        );

        let invoice_request = Arc::new(request.invoice_request.clone());

        let (federation_id, handle) = parse_routing_metadata(
            invoice_request
                .metadata()
                .context("The offer carries no metadata")?,
        )?;

        let amount = Amount::from_msats(
            invoice_request
                .amount_msats()
                .context("The request names no amount")?,
        );

        let (receive_fee, receive_enabled) = self.bolt12_receive_config(federation_id).await?;

        ensure!(receive_enabled, "Receives are disabled for this federation");

        let client = self.select_client(federation_id).await?;
        let module = client
            .value()
            .get_first_module::<GatewayClientModuleBolt12>()?;

        // Track every payment hash we claimed in `gateway_db` during this
        // attempt so failed or retried hashes are released cleanly, while the
        // issued invoice's hash stays durably owned.
        let claimed_hashes: Arc<Mutex<Vec<sha256::Hash>>> = Arc::default();

        let payment_path = |payment_hash: [u8; 32]| {
            let lnrpc = lnrpc.clone();
            let invoice_request = invoice_request.clone();
            let claimed_hashes = claimed_hashes.clone();

            async move {
                let payment_hash = sha256::Hash::from_byte_array(payment_hash);

                self.claim_bolt12_hash(federation_id, payment_hash)
                    .await
                    .map_err(Bolt12PaymentPathError::HashCollision)?;
                claimed_hashes
                    .lock()
                    .expect("not poisoned")
                    .push(payment_hash);

                // The handle labels the payment in the node's records; the
                // node has no offer of its own to name.
                match lnrpc
                    .register_bolt12_payment(payment_hash, amount, &invoice_request, handle)
                    .await
                {
                    Ok(path) => Ok(path),
                    Err(err) => {
                        self.release_bolt12_hash(federation_id, payment_hash).await;
                        claimed_hashes
                            .lock()
                            .expect("not poisoned")
                            .retain(|h| *h != payment_hash);
                        Err(Bolt12PaymentPathError::Node(anyhow::Error::from(err)))
                    }
                }
            }
        };

        let invoice = match module
            .issue_invoice(
                Bolt12InvoiceRequest {
                    handle,
                    invoice_request: invoice_request.encode(),
                    amount,
                    gateway_fee: receive_fee.fee(amount.msats),
                },
                payment_path,
            )
            .await
        {
            Ok(invoice) => {
                let issued_hash = sha256::Hash::from_byte_array(invoice.payment_hash().0);
                let unused: Vec<sha256::Hash> = claimed_hashes
                    .lock()
                    .expect("not poisoned")
                    .drain(..)
                    .filter(|hash| *hash != issued_hash)
                    .collect();
                for hash in unused {
                    self.release_bolt12_hash(federation_id, hash).await;
                }
                invoice
            }
            Err(err) => {
                let all_claimed: Vec<sha256::Hash> = claimed_hashes
                    .lock()
                    .expect("not poisoned")
                    .drain(..)
                    .collect();
                for hash in all_claimed {
                    // Only release if no reservation was persisted for this hash.
                    if module.reservation_for_hash(hash).await.is_none() {
                        self.release_bolt12_hash(federation_id, hash).await;
                    }
                }
                return Err(err);
            }
        };

        request.respond(invoice)?;

        Ok(())
    }

    /// Atomically reserve `payment_hash` for BOLT12 on `federation_id` in
    /// `gateway_db`, rejecting any collision across BOLT11, BOLT12, or other
    /// federations.
    async fn claim_bolt12_hash(
        &self,
        federation_id: FederationId,
        payment_hash: sha256::Hash,
    ) -> anyhow::Result<()> {
        let expires_at_secs = duration_since_epoch()
            .as_secs()
            .saturating_add(INVOICE_LIFETIME)
            .saturating_add(BOLT12_OWNER_RETENTION_SECS);

        let mut dbtx = self.gateway_db.begin_transaction().await;
        if dbtx
            .claim_payment_hash_owner(
                payment_hash,
                &PaymentHashOwner {
                    federation_id,
                    protocol: PaymentHashProtocol::Bolt12,
                    expires_at_secs,
                },
            )
            .await
            .is_some()
        {
            anyhow::bail!("Payment hash is already owned by another invoice or federation");
        }

        dbtx.commit_tx_result().await.map_err(|_| {
            anyhow::anyhow!("Payment hash is already owned by another invoice or federation")
        })?;

        Ok(())
    }

    async fn release_bolt12_hash(&self, federation_id: FederationId, payment_hash: sha256::Hash) {
        let mut dbtx = self.gateway_db.begin_transaction().await;
        dbtx.release_payment_hash_owner(payment_hash, federation_id, PaymentHashProtocol::Bolt12)
            .await;
        if let Err(err) = dbtx.commit_tx_result().await {
            warn!(
                target: LOG_GATEWAY,
                err = %err.fmt_compact(),
                %payment_hash,
                "Failed to release BOLT12 payment hash ownership"
            );
        }
    }

    /// Fund the claim behind a held payment for a federated BOLT12 invoice on
    /// an already-resolved federation client handle (avoiding any second
    /// `federation_manager` lookup / TOCTOU with concurrent federation leave).
    pub(crate) async fn try_handle_lightning_payment_bolt12_for_client(
        &self,
        htlc_request: &InterceptPaymentRequest,
        lightning_context: &LightningContext,
        client: &fedimint_client::ClientHandleArc,
    ) -> Result<()> {
        let started = fedimint_core::time::now();
        let observe = |outcome: &str| {
            metrics::BOLT12_HTLC_HANDLING_DURATION_SECONDS
                .with_label_values(&[outcome])
                .observe(
                    fedimint_core::time::now()
                        .duration_since(started)
                        .unwrap_or_default()
                        .as_secs_f64(),
                );
        };

        let Ok(module) = client.get_first_module::<GatewayClientModuleBolt12>() else {
            observe("unmatched");
            return Err(PublicGatewayError::Unexpected(anyhow::anyhow!(
                "Federation client has no BOLT12 gateway module"
            )));
        };

        let Some(reservation) = module.reservation_for_hash(htlc_request.payment_hash).await else {
            observe("unmatched");
            return Err(PublicGatewayError::Unexpected(anyhow::anyhow!(
                "Not a federated BOLT12 payment"
            )));
        };

        // Consult `relay_bolt12_htlc` BEFORE applying `receive_enabled` so
        // an already-funded receive redelivered after a restart is always
        // resumed and settled instead of being cancelled.
        let receive_enabled = self.receive_enabled(module.federation_id).await;
        let current_block_height = lightning_context
            .lnrpc
            .info()
            .await
            .ok()
            .map(|info| info.block_height);

        if let Err(relay_err) = module
            .relay_htlc(
                reservation,
                htlc_request.payment_hash,
                IncomingCircuitKey {
                    incoming_chan_id: htlc_request.incoming_chan_id,
                    htlc_id: htlc_request.htlc_id,
                },
                htlc_request.incoming_amount_msat,
                htlc_request.lnv2_blocks_to_claim_deadline(current_block_height),
                receive_enabled,
            )
            .await
        {
            if !relay_err.htlc_may_be_failed_back() {
                observe("held");
                crit!(
                    target: LOG_GATEWAY,
                    err = %relay_err.fmt_compact(),
                    payment_hash = %htlc_request.payment_hash,
                    "Keeping held BOLT12 HTLC because its receive contract may already be funded",
                );
                return Ok(());
            }

            observe("cancelled");
            warn!(target: LOG_GATEWAY, err = %relay_err.fmt_compact(), "Failing a federated BOLT12 payment");

            let outcome = InterceptPaymentResponse {
                action: PaymentAction::Cancel,
                payment_hash: htlc_request.payment_hash,
                incoming_chan_id: htlc_request.incoming_chan_id,
                htlc_id: htlc_request.htlc_id,
            };

            if let Err(err) = self.await_complete_htlc(outcome).await {
                warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Error sending HTLC response to lightning node");
            }
        } else {
            observe("funded");
        }

        Ok(())
    }

    /// Fund the claim behind a held payment for a federated BOLT12 invoice
    /// this gateway issued. Fails if the payment is for no such invoice.
    pub async fn try_handle_lightning_payment_bolt12(
        &self,
        htlc_request: &InterceptPaymentRequest,
        lightning_context: &LightningContext,
        expected_federation: Option<FederationId>,
    ) -> Result<()> {
        let clients = self.federation_manager.read().await.clients();

        for client in clients {
            if expected_federation.is_some_and(|expected| {
                client
                    .value()
                    .get_first_module::<GatewayClientModuleBolt12>()
                    .is_ok_and(|m| m.federation_id != expected)
            }) {
                continue;
            }

            if self
                .try_handle_lightning_payment_bolt12_for_client(
                    htlc_request,
                    lightning_context,
                    client.value(),
                )
                .await
                .is_ok()
            {
                return Ok(());
            }
        }

        Err(PublicGatewayError::Unexpected(anyhow::anyhow!(
            "Not a federated BOLT12 payment"
        )))
    }
}
