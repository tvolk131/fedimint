use std::collections::HashMap;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fedimint_core::BitcoinHash as _;
use fedimint_core::encoding::Encodable as _;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::SafeUrl;
use fedimint_core::util::backoff_util::{background_backoff, custom_backoff};
use futures::FutureExt as _;
use ldk_node::NodeError;
use ldk_node::io::sqlite_store::{KV_TABLE_NAME, SQLITE_DB_FILE_NAME, SqliteStore};
use ldk_node::payment::{PaymentDirection, PaymentStatus};
use lightning::ln::channelmanager::PaymentId;
use lightning::types::payment::PaymentHash;
use lightning::util::persist::KVStoreSync;
use lockable::LockPool;
use tokio::sync::{RwLock, oneshot};

use super::{
    GatewayLdkClient, HELD_PAYMENTS_PRIMARY_NAMESPACE, HELD_PAYMENTS_SECONDARY_NAMESPACE,
    HeldPayment, HeldPaymentStore, InboundRegistrationRefusal, LdkClientInitError, MnemonicSource,
    PendingPaymentWakeup, RecordedDelivery, check_inbound_registration, get_esplora_url,
    held_payment_is_claimable, htlc_completion_error, lightning_synced_since_start,
};
use crate::LightningRpcError;

/// The gateway retries `FailedToCompleteHtlc` forever and records only
/// `HtlcCompletionRejected`, so an `ldk-node` error that cannot change on
/// retry must map to the latter or the completion state machine never ends.
#[test]
fn completion_errors_are_permanent_unless_persistence_failed() {
    for err in [
        NodeError::InvalidPaymentHash,
        NodeError::InvalidPaymentPreimage,
        NodeError::InvalidAmount,
    ] {
        assert!(
            matches!(
                htlc_completion_error(&err, "ph"),
                LightningRpcError::HtlcCompletionRejected { .. }
            ),
            "{err} must be permanent"
        );
    }

    assert!(matches!(
        htlc_completion_error(&NodeError::PersistenceFailed, "ph"),
        LightningRpcError::FailedToCompleteHtlc { .. }
    ));
}

#[test]
fn verify_ldk_esplora_url() {
    let url = SafeUrl::parse("https://mempool.space/api/").expect("Cannot parse URL");
    let esplora_url = get_esplora_url(url).expect("Could not get esplora URL");
    // URLs without ports are allowed to have trailing slashes
    assert!(esplora_url.ends_with("/"));

    let url = SafeUrl::parse("https://mutinynet.com/api/").expect("Cannot parse URL");
    let esplora_url = get_esplora_url(url).expect("Could not get esplora URL");
    // URLs without ports are allowed to have trailing slashes
    assert!(esplora_url.ends_with("/"));

    let url = SafeUrl::parse("http://127.0.0.1:3003/").expect("Cannot parse URL");
    let esplora_url = get_esplora_url(url).expect("Could not get esplora URL");
    // URLs with ports are NOT allowed to have trailing slashes
    assert!(!esplora_url.ends_with("/"));
}

#[test]
fn an_esplora_url_without_a_host_is_rejected() {
    let url = SafeUrl::parse("unix:/run/esplora.sock").expect("Cannot parse URL");

    assert!(matches!(
        get_esplora_url(url),
        Err(LdkClientInitError::MissingEsploraHost)
    ));
}

/// The data directory is checked before LDK builds anything, so a path LDK
/// cannot use is refused without touching the disk or the network.
#[cfg(unix)]
#[test]
fn a_non_utf8_data_dir_is_rejected_before_the_node_is_built() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    use bitcoin::Network;
    use fedimint_bip39::Mnemonic;
    use fedimint_gateway_common::ChainSource;

    let runtime = Arc::new(tokio::runtime::Runtime::new().expect("A tokio runtime can be built"));
    let result = GatewayLdkClient::new(
        Path::new(OsStr::from_bytes(b"\xff")),
        ChainSource::Esplora {
            server_url: SafeUrl::parse("http://127.0.0.1:3002").expect("Cannot parse URL"),
        },
        Network::Regtest,
        0,
        String::new(),
        Mnemonic::from_entropy(&[0; 16]).expect("16 bytes of entropy form a mnemonic"),
        MnemonicSource::Generated,
        runtime,
    );

    assert!(matches!(result, Err(LdkClientInitError::InvalidDataDir)));
}

#[tokio::test]
async fn wake_pending_payment_reports_waiter_state() {
    let pending_payments = Arc::new(RwLock::new(HashMap::new()));
    let payment_id = PaymentId([1; 32]);

    // No waiter registered yet.
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id).await,
        PendingPaymentWakeup::NoWaiter
    );

    // A registered waiter is woken and removed from the map.
    let (sender, receiver) = oneshot::channel();
    pending_payments.write().await.insert(payment_id, sender);
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id).await,
        PendingPaymentWakeup::Woken
    );
    assert!(receiver.await.is_ok());
    assert!(pending_payments.read().await.is_empty());

    // A waiter whose receiver was dropped is reported as such and removed.
    let (sender, receiver) = oneshot::channel();
    drop(receiver);
    pending_payments.write().await.insert(payment_id, sender);
    assert_eq!(
        GatewayLdkClient::wake_pending_payment(&pending_payments, payment_id).await,
        PendingPaymentWakeup::ReceiverDropped
    );
    assert!(pending_payments.read().await.is_empty());
}

#[test]
fn inbound_registration_refuses_hashes_we_pay_outbound() {
    // A held `pay()` lock means a payment is in flight, whatever the store
    // says about the hash.
    for existing_direction in [
        None,
        Some(PaymentDirection::Inbound),
        Some(PaymentDirection::Outbound),
    ] {
        assert_eq!(
            check_inbound_registration(false, existing_direction),
            Err(InboundRegistrationRefusal::OutboundInFlight)
        );
    }

    // Any outbound record, pending or terminal, is refused so a restarted
    // `pay()` can still read the payment's result from it.
    assert_eq!(
        check_inbound_registration(true, Some(PaymentDirection::Outbound)),
        Err(InboundRegistrationRefusal::OutboundRecorded)
    );

    // A fresh hash is fine; an existing inbound record is refused so a
    // colliding BOLT11/BOLT12 registration cannot overwrite it.
    assert_eq!(check_inbound_registration(true, None), Ok(()));
    assert_eq!(
        check_inbound_registration(true, Some(PaymentDirection::Inbound)),
        Err(InboundRegistrationRefusal::InboundRecorded)
    );
}

#[tokio::test]
async fn registration_try_lock_is_refused_while_pay_holds_the_hash_lock() {
    // `pay()` takes the per-hash lock with `async_lock` and holds it until the
    // payment is terminal; `create_invoice` must see that as busy.
    let pool = LockPool::new();
    let payment_id = PaymentId([2; 32]);
    let other_payment_id = PaymentId([3; 32]);

    let pay_guard = pool.async_lock(payment_id).await;
    assert!(pool.try_lock(payment_id).is_none());
    // Other hashes are unaffected.
    assert!(pool.try_lock(other_payment_id).is_some());

    drop(pay_guard);
    assert!(pool.try_lock(payment_id).is_some());
}

/// A recorded held payment is delivered again only while the node may still
/// claim it: its inbound record has not succeeded and the node has not reached
/// the claim deadline, at which LDK fails the payment back. A failed record
/// may be claimable, as LDK Node keeps that status for a payer's retry.
#[test]
fn only_claimable_held_payments_are_delivered_again() {
    assert!(held_payment_is_claimable(
        Some(PaymentStatus::Pending),
        Some(110),
        109
    ));
    assert!(held_payment_is_claimable(
        Some(PaymentStatus::Pending),
        None,
        109
    ));
    assert!(!held_payment_is_claimable(
        Some(PaymentStatus::Pending),
        Some(110),
        110
    ));
    assert!(!held_payment_is_claimable(
        Some(PaymentStatus::Succeeded),
        Some(110),
        100
    ));
    assert!(held_payment_is_claimable(
        Some(PaymentStatus::Failed),
        Some(110),
        100
    ));
    assert!(!held_payment_is_claimable(
        Some(PaymentStatus::Failed),
        Some(110),
        110
    ));
    assert!(!held_payment_is_claimable(None, Some(110), 100));
}

/// Only a sync that ends after the node started counts: LDK Node loads the
/// time of its latest sync from before a restart.
#[test]
fn only_a_chain_sync_since_the_node_started_counts() {
    assert!(!lightning_synced_since_start(None, None));
    assert!(lightning_synced_since_start(Some(100), None));
    assert!(!lightning_synced_since_start(Some(100), Some(100)));
    assert!(lightning_synced_since_start(Some(101), Some(100)));
}

fn sqlite_store(dir: &tempfile::TempDir) -> SqliteStore {
    SqliteStore::new(
        dir.path().to_path_buf(),
        Some(SQLITE_DB_FILE_NAME.to_string()),
        Some(KV_TABLE_NAME.to_string()),
    )
    .expect("store opens")
}

fn held_payment(byte: u8) -> (PaymentHash, HeldPayment) {
    (
        PaymentHash([byte; 32]),
        HeldPayment {
            claimable_amount_msat: 1_000 * u64::from(byte),
            claim_deadline: Some(120),
            failing_back: false,
        },
    )
}

#[tokio::test]
async fn held_payments_are_recorded_until_removed() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let store = HeldPaymentStore::new(Arc::new(sqlite_store(&dir)));
    let first = held_payment(1);
    let second = (
        PaymentHash([2; 32]),
        HeldPayment {
            claimable_amount_msat: 2_000,
            claim_deadline: None,
            failing_back: false,
        },
    );

    store.record(first.0, &first.1).await.expect("recorded");
    store.record(second.0, &second.1).await.expect("recorded");
    // A repeated event records the same payment once.
    store.record(first.0, &first.1).await.expect("recorded");

    let mut payments = store.list().expect("listed");
    payments.sort_by_key(|(payment_hash, _)| payment_hash.0);
    assert_eq!(payments, vec![first.clone(), second.clone()]);

    let request = first.1.intercept_request(first.0);
    assert_eq!(request.payment_hash.to_byte_array(), [1; 32]);
    assert_eq!(request.incoming_amount_msat, 1_000);
    assert_eq!(request.expiry, 120);

    store.remove(first.0).expect("removed");
    // Removing a payment that is not recorded is not an error.
    store.remove(first.0).expect("removed");

    assert_eq!(store.list().expect("listed"), vec![second.clone()]);

    // Records the node can no longer claim are removed.
    store.record(first.0, &first.1).await.expect("recorded");
    store
        .remove_unclaimable(|payment_hash, _| payment_hash == first.0)
        .await
        .expect("removed");
    assert_eq!(store.list().expect("listed"), vec![first]);
}

/// The highest block height the node has been seen to reach is kept across
/// restarts, so a claim deadline the node reached stays reached even if the
/// chain tip later moves back below it.
#[test]
fn a_reached_claim_deadline_stays_reached_after_the_tip_moves_back() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let flaky = Arc::new(FlakyStore::new(&dir));
    let store = HeldPaymentStore::new(flaky.clone());

    assert_eq!(store.load_observed_height().expect("loaded"), 0);
    assert_eq!(store.observe_height(110), 110);
    assert_eq!(store.observe_height(105), 110);
    assert!(!held_payment_is_claimable(
        Some(PaymentStatus::Pending),
        Some(110),
        store.observe_height(105)
    ));

    // After a restart, the height reached before it still counts.
    let restarted = HeldPaymentStore::new(flaky.clone());
    assert_eq!(restarted.load_observed_height().expect("loaded"), 110);
    assert_eq!(restarted.observe_height(100), 110);

    // A height that cannot be written is written at the next observation.
    flaky.write_failures.store(1, Ordering::SeqCst);
    assert_eq!(store.observe_height(120), 120);
    assert_eq!(
        HeldPaymentStore::new(flaky.clone())
            .load_observed_height()
            .expect("loaded"),
        110
    );
    assert_eq!(store.observe_height(115), 120);
    assert_eq!(
        HeldPaymentStore::new(flaky.clone())
            .load_observed_height()
            .expect("loaded"),
        120
    );

    // The height is not a held payment.
    assert_eq!(store.list().expect("listed"), vec![]);
}

/// A store whose listings, reads and writes fail while `list_failures`,
/// `read_failures` and `write_failures` are not zero, each failure counting
/// its counter down.
struct FlakyStore {
    inner: SqliteStore,
    list_failures: AtomicUsize,
    read_failures: AtomicUsize,
    write_failures: AtomicUsize,
}

impl FlakyStore {
    fn new(dir: &tempfile::TempDir) -> Self {
        Self {
            inner: sqlite_store(dir),
            list_failures: AtomicUsize::new(0),
            read_failures: AtomicUsize::new(0),
            write_failures: AtomicUsize::new(0),
        }
    }

    fn maybe_fail(failures: &AtomicUsize) -> Result<(), lightning::io::Error> {
        match failures.try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1)) {
            Ok(_) => Err(lightning::io::Error::new(
                lightning::io::ErrorKind::Other,
                "store unavailable",
            )),
            Err(_) => Ok(()),
        }
    }
}

impl KVStoreSync for FlakyStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Result<Vec<u8>, lightning::io::Error> {
        Self::maybe_fail(&self.read_failures)?;
        KVStoreSync::read(&self.inner, primary_namespace, secondary_namespace, key)
    }

    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        buf: Vec<u8>,
    ) -> Result<(), lightning::io::Error> {
        Self::maybe_fail(&self.write_failures)?;
        KVStoreSync::write(
            &self.inner,
            primary_namespace,
            secondary_namespace,
            key,
            buf,
        )
    }

    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        lazy: bool,
    ) -> Result<(), lightning::io::Error> {
        KVStoreSync::remove(
            &self.inner,
            primary_namespace,
            secondary_namespace,
            key,
            lazy,
        )
    }

    fn list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> Result<Vec<String>, lightning::io::Error> {
        Self::maybe_fail(&self.list_failures)?;
        KVStoreSync::list(&self.inner, primary_namespace, secondary_namespace)
    }
}

/// A store error while listing or reading the records is retried, so a
/// briefly failing store does not lose held payments; a record that cannot be
/// decoded is skipped without holding up the others.
#[tokio::test]
async fn held_payments_are_listed_again_after_a_store_error() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let flaky = Arc::new(FlakyStore::new(&dir));
    let store = HeldPaymentStore::new(flaky.clone());
    let held = held_payment(1);

    store.record(held.0, &held.1).await.expect("recorded");
    // Records that cannot be decoded: a value that is not a held payment, and
    // a key that is not a payment hash.
    KVStoreSync::write(
        &*flaky,
        HELD_PAYMENTS_PRIMARY_NAMESPACE,
        HELD_PAYMENTS_SECONDARY_NAMESPACE,
        &hex::encode([2; 32]),
        vec![0xff],
    )
    .expect("written");
    KVStoreSync::write(
        &*flaky,
        HELD_PAYMENTS_PRIMARY_NAMESPACE,
        HELD_PAYMENTS_SECONDARY_NAMESPACE,
        "not_a_payment_hash",
        held.1.consensus_encode_to_vec(),
    )
    .expect("written");

    assert_eq!(store.list().expect("listed"), vec![held.clone()]);

    // A failed listing or read fails the listing rather than skipping records.
    flaky.list_failures.store(1, Ordering::SeqCst);
    store.list().expect_err("the listing fails");
    flaky.read_failures.store(1, Ordering::SeqCst);
    store.list().expect_err("the read fails");

    let task_group = TaskGroup::new();

    // The listing fails, then a read, then everything succeeds.
    flaky.list_failures.store(1, Ordering::SeqCst);
    flaky.read_failures.store(1, Ordering::SeqCst);
    assert_eq!(
        store
            .list_retrying(
                custom_backoff(Duration::ZERO, Duration::ZERO, Some(2)),
                &task_group.make_handle(),
            )
            .await,
        Some(vec![held])
    );
    assert_eq!(flaky.list_failures.load(Ordering::SeqCst), 0);
    assert_eq!(flaky.read_failures.load(Ordering::SeqCst), 0);

    // A store that keeps failing is retried until the task shuts down.
    flaky.list_failures.store(usize::MAX, Ordering::SeqCst);
    task_group.shutdown();
    assert_eq!(
        store
            .list_retrying(background_backoff(), &task_group.make_handle())
            .await,
        None
    );
}

/// A payment's record is marked before the payment is failed back, and
/// removed only once it is: until then the payment stays recorded, but is not
/// delivered again.
#[tokio::test]
async fn a_record_is_removed_only_once_its_payment_is_failed_back() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let flaky = Arc::new(FlakyStore::new(&dir));
    let store = HeldPaymentStore::new(flaky.clone());
    let held = held_payment(1);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

    store.record(held.0, &held.1).await.expect("recorded");

    // The payment is not failed back if its record cannot be marked.
    flaky.write_failures.store(1, Ordering::SeqCst);
    store
        .fail_back(held.0, || -> Result<(), ()> { panic!("failed back") })
        .await
        .expect_err("the record is not marked");
    assert_eq!(store.read(held.0).expect("read"), Some(held.1.clone()));

    // If the node cannot fail the payment back, its record stays, marked.
    assert!(matches!(
        store.fail_back(held.0, || Err::<(), _>("busy")).await,
        Ok(Err("busy"))
    ));
    assert_eq!(
        store.read(held.0).expect("read"),
        Some(HeldPayment {
            failing_back: true,
            ..held.1.clone()
        })
    );
    assert_eq!(
        store
            .deliver_if_current(held.0, &sender, |_| true)
            .await
            .expect("store read"),
        RecordedDelivery::NotRecorded
    );
    assert!(receiver.try_recv().is_err());

    // Once the payment is failed back, its record is removed.
    assert!(matches!(
        store.fail_back(held.0, || Ok::<_, ()>(())).await,
        Ok(Ok(()))
    ));
    assert_eq!(store.read(held.0).expect("read"), None);
}

/// Delivering a payment from its record waits for room on the HTLC stream
/// without holding up a fail-back, and once there is room delivers the
/// payment only if it is still recorded and the node may still claim it.
#[tokio::test]
async fn a_record_waiting_for_room_is_delivered_only_while_it_is_current() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let store = HeldPaymentStore::new(Arc::new(sqlite_store(&dir)));
    let held = held_payment(1);
    let (earlier_hash, earlier) = held_payment(2);
    let earlier = earlier.intercept_request(earlier_hash);

    store.record(held.0, &held.1).await.expect("recorded");

    // The stream is full, so the delivery waits for room.
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    sender.send(earlier.clone()).await.expect("sent");

    let mut delivery = pin!(store.deliver_if_current(held.0, &sender, |_| true));
    assert!(
        delivery.as_mut().now_or_never().is_none(),
        "the delivery waits for room on the stream"
    );

    // The gateway fails the payment back meanwhile, without waiting for the
    // delivery.
    store
        .fail_back(held.0, || Ok::<_, ()>(()))
        .now_or_never()
        .expect("the fail-back does not wait for the delivery")
        .expect("store write")
        .expect("failed back");

    // The gateway takes the earlier payment off the stream, making room.
    assert_eq!(
        receiver.try_recv().expect("earlier payment").payment_hash,
        earlier.payment_hash
    );
    assert_eq!(
        delivery.await.expect("store read"),
        RecordedDelivery::NotRecorded
    );
    assert!(receiver.try_recv().is_err());

    // A recorded payment the node can no longer claim is not delivered.
    store.record(held.0, &held.1).await.expect("recorded");
    assert_eq!(
        store
            .deliver_if_current(held.0, &sender, |_| false)
            .await
            .expect("store read"),
        RecordedDelivery::NotClaimable
    );
    assert!(receiver.try_recv().is_err());

    // A payment that is still recorded and claimable is delivered.
    assert_eq!(
        store
            .deliver_if_current(held.0, &sender, |_| true)
            .await
            .expect("store read"),
        RecordedDelivery::Delivered
    );
    assert_eq!(
        receiver.try_recv().expect("delivered payment").payment_hash,
        held.1.intercept_request(held.0).payment_hash
    );

    // Nothing is delivered once the gateway stops taking deliveries.
    drop(receiver);
    assert_eq!(
        store
            .deliver_if_current(held.0, &sender, |_| true)
            .await
            .expect("store read"),
        RecordedDelivery::StreamClosed
    );
}

/// Reading a record and delivering its payment is serialized with failing
/// the payment back: while one holds the lock, the other waits for it.
#[tokio::test]
async fn a_record_is_read_and_delivered_under_the_fail_back_lock() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let store = HeldPaymentStore::new(Arc::new(sqlite_store(&dir)));
    let held = held_payment(1);
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

    store.record(held.0, &held.1).await.expect("recorded");

    let lock = store.delivery_lock.lock().await;

    let mut fail_back = pin!(store.fail_back(held.0, || Ok::<_, ()>(())));
    assert!(
        fail_back.as_mut().now_or_never().is_none(),
        "the fail-back waits for the lock"
    );
    assert_eq!(
        store.read(held.0).expect("store read"),
        Some(held.1.clone()),
        "the record is marked and removed only under the lock"
    );

    let mut delivery = pin!(store.deliver_if_current(held.0, &sender, |_| true));
    assert!(
        delivery.as_mut().now_or_never().is_none(),
        "the delivery waits for the lock"
    );

    // The lock is granted in order: the fail-back removes the record before
    // the delivery reads it.
    drop(lock);
    assert!(matches!(fail_back.await, Ok(Ok(()))));
    assert_eq!(
        delivery.await.expect("store read"),
        RecordedDelivery::NotRecorded
    );
    assert!(receiver.try_recv().is_err());
}
