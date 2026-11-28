use fedimint_bolt12_common::protocol::RegistrationId;
use fedimint_core::bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped as _};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::secp256k1::{Keypair, SECP256K1};

use crate::db::{
    Bolt12NextOfferIndexKey, Bolt12OfferKey, Bolt12OfferRecord, Bolt12ReceiveStreamIndexKey,
    Bolt12ReceiveStreamRewindGenKey,
};
use crate::offers::{advance_bolt12_stream_cursor, record_rescanned_bolt12_offer};

#[tokio::test]
async fn cursor_zero_aba_does_not_skip_rescanned_offer() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let claim_pk = Keypair::new(SECP256K1, &mut rand::thread_rng()).public_key();

    let stream_index = 0u64;
    let seen_next = 0u64;
    let seen_rewind_gen = 0u64;

    let inserted = record_rescanned_bolt12_offer(
        &db,
        25,
        Some((
            RegistrationId(sha256::Hash::from_byte_array([7; 32])),
            claim_pk,
        )),
        false,
    )
    .await
    .expect("rescan db commit succeeds");
    assert!(inserted);

    let mut dbtx = db.begin_transaction().await;
    advance_bolt12_stream_cursor(
        &mut dbtx.to_ref_nc(),
        stream_index,
        seen_next,
        seen_rewind_gen,
        5,
    )
    .await;
    dbtx.commit_tx().await;

    let mut ro = db.begin_transaction_nc().await;
    assert_eq!(
        ro.get_value(&Bolt12ReceiveStreamIndexKey)
            .await
            .unwrap_or(0),
        0,
        "cursor-0 ABA race must not advance past newly rescanned offer"
    );
    assert_eq!(
        ro.get_value(&Bolt12ReceiveStreamRewindGenKey).await,
        Some(1)
    );
    assert_eq!(ro.get_value(&Bolt12NextOfferIndexKey).await, Some(26));
    assert!(ro.get_value(&Bolt12OfferKey(25)).await.is_some());
    drop(ro);

    let mut dbtx = db.begin_transaction().await;
    advance_bolt12_stream_cursor(&mut dbtx.to_ref_nc(), 0, 26, 1, 5).await;
    dbtx.commit_tx().await;

    let cursor = db
        .begin_transaction_nc()
        .await
        .get_value(&Bolt12ReceiveStreamIndexKey)
        .await
        .unwrap_or(0);
    assert_eq!(cursor, 5);
}

#[tokio::test]
async fn overlapping_tx_cursor_zero_aba_conflicts_on_mem_db() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let claim_pk = Keypair::new(SECP256K1, &mut rand::thread_rng()).public_key();

    // Seed an existing cursor = Some(0), gen = Some(1), next = Some(26).
    record_rescanned_bolt12_offer(
        &db,
        25,
        Some((
            RegistrationId(sha256::Hash::from_byte_array([7; 32])),
            claim_pk,
        )),
        false,
    )
    .await
    .expect("initial rescan");

    // `receive_bolt12` opens its committable transaction BEFORE the concurrent
    // rescan commits, staging cursor 0 -> 5 from snapshot (next=26, gen=1).
    let mut recv_tx = db.begin_transaction().await;
    advance_bolt12_stream_cursor(&mut recv_tx.to_ref_nc(), 0, 26, 1, 5).await;

    // While `recv_tx` is still open, a concurrent rescan discovers offer 50
    // and writes cursor = Some(0) (same value!), gen = 2, next = 51.
    record_rescanned_bolt12_offer(
        &db,
        50,
        Some((
            RegistrationId(sha256::Hash::from_byte_array([8; 32])),
            claim_pk,
        )),
        false,
    )
    .await
    .expect("overlapping rescan");

    // Because `advance_bolt12_stream_cursor` writes `RewindGenKey` and
    // `NextOfferIndexKey` into its write set, value-comparing backends
    // (`MemDatabase`, `redb`) MUST reject `recv_tx` with a write conflict.
    assert!(
        recv_tx.commit_tx_result().await.is_err(),
        "overlapping cursor-0 advance must conflict when rewind generation changed"
    );

    let mut ro = db.begin_transaction_nc().await;
    assert_eq!(ro.get_value(&Bolt12ReceiveStreamIndexKey).await, Some(0));
    assert_eq!(
        ro.get_value(&Bolt12ReceiveStreamRewindGenKey).await,
        Some(2)
    );
    assert_eq!(ro.get_value(&Bolt12NextOfferIndexKey).await, Some(51));
}

#[tokio::test]
async fn rescan_and_recovery_never_roll_back_or_clobber_offers() {
    let db = Database::new(MemDatabase::new(), ModuleRegistry::default());
    let claim_pk = Keypair::new(SECP256K1, &mut rand::thread_rng()).public_key();
    let reg5 = RegistrationId(sha256::Hash::from_byte_array([5; 32]));

    // Simulate a concurrently created offer at index 5 (with `offer: Some`) and
    // allocator already bumped to 30, with cursor at 12.
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_entry(
        &Bolt12OfferKey(5),
        &Bolt12OfferRecord {
            registration: reg5,
            claim_pk,
            offer: Some("lno1preserved".to_string()),
        },
    )
    .await;
    dbtx.insert_entry(&Bolt12NextOfferIndexKey, &30u64).await;
    dbtx.insert_entry(&Bolt12ReceiveStreamIndexKey, &12u64)
        .await;
    dbtx.commit_tx().await;

    // Background recovery encountering index 5 must preserve `offer: Some(...)`
    // and never lower `Bolt12NextOfferIndexKey`.
    assert!(
        !record_rescanned_bolt12_offer(&db, 5, Some((reg5, claim_pk)), false)
            .await
            .expect("recovery on existing offer")
    );
    let mut ro = db.begin_transaction_nc().await;
    assert_eq!(
        ro.get_value(&Bolt12OfferKey(5))
            .await
            .and_then(|r| r.offer)
            .as_deref(),
        Some("lno1preserved"),
        "recovery/rescan must preserve existing offer string"
    );
    assert_eq!(ro.get_value(&Bolt12NextOfferIndexKey).await, Some(30));
    assert_eq!(ro.get_value(&Bolt12ReceiveStreamIndexKey).await, Some(12));
    drop(ro);

    // Explicit rescan encountering a pruned offer at index 3 (< next=30) must
    // rewind the cursor while preserving `Bolt12NextOfferIndexKey = 30`.
    assert!(
        !record_rescanned_bolt12_offer(&db, 3, None, true)
            .await
            .expect("rescan on pruned offer")
    );

    let mut ro = db.begin_transaction_nc().await;
    assert_eq!(
        ro.get_value(&Bolt12NextOfferIndexKey).await,
        Some(30),
        "rescan must preserve higher concurrently allocated offer index"
    );
    assert_eq!(
        ro.get_value(&Bolt12ReceiveStreamIndexKey).await,
        Some(0),
        "explicit rescan on pruned offer must rewind cursor even when next > index"
    );
    assert_eq!(
        ro.get_value(&Bolt12ReceiveStreamRewindGenKey).await,
        Some(1)
    );
}
