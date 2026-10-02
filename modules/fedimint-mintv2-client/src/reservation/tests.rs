use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_mintv2_common::Denomination;

use super::*;
use crate::SpendableNote;
use crate::input::InputStateMachine;

fn common() -> InputSMCommon {
    InputSMCommon {
        operation_id: OperationId::new_random(),
        txid: TransactionId::from_raw_hash(bitcoin_hashes::Hash::from_byte_array([7; 32])),
        spendable_notes: vec![SpendableNote {
            denomination: Denomination(15),
            keypair: Keypair::new(SECP256K1, &mut rand::thread_rng()),
            signature: tbs::Signature(bls12_381::G1Affine::generator()),
        }],
    }
}

async fn reserved(db: &Database, common: &InputSMCommon) {
    let mut tx = db.begin_transaction().await;
    tx.insert_new_entry(
        &FundingReservationKey(common.operation_id),
        &FundingReservation::AwaitingOutcome,
    )
    .await;
    tx.commit_tx().await;
}

#[tokio::test]
async fn pending_and_accepted_funding_cannot_be_released() {
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let common = common();
    reserved(&db, &common).await;
    let mut tx = db.begin_transaction().await;
    assert!(
        !request_release(&mut tx.to_ref_nc(), common.operation_id, common.txid)
            .await
            .unwrap()
    );
    assert_eq!(
        record_outcome(&mut tx.to_ref_nc(), &common, true).await,
        InputSMState::Success
    );
    assert!(
        request_release(&mut tx.to_ref_nc(), common.operation_id, common.txid)
            .await
            .is_err()
    );
    assert!(
        tx.get_value(&SpendableNoteKey(common.spendable_notes[0].clone()))
            .await
            .is_none()
    );
    tx.commit_tx().await;
}

#[tokio::test]
async fn rejection_holds_notes_and_release_is_atomic_and_idempotent() {
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let common = common();
    let key = FundingReservationKey(common.operation_id);
    let note = SpendableNoteKey(common.spendable_notes[0].clone());
    let (balance, mut notifications) = tokio::sync::watch::channel(());
    reserved(&db, &common).await;
    let mut tx = db.begin_transaction().await;
    assert_eq!(
        record_outcome(&mut tx.to_ref_nc(), &common, false).await,
        InputSMState::AwaitingRelease
    );
    assert!(tx.get_value(&note).await.is_none());
    tx.commit_tx().await;

    // No request means rejection alone never restores or reissues the notes.
    let mut tx = db.begin_transaction().await;
    let wrong = TransactionId::from_raw_hash(bitcoin_hashes::Hash::from_byte_array([8; 32]));
    assert!(
        request_release(&mut tx.to_ref_nc(), common.operation_id, wrong)
            .await
            .is_err()
    );
    assert!(
        !request_release(&mut tx.to_ref_nc(), common.operation_id, common.txid)
            .await
            .unwrap()
    );
    tx.commit_tx().await;

    // A crash before committing restoration leaves both notes and status alone.
    let mut tx = db.begin_transaction().await;
    tx.ignore_uncommitted();
    restore_notes(&mut tx.to_ref_nc(), &common, balance.clone()).await;
    assert!(tx.get_value(&note).await.is_some());
    drop(tx);
    assert!(!notifications.has_changed().unwrap());
    let mut tx = db.begin_transaction().await;
    assert!(tx.get_value(&note).await.is_none());
    assert_eq!(
        tx.get_value(&key).await,
        Some(FundingReservation::ReleaseRequested(common.txid))
    );
    restore_notes(&mut tx.to_ref_nc(), &common, balance.clone()).await;
    tx.commit_tx().await;
    notifications.changed().await.unwrap();

    // A different operation spends the released note. Neither repeated release
    // requests nor repeated restoration may resurrect it afterwards.
    let mut tx = db.begin_transaction().await;
    assert!(tx.remove_entry(&note).await.is_some());
    tx.commit_tx().await;
    let mut tx = db.begin_transaction().await;
    assert!(
        request_release(&mut tx.to_ref_nc(), common.operation_id, common.txid)
            .await
            .unwrap()
    );
    restore_notes(&mut tx.to_ref_nc(), &common, balance).await;
    assert!(tx.get_value(&note).await.is_none());
    assert!(
        request_release(&mut tx.to_ref_nc(), common.operation_id, wrong)
            .await
            .is_err()
    );
    tx.commit_tx().await;
}

#[tokio::test]
async fn concurrent_restorations_cannot_commit_twice() {
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let common = common();
    reserved(&db, &common).await;
    let mut tx = db.begin_transaction().await;
    record_outcome(&mut tx.to_ref_nc(), &common, false).await;
    request_release(&mut tx.to_ref_nc(), common.operation_id, common.txid)
        .await
        .unwrap();
    tx.commit_tx().await;

    let (balance, _) = tokio::sync::watch::channel(());
    let mut first = db.begin_transaction().await;
    let mut second = db.begin_transaction().await;
    restore_notes(&mut first.to_ref_nc(), &common, balance.clone()).await;
    restore_notes(&mut second.to_ref_nc(), &common, balance.clone()).await;
    first.commit_tx_result().await.unwrap();
    assert!(second.commit_tx_result().await.is_err());

    let mut retry = db.begin_transaction().await;
    // A concurrent wallet operation may take the note immediately after the
    // winning release. Retrying the losing release must not resurrect it.
    let note = SpendableNoteKey(common.spendable_notes[0].clone());
    assert!(retry.remove_entry(&note).await.is_some());
    retry.commit_tx().await;
    let mut retry = db.begin_transaction().await;
    restore_notes(&mut retry.to_ref_nc(), &common, balance).await;
    assert!(retry.get_value(&note).await.is_none());
    retry.commit_tx().await;
}

#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable)]
enum LegacyState {
    Pending,
    Success,
    Refunding(fedimint_client_module::module::OutPointRange),
}
#[derive(Debug, Encodable, Decodable)]
struct LegacyInput {
    common: InputSMCommon,
    state: LegacyState,
}

#[test]
fn persisted_legacy_input_states_keep_their_encoding() {
    use fedimint_client_module::module::{IdxRange, OutPointRange};
    for state in [
        LegacyState::Pending,
        LegacyState::Success,
        LegacyState::Refunding(OutPointRange::new(common().txid, IdxRange::from(0..1))),
    ] {
        let old = LegacyInput {
            common: common(),
            state,
        };
        let bytes = old.consensus_encode_to_vec();
        let decoded =
            InputStateMachine::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .unwrap();
        assert_eq!(decoded.consensus_encode_to_vec(), bytes);
        let roundtrip = LegacyInput::consensus_decode_whole(
            &decoded.consensus_encode_to_vec(),
            &ModuleDecoderRegistry::default(),
        )
        .unwrap();
        assert_eq!(roundtrip.state, old.state);
    }
}
