use bitcoin::hashes::{Hash, sha256};

use super::*;

fn txid(value: u8) -> TransactionId {
    TransactionId::from_raw_hash(sha256::Hash::from_byte_array([value; 32]))
}
fn point(value: u8) -> OutPoint {
    OutPoint {
        txid: txid(value),
        out_idx: 0,
    }
}
fn record() -> IntentRecord {
    IntentRecord {
        intent: Intent {
            template: "test".to_owned(),
            version: 1,
            data: vec![],
        },
        policy: IntentPolicy::default(),
        status: IntentStatus::Submitted,
        attempts: vec![IntentAttempt {
            operation: OperationId::new_random(),
            transaction: txid(2),
            shared_inputs: vec![point(1)],
            outcome: AttemptOutcome::Pending,
        }],
        cancel_requested: false,
    }
}
fn competing() -> BTreeMap<OutPoint, WalletContract> {
    BTreeMap::from([(
        point(1),
        WalletContract {
            output: ContractOutput::action_output(Default::default()),
            descriptor: crate::descriptor::ContractDescriptor::owner([0; 32]),
            creation_session: 0,
            spent_by: Some(txid(3)),
        },
    )])
}
#[test]
fn only_a_confirmed_conflicting_spend_can_enable_rebuilding() {
    let mut r = record();
    assert!(r.can_prepare(0).is_err());
    r.resolve(Err("already spent".to_owned()), &BTreeMap::new());
    assert!(matches!(r.status, IntentStatus::Attention(_)));
    assert!(r.can_prepare(0).is_err());
    // A conflict on an input not designated shared is insufficient.
    r.resolve(
        Err("rejected".to_owned()),
        &BTreeMap::from([(point(4), competing()[&point(1)].clone())]),
    );
    assert!(r.can_prepare(0).is_err());
    r.resolve(Err("rejected".to_owned()), &competing());
    assert_eq!(r.status, IntentStatus::Conflict);
    assert!(r.can_prepare(0).is_ok());
    r.policy.max_attempts = 1;
    assert!(r.can_prepare(0).is_err());
    r.policy.max_attempts = 3;
    r.policy.deadline_session = Some(5);
    assert!(r.can_prepare(4).is_ok());
    assert!(r.can_prepare(5).is_err());
    r.cancel_requested = true;
    assert!(r.can_prepare(0).is_err());
}
#[test]
fn acceptance_wins_over_cancellation_and_rejection_never_retries_after_cancel() {
    let mut r = record();
    r.cancel_requested = true;
    r.resolve(Ok(()), &competing());
    assert_eq!(r.status, IntentStatus::Complete(txid(2)));
    let mut r = record();
    r.cancel_requested = true;
    r.resolve(Err("rejected".to_owned()), &competing());
    assert_eq!(r.status, IntentStatus::Cancelled);
}
#[test]
fn automatic_backoff_and_attempt_limits_survive_encoding() {
    let mut r = record();
    r.policy.retry = RetryMode::Automatic;
    r.resolve(Err("conflict".to_owned()), &competing());
    assert!(matches!(r.status, IntentStatus::Backoff { .. }));
    assert_eq!(
        IntentRecord::consensus_decode_whole(&r.consensus_encode_to_vec(), &Default::default())
            .unwrap(),
        r
    );
    assert_eq!(backoff_ms(1, 0), 500);
    assert!(backoff_ms(1000, u64::MAX) < 16_250);
    r.policy.max_attempts = 1;
    r.resolve(Err("conflict".to_owned()), &competing());
    assert!(matches!(r.status, IntentStatus::Failed(_)));
}

#[tokio::test]
async fn attempt_index_rolls_back_and_preserves_completed_history() {
    use fedimint_core::db::Database;
    use fedimint_core::db::mem_impl::MemDatabase;
    let db = Database::new(MemDatabase::new(), Default::default());
    let id = OperationId::new_random();
    let r = record();
    let mut tx = db.begin_transaction().await;
    save_record(&mut tx.to_ref_nc(), id, &r).await;
    drop(tx);
    let mut tx = db.begin_transaction_nc().await;
    assert!(tx.get_value(&db::IntentKey(id)).await.is_none());
    assert!(tx.get_value(&db::ActiveIntentKey(id)).await.is_none());
    drop(tx);
    let mut tx = db.begin_transaction().await;
    save_record(&mut tx.to_ref_nc(), id, &r).await;
    tx.commit_tx_result().await.unwrap();
    let mut reopened = db.begin_transaction().await;
    let mut restored = reopened.get_value(&db::IntentKey(id)).await.unwrap();
    assert_eq!(restored, r);
    assert_eq!(reopened.get_value(&db::ActiveIntentKey(id)).await, Some(()));
    restored.resolve(Ok(()), &BTreeMap::new());
    save_record(&mut reopened.to_ref_nc(), id, &restored).await;
    reopened.commit_tx_result().await.unwrap();
    let mut tx = db.begin_transaction_nc().await;
    assert!(tx.get_value(&db::ActiveIntentKey(id)).await.is_none());
    assert_eq!(
        tx.get_value(&db::IntentKey(id)).await.unwrap().status,
        IntentStatus::Complete(txid(2))
    );
}
