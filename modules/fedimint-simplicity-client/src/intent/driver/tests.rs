use fedimint_core::db::mem_impl::MemDatabase;
use futures::poll;

use super::*;
use crate::intent::advance_revision;

#[tokio::test]
async fn discovery_cannot_miss_a_commit_between_scanning_and_waiting() {
    let database = Database::new(MemDatabase::new(), Default::default());
    let (revision, ids) = active_intents(&database).await;
    assert_eq!(revision, 0); // Existing databases have no revision key.
    assert!(ids.is_empty());
    let id = OperationId::new_random();
    let mut tx = database.begin_transaction().await;
    tx.insert_new_entry(&db::ActiveIntentKey(id), &()).await;
    advance_revision(&mut tx.to_ref_nc()).await;
    tx.commit_tx().await;

    // Subscription begins after the notification has already been emitted.
    changed_intents(&database, revision).await;
    assert_eq!(active_intents(&database).await, (1, vec![id]));
}

#[tokio::test]
async fn discovery_wakes_on_committed_changes_but_not_rollback_or_unrelated_writes() {
    let database = Database::new(MemDatabase::new(), Default::default());
    let wait = changed_intents(&database, 0);
    tokio::pin!(wait);
    assert!(poll!(&mut wait).is_pending());

    let mut tx = database.begin_transaction().await;
    tx.ignore_uncommitted();
    advance_revision(&mut tx.to_ref_nc()).await;
    drop(tx);
    assert!(poll!(&mut wait).is_pending());

    let mut tx = database.begin_transaction().await;
    tx.insert_entry(&db::ViewRevisionKey, &[1; 32]).await;
    tx.commit_tx().await;
    assert!(poll!(&mut wait).is_pending());

    let mut tx = database.begin_transaction().await;
    advance_revision(&mut tx.to_ref_nc()).await;
    tx.commit_tx().await;
    assert!(poll!(&mut wait).is_ready());
}
