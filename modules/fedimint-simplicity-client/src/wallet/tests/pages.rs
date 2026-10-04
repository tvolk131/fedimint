use fedimint_core::db::{DatabaseKeyPrefix, IDatabaseTransactionOpsCore};

use super::*;

// Synthetic local records exercise key encoding boundaries without having to
// generate billions of actual sessions. Normal replay is exercised below.
async fn seeded() -> WalletStore {
    let store = wallet(database()).await;
    let descriptor = ContractDescriptor::owner([3; 32]);
    let output = output(&store, &descriptor);
    let mut transaction = tx(0, &[], vec![output.clone()]);
    let mut tx = store.db.begin_transaction().await;
    for index in (0..260).chain([65535, 65536, u32::MAX as u64, u32::MAX as u64 + 1, u64::MAX]) {
        transaction.nonce = index.to_be_bytes();
        let point = OutPoint {
            txid: TransactionId::from_raw_hash(sha256::Hash::all_zeros()),
            out_idx: index,
        };
        tx.insert_new_entry(
            &db::ContractKey(point),
            &WalletContract {
                output: output.clone(),
                descriptor: descriptor.clone(),
                creation_session: index,
                spent_by: index.is_multiple_of(2).then_some(transaction.tx_hash()),
            },
        )
        .await;
        for item in [0, 252, 253, 65535, 65536, u64::MAX] {
            transaction.nonce = item.to_be_bytes();
            tx.insert_new_entry(
                &db::HistoryKey(index, item),
                &HistoryEntry {
                    transaction: transaction.clone(),
                    session: index,
                    consumed: vec![],
                    received: vec![point],
                    sent: None,
                },
            )
            .await;
        }
    }
    tx.commit_tx().await;
    store
}

#[tokio::test]
async fn pages_preserve_all_records_and_numeric_history_order() {
    let store = seeded().await;
    for limit in [1, 3, MAX_WALLET_PAGE_SIZE] {
        let mut cursor = None;
        let mut contracts = vec![];
        loop {
            let page = store.contracts_page(cursor.as_ref(), limit).await.unwrap();
            assert!(!page.entries.is_empty() && page.entries.len() <= limit);
            contracts.extend(page.entries);
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(contracts, store.contracts().await);
        assert_eq!(contracts.last().unwrap().0.out_idx, u64::MAX);
        let mut cursor = None;
        let mut history = vec![];
        loop {
            let page = store.history_page(cursor.as_ref(), limit).await.unwrap();
            assert!(!page.entries.is_empty() && page.entries.len() <= limit);
            history.extend(page.entries);
            cursor = page.next;
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(history, store.history().await);
        assert_eq!(history.last().unwrap().session, u64::MAX);
    }
}

#[tokio::test]
async fn page_limits_empty_views_and_cursor_scope() {
    let empty = wallet(database()).await;
    assert!(empty.contracts_page(None, 1).await.unwrap().next.is_none());
    assert!(
        empty
            .history_page(None, 1)
            .await
            .unwrap()
            .entries
            .is_empty()
    );
    for limit in [0, MAX_WALLET_PAGE_SIZE + 1, usize::MAX] {
        assert!(matches!(
            empty
                .contracts_page(None, limit)
                .await
                .unwrap_err()
                .downcast_ref(),
            Some(PageError::InvalidLimit)
        ));
        assert!(matches!(
            empty
                .history_page(None, limit)
                .await
                .unwrap_err()
                .downcast_ref(),
            Some(PageError::InvalidLimit)
        ));
    }
    let store = seeded().await;
    let cursor = store.contracts_page(None, 1).await.unwrap().next.unwrap();
    let restored =
        serde_json::from_str::<WalletCursor>(&serde_json::to_string(&cursor).unwrap()).unwrap();
    let reopened = wallet(store.db.clone()).await;
    assert_eq!(
        reopened
            .contracts_page(Some(&restored), 1)
            .await
            .unwrap()
            .entries,
        store
            .contracts_page(Some(&cursor), 1)
            .await
            .unwrap()
            .entries
    );
    assert!(matches!(
        store
            .history_page(Some(&cursor), 1)
            .await
            .unwrap_err()
            .downcast_ref(),
        Some(PageError::WrongCollection)
    ));
    assert!(matches!(
        empty
            .contracts_page(Some(&cursor), 1)
            .await
            .unwrap_err()
            .downcast_ref(),
        Some(PageError::StaleCursor)
    ));
}

#[tokio::test]
async fn opening_an_older_database_initializes_listing_identity_without_replaying_history() {
    let store = seeded().await;
    let expected = store.history().await;
    let mut tx = store.db.begin_transaction().await;
    tx.remove_entry(&db::ViewRevisionKey).await;
    tx.commit_tx().await;
    let reopened = wallet(store.db.clone()).await;
    assert_eq!(reopened.history().await, expected);
    assert!(reopened.history_page(None, 1).await.unwrap().next.is_some());
}

#[tokio::test]
async fn replay_expires_cursors_only_when_visible_records_change() {
    let store = wallet(database()).await;
    let descriptor = ContractDescriptor::owner([4; 32]);
    let a = tx(0, &[], vec![output(&store, &descriptor)]);
    let b = tx(1, &[], vec![output(&store, &descriptor)]);
    let accepted = session(&[a.clone(), b]);
    store.apply_session(0, &accepted, false).await.unwrap();
    let contracts = store.contracts_page(None, 1).await.unwrap().next.unwrap();
    let history = store.history_page(None, 1).await.unwrap().next.unwrap();
    // Replaying an open prefix, closing it, and empty sessions change progress
    // but cannot invalidate a cursor into the same visible records.
    store.apply_session(0, &accepted, false).await.unwrap();
    store.apply_session(0, &accepted, true).await.unwrap();
    store.apply_session(1, &session(&[]), true).await.unwrap();
    assert!(
        store
            .contracts_page(Some(&contracts), 1)
            .await
            .unwrap()
            .next
            .is_none()
    );
    assert!(
        store
            .history_page(Some(&history), 1)
            .await
            .unwrap()
            .next
            .is_none()
    );
    let spend = tx(2, &[point(&a)], vec![]);
    store
        .apply_session(2, &session(&[spend]), true)
        .await
        .unwrap();
    assert!(matches!(
        store
            .contracts_page(Some(&contracts), 1)
            .await
            .unwrap_err()
            .downcast_ref(),
        Some(PageError::StaleCursor)
    ));
    assert!(matches!(
        store
            .history_page(Some(&history), 1)
            .await
            .unwrap_err()
            .downcast_ref(),
        Some(PageError::StaleCursor)
    ));
    assert_eq!(
        store.contracts_page(None, 256).await.unwrap().entries,
        store.contracts().await
    );
    assert_eq!(
        store.history_page(None, 256).await.unwrap().entries,
        store.history().await
    );
}

#[tokio::test]
async fn continuation_seeks_past_previous_records_and_decodes_only_requested_page() {
    let store = seeded().await;
    let first = store.contracts_page(None, 1).await.unwrap();
    let second = store.contracts_page(first.next.as_ref(), 1).await.unwrap();
    let mut tx = store.db.begin_transaction().await;
    // Deliberate corruption without changing the view token proves the reader
    // neither rescans the prefix nor decodes the lookahead record.
    for point in [
        first.entries[0].0,
        OutPoint {
            out_idx: 2,
            ..first.entries[0].0
        },
    ] {
        tx.raw_insert_bytes(&db::ContractKey(point).to_bytes(), &[255])
            .await
            .unwrap();
    }
    tx.commit_tx().await;
    assert_eq!(
        store
            .contracts_page(first.next.as_ref(), 1)
            .await
            .unwrap()
            .entries,
        second.entries
    );
    assert!(store.contracts_page(None, 1).await.is_err());
    assert!(store.contracts_page(second.next.as_ref(), 1).await.is_err());
}
