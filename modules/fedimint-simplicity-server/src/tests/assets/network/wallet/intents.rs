//! Persist competing attempts before starting their core executors. This makes
//! the race deterministic while using the real guardian consensus and client.
use fedimint_client::transaction::{TransactionBuilder, TxSubmissionStates};
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_mintv2_client::{MintClientInit, SpendableNote};
use fedimint_simplicity_client::intent::{
    Intent, IntentPolicy, IntentRecord, IntentStatus, MintPairs, RetryMode,
};
use futures::StreamExt;

use super::*;

// Exercise intents with real ecash and nonzero mint fees. The dummy module is
// used only to bootstrap issuance; all purchase funding comes from Mint v2.
async fn builder(stopped: bool) -> ClientBuilder {
    let mut builder = super::builder(stopped).await;
    builder.with_module(MintClientInit);
    builder
}
async fn funds(client: &ClientHandle) {
    let input = client
        .get_first_module::<DummyClientModule>()
        .unwrap()
        .create_input(Amount::from_sats(10_000));
    let operation = OperationId::new_random();
    let change = client
        .finalize_and_submit_transaction(
            operation,
            "test ecash issuance",
            |_| (),
            TransactionBuilder::new().with_inputs(input),
        )
        .await
        .unwrap();
    client
        .await_primary_bitcoin_module_outputs(operation, change.into_iter().collect())
        .await
        .unwrap();
}
#[derive(Debug, Encodable, Decodable)]
struct OriginalNotes;
fedimint_core::impl_db_record!(key = OriginalNotes, value = Vec<SpendableNote>, db_prefix = 0xb0);

async fn assert_restored(client: &ClientHandle) {
    let original = client
        .db()
        .begin_transaction_nc()
        .await
        .get_value(&OriginalNotes)
        .await
        .unwrap();
    assert_eq!(
        notes(client).await,
        original,
        "conflict must return the identical notes without a paid reissue"
    );
}
async fn notes(client: &ClientHandle) -> Vec<SpendableNote> {
    let mint = client
        .get_first_instance(&fedimint_mintv2_common::KIND)
        .unwrap();
    client
        .db()
        .with_prefix_module_id(mint)
        .0
        .begin_transaction_nc()
        .await
        .find_by_prefix(&fedimint_mintv2_client::client_db::SpendableNotePrefix)
        .await
        .map(|(key, ())| key.0)
        .collect()
        .await
}

async fn genesis(fed: &Federation) -> (market::BinaryMarket, OutPoint, Keypair) {
    let creator = key();
    let oracle = key();
    let (creation, ids) = assets::creation(fed.id, fed.simplicity, &creator, vec![0, 0]).unwrap();
    let market = market::BinaryMarket {
        federation: fed.id,
        module: fed.simplicity,
        yes: ids[0],
        no: ids[1],
        event: [31; 32],
        rules: [32; 32],
        oracle: oracle.x_only_public_key().0,
        resolution_start: 5,
        deadline: 10,
    };
    let vault = market
        .program()
        .unwrap()
        .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[], &ids))
        .unwrap();
    let (mut tx, sponsor) = fed.sponsored(
        vec![],
        vec![
            fed.output(vault),
            fed.output(
                assets::action_output(AssetActions {
                    creations: vec![creation],
                    ..Default::default()
                })
                .unwrap(),
            ),
        ],
    );
    assets::sign_creation(&mut tx, fed.id, fed.simplicity, &creator).unwrap();
    sign_transaction(&mut tx, &[sponsor]).unwrap();
    fed.submit(&tx).await;
    fed.wait_contract(point(&tx, 0)).await;
    (market, point(&tx, 0), oracle)
}
fn intent(
    wallet: &SimplicityClientModule,
    market: &market::BinaryMarket,
    anchor: OutPoint,
    quantity: u64,
) -> Intent {
    MintPairs {
        market: market.clone(),
        anchor,
        quantity,
        yes_destination: wallet
            .receive(Amount::ZERO, bundle(&[(market.yes, quantity)], &[]))
            .unwrap(),
        no_destination: wallet
            .receive(Amount::ZERO, bundle(&[(market.no, quantity)], &[]))
            .unwrap(),
    }
    .into_intent()
}
fn completed(record: &IntentRecord, attempts: usize) -> TransactionId {
    assert_eq!(record.attempts.len(), attempts, "{record:?}");
    let IntentStatus::Complete(txid) = record.status else {
        panic!("{record:?}")
    };
    txid
}
async fn prepare(
    fed: &Federation,
    seed: u8,
    market: &market::BinaryMarket,
    quantity: u64,
    policy: IntentPolicy,
) -> (Database, fedimint_core::core::OperationId) {
    let database = db();
    let client = join(builder, fed, database.clone(), seed, false, false).await;
    funds(&client).await;
    let owned = notes(&client).await;
    assert!(!owned.is_empty());
    let issued: Amount = owned.iter().map(SpendableNote::amount).sum();
    assert!(
        issued < Amount::from_sats(10_000),
        "fixture must charge real mint fees"
    );
    let mut saved = database.begin_transaction().await;
    saved.insert_entry(&OriginalNotes, &owned).await;
    saved.commit_tx().await;
    client.shutdown().await;
    let client = builder(true)
        .await
        .open(
            ConnectorRegistry::build_from_testing_env()
                .unwrap()
                .bind()
                .await
                .unwrap(),
            database.clone(),
            root(seed),
        )
        .await
        .unwrap();
    let wallet = client.get_first_module::<SimplicityClientModule>().unwrap();
    let current = wallet.watch_market(market).await.unwrap();
    let id = wallet
        .submit_intent(intent(&wallet, market, current, quantity), policy)
        .await
        .unwrap();
    let pending = wallet.intent(id).await.unwrap();
    assert!(
        notes(&client).await.len() < owned.len(),
        "funding must be reserved before submission"
    );
    assert_eq!(pending.status, IntentStatus::Submitted, "{pending:?}");
    assert_eq!(pending.attempts.len(), 1);
    // Repeated polling with no accepted/rejected result must not rebuild.
    fedimint_core::runtime::sleep(Duration::from_millis(600)).await;
    assert_eq!(wallet.intent(id).await.unwrap(), pending);
    drop(wallet);
    client.shutdown().await;
    (database, id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shared_market_intents_survive_races_restarts_limits_and_resolution() {
    let _ = fedimint_logging::TracingSetup::default().init();
    tokio::time::timeout(Duration::from_secs(360), run())
        .await
        .unwrap();
}
async fn run() {
    let mut fed = Federation::new().await;
    let (market, anchor, oracle) = genesis(&fed).await;
    let (alice_db, alice_id) = prepare(&fed, 41, &market, 2, IntentPolicy::default()).await;
    let (bob_db, bob_id) = prepare(&fed, 42, &market, 3, IntentPolicy::default()).await;
    // Simulate losing the acceptance response: submit the persisted transaction
    // while its client executor is stopped. The federation accepts it, but the
    // local submission and funding state machines still know only "pending".
    let offline = builder(true)
        .await
        .open(
            ConnectorRegistry::build_from_testing_env()
                .unwrap()
                .bind()
                .await
                .unwrap(),
            alice_db.clone(),
            root(41),
        )
        .await
        .unwrap();
    let operation = offline
        .get_first_module::<SimplicityClientModule>()
        .unwrap()
        .intent(alice_id)
        .await
        .unwrap()
        .attempts[0]
        .operation;
    let update = offline
        .transaction_updates(operation)
        .await
        .update_stream
        .next()
        .await
        .unwrap();
    let TxSubmissionStates::Created(transaction) = update.state else {
        panic!("expected pending submission")
    };
    fed.submit(&transaction).await;
    assert!(
        notes(&offline).await.len()
            < offline
                .db()
                .begin_transaction_nc()
                .await
                .get_value(&OriginalNotes)
                .await
                .unwrap()
                .len()
    );
    offline.shutdown().await;
    let alice = open(builder(false).await, alice_db, 41).await;
    let a = alice.get_first_module::<SimplicityClientModule>().unwrap();
    completed(&await_record(&a, alice_id).await, 1);

    // Watching another market enriches the local view without an owned receipt.
    // Existing page cursors expire; watching the same market again is idempotent.
    let (other_market, _, _) = genesis(&fed).await;
    a.sync().await.unwrap();
    let contracts_cursor = a.contracts_page(None, 1).await.unwrap().next.unwrap();
    let history_cursor = a.history_page(None, 1).await.unwrap().next.unwrap();
    a.watch_market(&other_market).await.unwrap();
    for error in [
        a.contracts_page(Some(&contracts_cursor), 1)
            .await
            .unwrap_err(),
        a.history_page(Some(&history_cursor), 1).await.unwrap_err(),
    ] {
        assert!(matches!(
            error.downcast_ref(),
            Some(fedimint_simplicity_client::wallet::PageError::StaleCursor)
        ));
    }
    let contracts_cursor = a.contracts_page(None, 1).await.unwrap().next.unwrap();
    let history_cursor = a.history_page(None, 1).await.unwrap().next.unwrap();
    a.watch_market(&other_market).await.unwrap();
    a.contracts_page(Some(&contracts_cursor), 1).await.unwrap();
    a.history_page(Some(&history_cursor), 1).await.unwrap();

    let bob = open(builder(false).await, bob_db.clone(), 42).await;
    let b = bob.get_first_module::<SimplicityClientModule>().unwrap();
    let conflict = await_record(&b, bob_id).await;
    assert_restored(&bob).await;
    assert_eq!(conflict.status, IntentStatus::Conflict, "{conflict:?}");
    assert_eq!(conflict.attempts.len(), 1);
    assert!(
        b.contracts()
            .await
            .iter()
            .any(|(p, c)| *p == anchor && c.spent_by.is_some())
    );
    drop(b);
    bob.shutdown().await;
    let bob = builder(true)
        .await
        .open(
            ConnectorRegistry::build_from_testing_env()
                .unwrap()
                .bind()
                .await
                .unwrap(),
            bob_db.clone(),
            root(42),
        )
        .await
        .unwrap();
    let b = bob.get_first_module::<SimplicityClientModule>().unwrap();
    assert_eq!(b.intent(bob_id).await.unwrap(), conflict);
    b.retry_intent(bob_id).await.unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let record = b.intent(bob_id).await.unwrap();
            if record.status == IntentStatus::Submitted {
                break;
            }
            assert!(record.status.is_running(), "retry stopped: {record:?}");
            fedimint_core::runtime::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    // Lose a second race on a rebuilt attempt. The third attempt must still
    // honor the same immutable request and share the original attempt budget.
    let second_winner = a
        .submit_intent(intent(&a, &market, anchor, 1), IntentPolicy::default())
        .await
        .unwrap();
    completed(&await_record(&a, second_winner).await, 1);
    drop(b);
    bob.shutdown().await;
    let bob = open(builder(false).await, bob_db, 42).await;
    let b = bob.get_first_module::<SimplicityClientModule>().unwrap();
    let second_conflict = await_record(&b, bob_id).await;
    assert_restored(&bob).await;
    assert_eq!(second_conflict.status, IntentStatus::Conflict);
    assert_eq!(second_conflict.attempts.len(), 2);
    b.retry_intent(bob_id).await.unwrap();
    let record = await_record(&b, bob_id).await;
    let txid = completed(&record, 3);
    bob.wait_for_all_active_state_machines().await.unwrap();
    let fees = bob
        .db()
        .begin_transaction_nc()
        .await
        .get_value(&fedimint_client::db::TransactionFeesKey(txid))
        .await
        .unwrap();
    let original_balance: Amount = bob
        .db()
        .begin_transaction_nc()
        .await
        .get_value(&OriginalNotes)
        .await
        .unwrap()
        .iter()
        .map(SpendableNote::amount)
        .sum();
    assert_eq!(
        bob.get_balance_for_btc().await.unwrap(),
        original_balance - Amount::from_msats(3000) - fees.get_bitcoin()
    );
    assert!(fees.get_bitcoin() > Amount::ZERO);
    assert_eq!(record.intent, conflict.intent);
    let vault = fed.wait_contract(OutPoint { txid, out_idx: 0 }).await;
    assert_eq!(vault.output.amount, Amount::from_msats(6000));
    let original =
        MintPairs::consensus_decode_whole(&record.intent.data, &Default::default()).unwrap();
    assert_eq!(
        fed.wait_contract(OutPoint { txid, out_idx: 1 })
            .await
            .output,
        original.yes_destination
    );
    assert_eq!(
        fed.wait_contract(OutPoint { txid, out_idx: 2 })
            .await
            .output,
        original.no_destination
    );

    // Final funded fee check rolls back both reservation and primary funds.
    let balance = alice.get_balance_for_btc().await.unwrap();
    let cap = a
        .submit_intent(
            intent(&a, &market, anchor, 1),
            IntentPolicy {
                max_fee: Amount::ZERO,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let record = await_record(&a, cap).await;
    assert!(
        matches!(record.status, IntentStatus::Attention(ref error) if error.contains("fee budget")),
        "{record:?}"
    );
    assert!(record.attempts.is_empty());
    assert_eq!(alice.get_balance_for_btc().await.unwrap(), balance);
    let deadline = a
        .submit_intent(
            intent(&a, &market, anchor, 1),
            IntentPolicy {
                deadline_session: Some(0),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        await_record(&a, deadline).await.status,
        IntentStatus::Failed(_)
    ));

    // Automatic retries follow the same safety checks and keep recipients
    // fixed.
    let auto = IntentPolicy {
        retry: RetryMode::Automatic,
        ..Default::default()
    };
    let (carol_db, carol_id) = prepare(&fed, 43, &market, 1, auto.clone()).await;
    let (dan_db, dan_id) = prepare(&fed, 44, &market, 1, auto.clone()).await;
    let carol = open(builder(false).await, carol_db, 43).await;
    let c = carol.get_first_module::<SimplicityClientModule>().unwrap();
    completed(&await_record(&c, carol_id).await, 1);
    let dan = open(builder(false).await, dan_db, 44).await;
    let d = dan.get_first_module::<SimplicityClientModule>().unwrap();
    completed(&await_record(&d, dan_id).await, 2);

    // An exhausted budget does not restart after a local database reopen.
    let (eve_db, eve_id) = prepare(
        &fed,
        45,
        &market,
        1,
        IntentPolicy {
            max_attempts: 1,
            ..auto.clone()
        },
    )
    .await;
    let winner = a
        .submit_intent(intent(&a, &market, anchor, 1), IntentPolicy::default())
        .await
        .unwrap();
    completed(&await_record(&a, winner).await, 1);
    let eve = open(builder(false).await, eve_db.clone(), 45).await;
    let e = eve.get_first_module::<SimplicityClientModule>().unwrap();
    let exhausted = await_record(&e, eve_id).await;
    assert_restored(&eve).await;
    assert!(
        matches!(exhausted.status, IntentStatus::Failed(_)),
        "{exhausted:?}"
    );
    assert_eq!(exhausted.attempts.len(), 1);
    assert!(e.retry_intent(eve_id).await.is_err());
    drop(e);
    eve.shutdown().await;
    let eve = open(builder(false).await, eve_db, 45).await;
    assert_eq!(
        eve.get_first_module::<SimplicityClientModule>()
            .unwrap()
            .intent(eve_id)
            .await
            .unwrap(),
        exhausted
    );

    // Cancellation cannot retract an already persisted valid transaction.
    let (frank_db, frank_id) = prepare(&fed, 46, &market, 1, auto.clone()).await;
    let frank = builder(true)
        .await
        .open(
            ConnectorRegistry::build_from_testing_env()
                .unwrap()
                .bind()
                .await
                .unwrap(),
            frank_db.clone(),
            root(46),
        )
        .await
        .unwrap();
    let f = frank.get_first_module::<SimplicityClientModule>().unwrap();
    f.cancel_intent(frank_id).await.unwrap();
    assert_eq!(
        f.intent(frank_id).await.unwrap().status,
        IntentStatus::Submitted
    );
    drop(f);
    frank.shutdown().await;
    let frank = open(builder(false).await, frank_db, 46).await;
    let f = frank.get_first_module::<SimplicityClientModule>().unwrap();
    completed(&await_record(&f, frank_id).await, 1);

    // Resolve after a stale mint was persisted. Rebuilding must not turn it
    // into redemption or issue into a market that has ceased to be unresolved.
    let (grace_db, grace_id) = prepare(&fed, 47, &market, 1, auto).await;
    let current = a.watch_market(&market).await.unwrap();
    let input = SpendIntent {
        outpoint: current,
        signature_witness: None,
        witnesses: witnesses([
            ("ACTION", Value::u8(2)),
            ("OUTCOME", Value::u8(1)),
            (
                "ORACLE_SIGNATURE",
                Value::byte_array(
                    *SECP256K1
                        .sign_schnorr_no_aux_rand(
                            &Message::from_digest(market.attestation_message(1).unwrap()),
                            &oracle,
                        )
                        .as_ref(),
                ),
            ),
        ]),
    };
    let amount = a
        .contracts()
        .await
        .into_iter()
        .find(|(p, _)| *p == current)
        .unwrap()
        .1
        .output
        .amount;
    let resolved = a
        .output(
            &ContractDescriptor::binary_market([6; 32], &market),
            amount,
            market::state(1).unwrap(),
            bundle(&[], &[market.yes, market.no]),
        )
        .unwrap();
    submit(&a, vec![input], vec![resolved], vec![]).await;
    let grace = open(builder(false).await, grace_db, 47).await;
    let g = grace.get_first_module::<SimplicityClientModule>().unwrap();
    let closed = await_record(&g, grace_id).await;
    assert!(
        matches!(closed.status, IntentStatus::Failed(ref error) if error.contains("resolved")),
        "{closed:?}"
    );
    assert_eq!(closed.attempts.len(), 1);

    // Seed recovery restores confirmed positions, not unfinished intentions.
    drop(d);
    dan.shutdown().await;
    let dan = join(builder, &fed, db(), 44, false, true).await;
    let restored = dan.get_first_module::<SimplicityClientModule>().unwrap();
    assert!(restored.intent(dan_id).await.is_none());
    assert!(
        restored
            .contracts()
            .await
            .iter()
            .any(|(_, c)| c.spent_by.is_none()
                && c.output.bundle().is_some_and(|b| b
                    .balances
                    .iter()
                    .any(|v| v.asset == market.yes && v.quantity == 1)))
    );
    drop(restored);
    dan.shutdown().await;
    drop(a);
    alice.shutdown().await;
    drop(b);
    bob.shutdown().await;
    drop(c);
    carol.shutdown().await;
    drop(f);
    frank.shutdown().await;
    drop(g);
    grace.shutdown().await;
    eve.shutdown().await;
    fed.completed = true;
}

async fn await_record(
    wallet: &SimplicityClientModule,
    id: fedimint_core::core::OperationId,
) -> IntentRecord {
    match tokio::time::timeout(Duration::from_secs(20), wallet.await_intent(id)).await {
        Ok(result) => result.unwrap(),
        Err(_) => panic!("intent stalled: {:?}", wallet.intent(id).await),
    }
}
