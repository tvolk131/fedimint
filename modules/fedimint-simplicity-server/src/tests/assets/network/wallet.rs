//! Real client-module recovery using only the root secret and guardian history.
use fedimint_client::{Client, ClientBuilder, ClientHandle, RootSecret};
use fedimint_core::TransactionId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_derive_secret::DerivableSecret;
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_simplicity_client::descriptor::ContractDescriptor;
use fedimint_simplicity_client::{
    SimplicityClientInit, SimplicityClientModule, SpendIntent, compiler,
};

use super::*;

fn root(seed: u8) -> RootSecret {
    RootSecret::StandardDoubleDerive(DerivableSecret::new_root(
        &[seed; 32],
        b"network-wallet-test",
    ))
}
fn db() -> Database {
    Database::new(MemDatabase::new(), Default::default())
}
async fn builder(stopped: bool) -> ClientBuilder {
    let mut builder = Client::builder().await;
    builder.with_module(DummyClientInit);
    builder.with_module(SimplicityClientInit::default());
    if stopped {
        builder.stopped();
    }
    builder
}
async fn join(
    make_builder: impl AsyncFn(bool) -> ClientBuilder,
    fed: &Federation,
    database: Database,
    seed: u8,
    stopped: bool,
    recover: bool,
) -> ClientHandle {
    let preview = make_builder(stopped)
        .await
        .preview_with_existing_config(
            ConnectorRegistry::build_from_testing_env().bind().await,
            fed.configs[&PeerId::from(0)]
                .consensus
                .to_client_config(&registry())
                .unwrap(),
            None,
        )
        .await;
    if recover {
        let client = preview
            .recover(database.clone(), root(seed), None)
            .await
            .unwrap();
        client.wait_for_all_recoveries().await.unwrap();
        client.shutdown().await;
        open(make_builder(false).await, database, seed).await
    } else {
        preview.join(database, root(seed)).await.unwrap()
    }
}
async fn open(builder: ClientBuilder, database: Database, seed: u8) -> ClientHandle {
    builder
        .open(
            ConnectorRegistry::build_from_testing_env().bind().await,
            database,
            root(seed),
        )
        .await
        .unwrap()
}
async fn funds(client: &ClientHandle) {
    client
        .get_first_module::<DummyClientModule>()
        .unwrap()
        .mock_receive(Amount::from_sats(10_000), AmountUnit::BITCOIN)
        .await;
}
async fn submit(
    wallet: &SimplicityClientModule,
    inputs: Vec<SpendIntent>,
    outputs: Vec<ContractOutput>,
    creations: Vec<Keypair>,
) -> TransactionId {
    let (operation, txid) = wallet.submit(inputs, outputs, creations).await.unwrap();
    wallet.await_operation(operation).await.unwrap();
    txid
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mnemonic_only_client_recovery_preserves_assets_history_and_spendability() {
    let _ = fedimint_logging::TracingSetup::default().init();
    tokio::time::timeout(Duration::from_secs(180), run())
        .await
        .unwrap();
}

async fn run() {
    let mut fed = Federation::new().await;
    let alice_db = db();
    let alice = join(builder, &fed, alice_db.clone(), 1, true, false).await;
    funds(&alice).await;
    let wallet = alice.get_first_module::<SimplicityClientModule>().unwrap();
    let deposit = wallet
        .receive(Amount::from_sats(100), AssetBundle::default())
        .unwrap();
    // The executor is stopped: this must persist the submission before any
    // guardian can see it, then finish after reopening the same database.
    let (operation, deposit_id) = wallet.submit(vec![], vec![deposit], vec![]).await.unwrap();
    drop(wallet);
    alice.shutdown().await;
    let alice = open(builder(false).await, alice_db.clone(), 1).await;
    let wallet = alice.get_first_module::<SimplicityClientModule>().unwrap();
    wallet.await_operation(operation).await.unwrap();
    assert_eq!(wallet.history().await.len(), 1);
    assert_eq!(wallet.contracts().await[0].0.txid, deposit_id);

    // v0 covenant top-up needs external primary-module funding, and release
    // pays into primary-module change. Both signatures must cover final change.
    let descriptor = ContractDescriptor::top_up([5; 32], 0, 0);
    let top_up = wallet
        .output(
            &descriptor,
            Amount::from_sats(10),
            [0; 32],
            AssetBundle::default(),
        )
        .unwrap();
    let id = submit(&wallet, vec![], vec![top_up], vec![]).await;
    let top_up = wallet
        .output(
            &descriptor,
            Amount::from_sats(20),
            [0; 32],
            AssetBundle::default(),
        )
        .unwrap();
    let top_up_spend = |id, release| SpendIntent {
        outpoint: OutPoint {
            txid: id,
            out_idx: 0,
        },
        witnesses: compiler::witnesses([("RELEASE", Value::from(release))]),
        signature_witness: Some("SIGNATURE".to_owned()),
    };
    let id = submit(&wallet, vec![top_up_spend(id, false)], vec![top_up], vec![]).await;
    let before_rejection = wallet.history().await;
    let invalid_successor = wallet
        .output(
            &descriptor,
            Amount::from_sats(19),
            [0; 32],
            AssetBundle::default(),
        )
        .unwrap();
    let (rejected, _) = wallet
        .submit(
            vec![top_up_spend(id, false)],
            vec![invalid_successor],
            vec![],
        )
        .await
        .unwrap();
    assert!(wallet.await_operation(rejected).await.is_err());
    assert_eq!(wallet.history().await, before_rejection);
    // The rejected operation must release its reservation for a corrected spend.
    submit(&wallet, vec![top_up_spend(id, true)], vec![], vec![]).await;

    let creator = key();
    let (creation, ids) = assets::creation(fed.id, fed.simplicity, &creator, vec![0, 0]).unwrap();
    let authorities = AssetBundle {
        balances: vec![],
        authorities: ids.clone(),
    };
    let authority_output = wallet.receive(Amount::ZERO, authorities.clone()).unwrap();
    let creation_id = submit(
        &wallet,
        vec![],
        vec![
            authority_output,
            assets::action_output(AssetActions {
                creations: vec![creation],
                ..Default::default()
            })
            .unwrap(),
        ],
        vec![creator],
    )
    .await;
    let quantities: Vec<_> = ids
        .iter()
        .map(|asset| AssetAmount {
            asset: *asset,
            quantity: 10,
        })
        .collect();
    let issuance_id = submit(
        &wallet,
        vec![SpendIntent::owner(OutPoint {
            txid: creation_id,
            out_idx: 0,
        })],
        vec![
            wallet.receive(Amount::ZERO, authorities).unwrap(),
            wallet
                .receive(
                    Amount::ZERO,
                    AssetBundle {
                        balances: quantities.clone(),
                        authorities: vec![],
                    },
                )
                .unwrap(),
            assets::action_output(AssetActions {
                issuance: quantities.clone(),
                ..Default::default()
            })
            .unwrap(),
        ],
        vec![],
    )
    .await;

    let bob = join(builder, &fed, db(), 2, false, false).await;
    let bob_wallet = bob.get_first_module::<SimplicityClientModule>().unwrap();
    let bob_output = bob_wallet
        .receive(
            Amount::ZERO,
            AssetBundle {
                balances: quantities.clone(),
                authorities: vec![],
            },
        )
        .unwrap();
    let (unbacked, _) = wallet
        .submit(vec![], vec![bob_output.clone()], vec![])
        .await
        .unwrap();
    assert!(wallet.await_operation(unbacked).await.is_err());
    assert!(
        wallet
            .await_operation(fedimint_core::core::OperationId::new_random())
            .await
            .is_err()
    );
    submit(
        &wallet,
        vec![SpendIntent::owner(OutPoint {
            txid: issuance_id,
            out_idx: 1,
        })],
        vec![bob_output],
        vec![],
    )
    .await;
    bob_wallet.sync().await.unwrap();
    assert_eq!(bob_wallet.contracts().await.len(), 1);

    let expected_contracts = wallet.contracts().await;
    let expected_history = wallet.history().await;
    drop(wallet);
    alice.shutdown().await;
    drop(alice_db); // Discard the entire database, including operations and keys.
    let restored = join(builder, &fed, db(), 1, false, true).await;
    let recovered = restored
        .get_first_module::<SimplicityClientModule>()
        .unwrap();
    assert_eq!(recovered.contracts().await, expected_contracts);
    assert_eq!(recovered.history().await, expected_history);

    // Recover Bob independently, proving the sender never needed his discovery
    // key and the receiver needs no locally saved receive request.
    let bob_expected = bob_wallet.contracts().await;
    drop(bob_wallet);
    bob.shutdown().await;
    let bob = join(builder, &fed, db(), 2, false, true).await;
    let bob_wallet = bob.get_first_module::<SimplicityClientModule>().unwrap();
    assert_eq!(bob_wallet.contracts().await, bob_expected);
    funds(&bob).await;
    let burn = assets::action_output(AssetActions {
        burns: quantities,
        ..Default::default()
    })
    .unwrap();
    submit(
        &bob_wallet,
        vec![SpendIntent::owner(bob_expected[0].0)],
        vec![burn],
        vec![],
    )
    .await;
    let bob_history = bob_wallet.history().await;
    assert_eq!(bob_history.len(), 2);

    // Spend restored native collateral and retire restored issuance authorities.
    let spends = recovered
        .contracts()
        .await
        .into_iter()
        .filter(|(_, contract)| contract.spent_by.is_none())
        .map(|(point, _)| SpendIntent::owner(point))
        .collect();
    submit(&recovered, spends, vec![], vec![]).await;
    let drained_history = recovered.history().await;
    assert!(
        recovered
            .contracts()
            .await
            .iter()
            .all(|(_, contract)| contract.spent_by.is_some())
    );
    drop(recovered);
    restored.shutdown().await;
    let drained = join(builder, &fed, db(), 1, false, true).await;
    let wallet = drained
        .get_first_module::<SimplicityClientModule>()
        .unwrap();
    assert_eq!(wallet.history().await, drained_history);
    assert!(
        wallet
            .contracts()
            .await
            .iter()
            .all(|(_, contract)| contract.spent_by.is_some())
    );
    drop(wallet);
    drained.shutdown().await;
    drop(bob_wallet);
    bob.shutdown().await;
    let bob = join(builder, &fed, db(), 2, false, true).await;
    assert_eq!(
        bob.get_first_module::<SimplicityClientModule>()
            .unwrap()
            .history()
            .await,
        bob_history
    );
    bob.shutdown().await;
    fed.completed = true;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_sender_receipts_restore_history_without_owning_recipient_contracts() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let mut fed = Federation::new().await;
        let alice = join(builder, &fed, db(), 11, false, false).await;
        let bob = join(builder, &fed, db(), 12, false, false).await;
        funds(&alice).await;
        funds(&bob).await;
        let sender = alice.get_first_module::<SimplicityClientModule>().unwrap();
        let recipient = bob.get_first_module::<SimplicityClientModule>().unwrap();
        // No sender-owned Simplicity contracts: funding comes entirely from the
        // primary module. A minimal receipt is installed automatically.
        let received = recipient
            .receive(Amount::from_sats(10), AssetBundle::default())
            .unwrap();
        let id = submit(&sender, vec![], vec![received], vec![]).await;
        recipient.sync().await.unwrap();
        assert!(sender.contracts().await.is_empty());
        let history = sender.history().await;
        assert_eq!(history.len(), 1);
        assert!(history[0].sent.is_some());
        assert!(history[0].received.is_empty());
        assert_eq!(history[0].transaction.tx_hash(), id);
        assert_eq!(
            history[0]
                .transaction
                .outputs
                .iter()
                .filter(|output| output.module_instance_id() == fed.simplicity)
                .count(),
            2
        );
        let bob_contracts = recipient.contracts().await;
        assert_eq!(bob_contracts.len(), 1);
        assert_eq!(
            bob_contracts[0].0,
            OutPoint {
                txid: id,
                out_idx: 0
            }
        );
        for peer in fed.configs.keys() {
            assert!(
                fed.contract_on(
                    *peer,
                    OutPoint {
                        txid: id,
                        out_idx: 1
                    }
                )
                .await
                .is_none(),
                "receipts must not create a UTXO"
            );
        }
        // An accepted transaction funded by Bob can copy Alice's public
        // ciphertext, but it must not become outgoing activity in her wallet.
        let copied = history[0].transaction.outputs[1]
            .as_any()
            .downcast_ref::<ContractOutput>()
            .unwrap()
            .clone();
        let unrelated = recipient
            .receive(Amount::from_sats(1), AssetBundle::default())
            .unwrap();
        submit(&recipient, vec![], vec![unrelated, copied], vec![]).await;
        sender.sync().await.unwrap();
        assert_eq!(sender.history().await, history);
        let bob_contracts = recipient.contracts().await;
        assert_eq!(bob_contracts.len(), 2);
        // Explicit application metadata can reuse an action output and is
        // retained even when the transaction also has an owned contract.
        let own = sender
            .receive(Amount::from_sats(1), AssetBundle::default())
            .unwrap();
        let context = fedimint_simplicity_client::receipt::ReceiptContext {
            application: "receipt-test".to_owned(),
            version: 1,
            data: b"private note".to_vec(),
        };
        let (op, _) = sender
            .submit_with_receipt(
                vec![],
                vec![own, assets::action_output(AssetActions::default()).unwrap()],
                vec![],
                Some(context.clone()),
            )
            .await
            .unwrap();
        sender.await_operation(op).await.unwrap();
        let expected = sender.history().await;
        assert_eq!(expected.len(), 2);
        assert_eq!(expected[1].sent.as_ref().unwrap().context, Some(context));
        assert_eq!(expected[1].received.len(), 1);
        let alice_contracts = sender.contracts().await;
        drop(sender);
        alice.shutdown().await;
        let alice = join(builder, &fed, db(), 11, false, true).await;
        let restored = alice.get_first_module::<SimplicityClientModule>().unwrap();
        assert_eq!(restored.history().await, expected);
        assert_eq!(restored.contracts().await, alice_contracts);
        drop(recipient);
        bob.shutdown().await;
        let bob = join(builder, &fed, db(), 12, false, true).await;
        let restored_bob = bob.get_first_module::<SimplicityClientModule>().unwrap();
        assert_eq!(restored_bob.contracts().await, bob_contracts);
        funds(&bob).await;
        submit(
            &restored_bob,
            bob_contracts
                .iter()
                .map(|(point, _)| SpendIntent::owner(*point))
                .collect(),
            vec![],
            vec![],
        )
        .await;
        let bob_history = restored_bob.history().await;
        assert_eq!(bob_history.len(), 3);
        drop(restored_bob);
        bob.shutdown().await;
        let bob = join(builder, &fed, db(), 12, false, true).await;
        assert_eq!(
            bob.get_first_module::<SimplicityClientModule>()
                .unwrap()
                .history()
                .await,
            bob_history
        );
        drop(restored);
        alice.shutdown().await;
        bob.shutdown().await;
        fed.completed = true;
    })
    .await
    .unwrap();
}

mod intents;
