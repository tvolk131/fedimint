use fedimint_simplicity_client::intent::IntentPlan;

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn watched_market_submission_survives_mnemonic_only_recovery() {
    let _ = fedimint_logging::TracingSetup::default().init();
    tokio::time::timeout(Duration::from_secs(180), async {
        let mut fed = Federation::new().await;
        let (market, origin, _) = intents::genesis(&fed).await;
        fed.set_block_count(market.deadline).await;
        let client = join(builder, &fed, db(), 51, false, false).await;
        funds(&client).await;
        let wallet = client.get_first_module::<SimplicityClientModule>().unwrap();
        assert_eq!(wallet.watch_market(&market).await.unwrap(), origin);
        let context = wallet.intent_context().await;
        let mut output = context.contracts[&origin].output.clone();
        assert!(output.recovery.is_empty());
        output.state[31] = 3;
        let plan = IntentPlan {
            max_fee: None,
            spends: vec![SpendIntent {
                outpoint: origin,
                signature_witness: None,
                witnesses: compiler::witnesses([
                    ("ACTION", Value::u8(2)),
                    ("OUTCOME", Value::u8(3)),
                    (
                        "ORACLE_SIGNATURE",
                        fedimint_simplicity_client::placeholder_signature(),
                    ),
                ]),
            }],
            outputs: vec![output],
            shared_inputs: vec![origin],
        };
        let snapshot = wallet.pruning_snapshot([origin]).await.unwrap();
        let quoted = wallet.plan_fee_request(&plan, &context, &snapshot).unwrap();
        let txid = submit(&wallet, plan.spends, plan.outputs, vec![]).await;
        let history = wallet.history().await;
        let submitted = history
            .iter()
            .find(|entry| entry.transaction.tx_hash() == txid)
            .unwrap();
        assert!(submitted.sent.is_some());
        let output_fee: Amount = submitted
            .transaction
            .outputs
            .iter()
            .filter(|output| output.module_instance_id() == fed.simplicity)
            .map(|output| {
                fedimint_simplicity_common::output_fee(
                    output.as_any().downcast_ref::<ContractOutput>().unwrap(),
                )
            })
            .sum();
        assert_eq!(quoted.output_fee.get_bitcoin(), output_fee);
        drop(wallet);
        client.shutdown().await;

        let client = join(builder, &fed, db(), 51, false, true).await;
        let wallet = client.get_first_module::<SimplicityClientModule>().unwrap();
        let history = wallet.history().await;
        let restored = history
            .iter()
            .find(|entry| entry.transaction.tx_hash() == txid)
            .unwrap();
        assert_eq!(restored.sent, submitted.sent);
        assert!(restored.consumed.is_empty());
        assert!(restored.received.is_empty());
        assert!(wallet.contracts().await.is_empty());
        drop(wallet);
        client.shutdown().await;
        fed.completed = true;
    })
    .await
    .unwrap();
}
