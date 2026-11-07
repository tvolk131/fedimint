//! A wallet that only watches a public contract can still spend it, and the
//! confirmed submission is restored from the root secret and guardian history
//! alone, without any holding of the watched contract.
use fedimint_simplicity_client::TransactionPlan;
use fedimint_simplicity_client::descriptor::ContractTemplates as _;

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn watched_shared_contract_submission_survives_mnemonic_only_recovery() {
    let _ = fedimint_logging::TracingSetup::default().init();
    tokio::time::timeout(Duration::from_secs(180), async {
        let mut fed = Federation::new().await;
        // A public contract no wallet owns, spendable by anyone once its height
        // opens. Its creation carries no encrypted descriptor.
        let opens = INITIAL_BLOCK_COUNT + 1;
        let descriptor = pruning::shared_descriptor(opens);
        let program = pruning::Templates
            .compile(&descriptor, key().x_only_public_key().0)
            .unwrap()
            .1;
        let (mut genesis, sponsor) = fed.sponsored(
            vec![],
            vec![
                fed.output(
                    program
                        .output(Amount::from_sats(1), [0; 32], vec![])
                        .unwrap(),
                ),
            ],
        );
        sign_transaction(&mut genesis, &[sponsor]).unwrap();
        fed.submit(&genesis).await;
        fed.wait_contract(point(&genesis, 0)).await;
        let origin = point(&genesis, 0);
        fed.set_block_count(opens).await;
        let client = join(builder, &fed, db(), 51, false, false).await;
        funds(&client).await;
        let wallet = client.get_first_module::<SimplicityClientModule>().unwrap();
        assert_eq!(
            wallet
                .watch_contract(origin, descriptor.clone())
                .await
                .unwrap(),
            Some(origin)
        );
        let contracts = wallet.contracts_for([origin]).await;
        let mut output = contracts[&origin].output.clone();
        assert!(output.recovery.is_empty());
        output.state[31] = 3;
        let plan = TransactionPlan {
            spends: vec![SpendIntent {
                outpoint: origin,
                signature_witness: None,
                witnesses: compiler::witnesses([]),
            }],
            outputs: vec![output],
            ..Default::default()
        };
        let snapshot = wallet.pruning_snapshot([origin]).await.unwrap();
        let quoted = wallet
            .plan_fee_request(&plan, &contracts, &snapshot)
            .unwrap();
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
