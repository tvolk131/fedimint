//! Force a spend after plan construction but before the pruning point query.
use fedimint_simplicity_client::intent::RetryMode;

use super::*;

pub(super) async fn build(
    wallet: &SimplicityClientModule,
    intent: &Intent,
    context: &IntentContext,
) -> anyhow::Result<IntentPlan> {
    let (original, replacement, stale) =
        <(OutPoint, ContractOutput, bool)>::consensus_decode_whole(
            &intent.data,
            &Default::default(),
        )?;
    let before = &context.contracts[&original];
    let point = match before.spent_by {
        None => {
            // This successful competing transaction makes the already captured
            // context stale deterministically, with no scheduling sleeps.
            let (operation, _) = wallet
                .submit(
                    vec![SpendIntent::owner(original)],
                    vec![replacement],
                    vec![],
                )
                .await?;
            wallet.await_operation(operation).await?;
            original
        }
        Some(_) if stale => original,
        Some(txid) => OutPoint { txid, out_idx: 0 },
    };
    Ok(IntentPlan {
        max_fee: None,
        spends: vec![SpendIntent::owner(point)],
        outputs: vec![],
        shared_inputs: vec![point],
    })
}

pub(super) async fn check(client: &ClientHandle) {
    let wallet = client.get_first_module::<SimplicityClientModule>().unwrap();
    for (retry, stale, completes) in [
        (RetryMode::Automatic, false, true),
        (RetryMode::Automatic, true, false),
        (RetryMode::Manual, false, false),
    ] {
        let output = wallet
            .receive(Amount::from_sats(1), Default::default())
            .unwrap();
        let txid = submit(&wallet, vec![], vec![output], vec![]).await;
        let original = OutPoint { txid, out_idx: 0 };
        let replacement = wallet
            .receive(Amount::from_sats(1), Default::default())
            .unwrap();
        let history = wallet.history().await.len();
        let id = wallet
            .submit_intent(
                Intent {
                    template: "pruning-race-test".to_owned(),
                    version: 1,
                    data: (original, replacement, stale).consensus_encode_to_vec(),
                },
                IntentPolicy {
                    retry,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let record = tokio::time::timeout(Duration::from_secs(20), wallet.await_intent(id))
            .await
            .unwrap()
            .unwrap();
        if completes {
            assert!(
                matches!(record.status, IntentStatus::Complete(_)),
                "{record:?}"
            );
            assert_eq!(
                record.attempts.len(),
                1,
                "no losing transaction was submitted"
            );
            assert_ne!(record.attempts[0].shared_inputs, vec![original]);
        } else {
            assert!(
                matches!(record.status, IntentStatus::Attention(_)),
                "{record:?}"
            );
            assert!(record.attempts.is_empty());
        }
        wallet.sync().await.unwrap();
        assert_eq!(
            wallet.history().await.len(),
            history + 1 + usize::from(completes)
        );
    }
}
