//! Distinct transactions competing for one shared contract. Admission checks
//! each against the same state, so both look valid; consensus accepts the
//! first and rejects the loser without side effects, and a spend rebuilt on the
//! winner's successor succeeds.
use super::*;

/// Anyone may spend this contract, provided output 0 keeps its policy.
const SHARED_POLICY: &str =
    "fn main() { assert!(jet::eq_256(jet::fm_current_cmr(), jet::fm_output_cmr(0))); }";

async fn spend(
    fed: &Harness,
    shared: &ContractProgram,
    point: OutPoint,
    spender: &Keypair,
    remaining_msats: u64,
    payout: &ContractProgram,
) -> Transaction {
    let input = shared
        .input(point, spender.public_key(), witnesses([]))
        .unwrap();
    let (mut tx, sponsor) = sponsored(
        vec![DynInput::from_typed(SIMP, input)],
        vec![
            output(
                shared
                    .output(Amount::from_msats(remaining_msats), [0; 32], vec![])
                    .unwrap(),
            ),
            output(
                payout
                    .output(Amount::from_msats(1000), [0; 32], vec![])
                    .unwrap(),
            ),
        ],
    );
    fed.sign(&mut tx, &[*spender, sponsor]).await.unwrap();
    tx
}

#[tokio::test]
async fn distinct_competing_spends_rebuild_against_the_winning_successor() {
    let fed = Harness::new();
    let shared = ContractProgram::compile(SHARED_POLICY, arguments([])).unwrap();
    let (alice, bob) = (key(), key());
    let alice_payout = owner_program(alice.x_only_public_key().0).unwrap();
    let bob_payout = owner_program(bob.x_only_public_key().0).unwrap();
    let funding = fed
        .fund(vec![output(
            shared
                .output(Amount::from_msats(3000), [0; 32], vec![])
                .unwrap(),
        )])
        .await;
    let origin = point(&funding, 0);
    let first = spend(&fed, &shared, origin, &alice, 2000, &alice_payout).await;
    let loser = spend(&fed, &shared, origin, &bob, 2000, &bob_payout).await;
    assert_ne!(first.tx_hash(), loser.tx_hash());
    fed.check_submission(&first, 1).await.unwrap();
    fed.check_submission(&loser, 1).await.unwrap();
    fed.process(&first, 1).await.unwrap();
    assert_error(fed.process(&loser, 1).await, "already spent");
    assert!(fed.check_submission(&loser, 1).await.is_err());
    assert!(fed.contract(point(&loser, 0)).await.is_none());
    assert!(fed.contract(point(&loser, 1)).await.is_none());
    assert!(fed.contract(origin).await.is_none());

    // Rebuilt against the winner's successor, the loser's spend succeeds.
    let winner = point(&first, 0);
    assert_eq!(
        fed.contract(winner).await.unwrap().output.amount,
        Amount::from_msats(2000)
    );
    let rebuilt = spend(&fed, &shared, winner, &bob, 1000, &bob_payout).await;
    fed.process(&rebuilt, 2).await.unwrap();
    assert!(fed.contract(winner).await.is_none());
    // The successor keeps 1000 and the payout carries 1000.
    for index in 0..2 {
        assert_eq!(
            fed.contract(point(&rebuilt, index))
                .await
                .unwrap()
                .output
                .amount,
            Amount::from_msats(1000)
        );
    }
}
