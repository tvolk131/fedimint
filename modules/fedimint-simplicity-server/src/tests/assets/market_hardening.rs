//! Exercise policy failures through core validation, keeping asset accounting
//! and signatures valid so they cannot mask a missing covenant check.
use super::*;

fn resolve(market: &Market, state: u8, amount: u64) -> Transaction {
    let (mut tx, sponsor) = sponsored(
        vec![market.input(2, state, &market.oracle)],
        vec![market.vault_output(amount, state)],
    );
    sign_transaction(&mut tx, &[market.operator, sponsor]).unwrap();
    tx
}

fn attestation_input(
    market: &Market,
    terms: &market::BinaryMarket,
    signed: u8,
    claimed: u8,
) -> DynInput {
    let message = Message::from_digest(terms.attestation_message(signed).unwrap());
    let signature = Value::byte_array(
        *SECP256K1
            .sign_schnorr_no_aux_rand(&message, &market.oracle)
            .as_ref(),
    );
    DynInput::from_typed(
        SIMP,
        market
            .program
            .input(
                market.vault,
                market.operator.public_key(),
                witnesses([
                    ("ACTION", Value::u8(2)),
                    ("OUTCOME", Value::u8(claimed)),
                    ("ORACLE_SIGNATURE", signature),
                ]),
            )
            .unwrap(),
    )
}

#[tokio::test]
async fn oracle_attestations_are_bound_to_every_market_term_and_outcome() {
    let market = Market::new().await;
    market.fed.vote(5).await;
    for field in 0..9 {
        let mut other = market.terms.clone();
        match field {
            0 => other.event[0] ^= 1,
            1 => other.rules[0] ^= 1,
            2 => other.federation = FederationId(sha256::Hash::hash(b"another federation")),
            3 => other.module += 1,
            4 => other.yes.0[0] ^= 1,
            5 => other.no.0[0] ^= 1,
            6 => other.resolution_start += 1,
            7 => other.deadline += 1,
            8 => other.oracle = key().x_only_public_key().0,
            _ => unreachable!(),
        }
        let (mut tx, sponsor) = sponsored(
            vec![attestation_input(&market, &other, 1, 1)],
            vec![market.vault_output(0, 1)],
        );
        sign_transaction(&mut tx, &[market.operator, sponsor]).unwrap();
        assert_error(market.fed.process(&tx, 1).await, "program rejected");
        assert!(market.fed.contract(market.vault).await.is_some());
    }
    let (mut tx, sponsor) = sponsored(
        vec![attestation_input(&market, &market.terms, 2, 1)],
        vec![market.vault_output(0, 1)],
    );
    sign_transaction(&mut tx, &[market.operator, sponsor]).unwrap();
    assert_error(market.fed.process(&tx, 1).await, "program rejected");
    market
        .fed
        .process(&resolve(&market, 1, 0), 1)
        .await
        .unwrap();
}

#[tokio::test]
async fn oracle_and_timeout_windows_have_exact_boundaries() {
    for height in [4, 5, 9, 10, 11] {
        for outcome in [1, 2, 3] {
            let market = Market::new().await;
            market.fed.vote(height).await;
            let tx = resolve(&market, outcome, 0);
            if (5..10).contains(&height) || (height >= 10 && outcome == 3) {
                market.fed.process(&tx, 1).await.unwrap();
            } else {
                assert_error(market.fed.process(&tx, 1).await, "program rejected");
                assert!(market.fed.contract(market.vault).await.is_some());
            }
        }
        // A timeout needs no oracle signature, but cannot be taken early.
        let market = Market::new().await;
        market.fed.vote(height).await;
        let (mut tx, sponsor) = sponsored(
            vec![market.input(2, 3, &key())],
            vec![market.vault_output(0, 3)],
        );
        sign_transaction(&mut tx, &[market.operator, sponsor]).unwrap();
        if height >= 10 {
            market.fed.process(&tx, 1).await.unwrap();
        } else {
            assert_error(market.fed.process(&tx, 1).await, "program rejected");
        }
    }
}

fn issue_transaction(
    market: &Market,
    owner: &Keypair,
    yes: u64,
    no: u64,
    collateral: u64,
    state: u8,
) -> (Transaction, Keypair) {
    let program = market::owner_program(owner.x_only_public_key().0).unwrap();
    sponsored(
        vec![market.input(0, 1, &market.oracle)],
        vec![
            market.vault_output(collateral, state),
            output(
                program
                    .asset_output(
                        Amount::ZERO,
                        [0; 32],
                        vec![],
                        bundle(&[(market.terms.yes, yes), (market.terms.no, no)], &[]),
                    )
                    .unwrap(),
            ),
            actions(&[(market.terms.yes, yes), (market.terms.no, no)], &[]),
        ],
    )
}

#[tokio::test]
async fn issuance_preserves_the_vault_policy_authorities_state_and_pair_backing() {
    let market = Market::new().await;
    let owner = key();
    let program = market::owner_program(owner.x_only_public_key().0).unwrap();
    for case in 0..9 {
        let (mut tx, sponsor) = issue_transaction(&market, &owner, 1, 1, 1000, 0);
        let mut successor = tx.outputs[0]
            .as_any()
            .downcast_ref::<ContractOutput>()
            .unwrap()
            .clone();
        let expected = match case {
            0 => {
                successor.cmr = program.cmr();
                "program rejected"
            }
            1 => {
                successor.state = market::state(1).unwrap();
                "program rejected"
            }
            2 => {
                successor.extension = Some(AssetExtension::Bundle(bundle(&[], &[])));
                "program rejected"
            }
            3 => {
                // Move the authorities to a different, freely spendable output.
                successor.extension = Some(AssetExtension::Bundle(bundle(&[], &[])));
                tx.outputs.push(output(
                    program
                        .asset_output(
                            Amount::ZERO,
                            [0; 32],
                            vec![],
                            bundle(&[], &[market.terms.yes, market.terms.no]),
                        )
                        .unwrap(),
                ));
                "program rejected"
            }
            4 => {
                successor.amount = Amount::from_msats(999);
                "program rejected"
            }
            5 => {
                successor.amount = Amount::from_msats(1001);
                "program rejected"
            }
            6 => {
                tx.outputs.push(output(successor.clone()));
                "asset transition"
            }
            7 => {
                successor.extension =
                    Some(AssetExtension::Bundle(bundle(&[], &[market.terms.yes])));
                "program rejected"
            }
            8 => {
                successor.version = 0;
                successor.extension = None;
                "program rejected"
            }
            _ => unreachable!(),
        };
        tx.outputs[0] = output(successor);
        sign_transaction(&mut tx, &[market.operator, sponsor]).unwrap();
        assert_error(market.fed.process(&tx, 1).await, expected);
        assert!(market.fed.contract(market.vault).await.is_some());
        assert!(market.fed.contract(point(&tx, 1)).await.is_none());
    }
    for (yes, no) in [(0, 0), (1, 0), (0, 1), (1, 2)] {
        let (mut tx, sponsor) = issue_transaction(&market, &owner, yes, no, yes * 1000, 0);
        sign_transaction(&mut tx, &[market.operator, sponsor]).unwrap();
        assert_error(market.fed.process(&tx, 1).await, "program rejected");
    }
    for height in [9, 10] {
        let market = Market::new().await;
        market.fed.vote(height).await;
        let (mut tx, sponsor) = issue_transaction(&market, &owner, 1, 1, 1000, 0);
        sign_transaction(&mut tx, &[market.operator, sponsor]).unwrap();
        if height == 9 {
            market.fed.process(&tx, 1).await.unwrap();
        } else {
            assert_error(market.fed.process(&tx, 1).await, "program rejected");
        }
    }
}

struct Holding {
    point: OutPoint,
    owner: Keypair,
    yes: u64,
    no: u64,
    native: u64,
}

// Exact token conservation and owner authorization, with independently
// specified policy action, burns, successor state, and collateral for negative
// cases.
fn burn_transaction(
    market: &Market,
    holding: &Holding,
    action: u8,
    state: u8,
    burns: (u64, u64),
    collateral: u64,
    payout: u64,
) -> Transaction {
    let program = market::owner_program(holding.owner.x_only_public_key().0).unwrap();
    let (mut tx, sponsor) = sponsored(
        vec![
            market.input(action, state, &market.oracle),
            owner_input(
                &program,
                holding.point,
                &holding.owner,
                placeholder_signature(),
            ),
        ],
        vec![
            market.vault_output(collateral, state),
            output(
                program
                    .asset_output(
                        Amount::from_msats(holding.native + payout),
                        [0; 32],
                        vec![],
                        bundle(
                            &[
                                (market.terms.yes, holding.yes - burns.0),
                                (market.terms.no, holding.no - burns.1),
                            ],
                            &[],
                        ),
                    )
                    .unwrap(),
            ),
            actions(
                &[],
                &[(market.terms.yes, burns.0), (market.terms.no, burns.1)],
            ),
        ],
    );
    sign_owner(&mut tx, 1, &program, holding.point, &holding.owner);
    sign_transaction(&mut tx, &[market.operator, holding.owner, sponsor]).unwrap();
    tx
}

#[tokio::test]
async fn actions_cannot_cross_resolution_states_or_redeem_unmatched_pairs() {
    for state in 0..=3 {
        let mut market = Market::new().await;
        let owner = key();
        let holding = Holding {
            point: market.issue(&owner, 4).await,
            owner,
            yes: 4,
            no: 4,
            native: 0,
        };
        if state != 0 {
            market.fed.vote(5).await;
            let tx = resolve(&market, state, 4000);
            market.fed.process(&tx, 2).await.unwrap();
            market.vault = point(&tx, 0);
        }
        // A one-unit burn with the wrong action/state may conserve all assets,
        // yet cannot release collateral under this policy.
        let cases: Vec<_> = if state == 0 {
            vec![
                (1, (1, 0), 1000),
                (1, (0, 1), 1000),
                (1, (1, 2), 1000),
                (1, (0, 0), 0),
                (3, (1, 1), 1000),
            ]
        } else {
            let mut cases = vec![(1, (1, 1), 1000), (3, (0, 0), 0)];
            if state == 1 {
                cases.push((3, (0, 1), 1000));
            }
            if state == 2 {
                cases.push((3, (1, 0), 1000));
            }
            cases
        };
        for (action, burns, payout) in cases {
            let tx = burn_transaction(
                &market,
                &holding,
                action,
                state,
                burns,
                4000 - payout,
                payout,
            );
            assert_error(market.fed.process(&tx, 3).await, "program rejected");
            assert!(market.fed.contract(market.vault).await.is_some());
            assert!(market.fed.contract(holding.point).await.is_some());
        }
        if state != 0 {
            let (mut tx, sponsor) = issue_transaction(&market, &owner, 1, 1, 5000, state);
            sign_transaction(&mut tx, &[market.operator, sponsor]).unwrap();
            assert_error(market.fed.process(&tx, 3).await, "program rejected");
        }
        // Prove rejected attempts leave a valid transition available.
        let burns = match state {
            0 => (1, 1),
            1 => (1, 0),
            2 => (0, 1),
            _ => (1, 1),
        };
        let tx = burn_transaction(
            &market,
            &holding,
            if state == 0 { 1 } else { 3 },
            state,
            burns,
            3000,
            1000,
        );
        market.fed.process(&tx, 3).await.unwrap();
    }
}

#[tokio::test]
async fn repeated_issuance_transfers_and_partial_redemptions_exhaust_all_outcomes() {
    for state in 1..=3 {
        let mut market = Market::new().await;
        let alice = key();
        let bob = key();
        let carol = key();
        let first = market.issue(&alice, 6).await;
        let second = market.issue(&bob, 4).await;
        assert_eq!(
            market
                .fed
                .contract(market.vault)
                .await
                .unwrap()
                .output
                .amount
                .msats,
            10_000
        );
        let mut holdings = vec![];
        // Transfer YES and NO independently to different owners; leave the
        // vault untouched. INVALID will redeem every unit of both assets.
        for (point_in, owner, quantity, yes_owner, no_owner) in [
            (first, alice, 6, carol, alice),
            (second, bob, 4, bob, carol),
        ] {
            let program = market::owner_program(owner.x_only_public_key().0).unwrap();
            let recipients = [(yes_owner, quantity, 0), (no_owner, 0, quantity)];
            let outputs = recipients
                .iter()
                .map(|(key, yes, no)| {
                    output(
                        market::owner_program(key.x_only_public_key().0)
                            .unwrap()
                            .asset_output(
                                Amount::ZERO,
                                [0; 32],
                                vec![],
                                bundle(&[(market.terms.yes, *yes), (market.terms.no, *no)], &[]),
                            )
                            .unwrap(),
                    )
                })
                .collect();
            let (mut tx, sponsor) = sponsored(
                vec![owner_input(
                    &program,
                    point_in,
                    &owner,
                    placeholder_signature(),
                )],
                outputs,
            );
            sign_owner(&mut tx, 0, &program, point_in, &owner);
            sign_transaction(&mut tx, &[owner, sponsor]).unwrap();
            market.fed.process(&tx, 2).await.unwrap();
            for (index, (owner, yes, no)) in recipients.into_iter().enumerate() {
                holdings.push(Holding {
                    point: point(&tx, index as u64),
                    owner,
                    yes,
                    no,
                    native: 0,
                });
            }
        }
        market.fed.vote(5).await;
        let tx = resolve(&market, state, 10_000);
        market.fed.process(&tx, 3).await.unwrap();
        market.vault = point(&tx, 0);
        let mut collateral = 10_000;
        let mut total_paid = 0;
        for holding in &mut holdings {
            let yes = if state == 2 { 0 } else { holding.yes };
            let no = if state == 1 { 0 } else { holding.no };
            if yes + no == 0 {
                continue;
            }
            // Redeem one unit, then the remainder against the new vault.
            let first = (u64::from(yes != 0), u64::from(no != 0));
            for burns in [first, (yes - first.0, no - first.1)] {
                let payout = (burns.0 + burns.1) * if state == 3 { 500 } else { 1000 };
                collateral -= payout;
                let tx = burn_transaction(&market, holding, 3, state, burns, collateral, payout);
                market.fed.process(&tx, 4).await.unwrap();
                market.vault = point(&tx, 0);
                holding.point = point(&tx, 1);
                holding.yes -= burns.0;
                holding.no -= burns.1;
                holding.native += payout;
                let received = market.fed.contract(holding.point).await.unwrap();
                assert_eq!(received.output.amount.msats, holding.native);
                total_paid += payout;
                assert_eq!(
                    market
                        .fed
                        .contract(market.vault)
                        .await
                        .unwrap()
                        .output
                        .amount
                        .msats,
                    collateral
                );
            }
        }
        assert_eq!(total_paid, 10_000);
        assert_eq!(collateral, 0);
        assert!(holdings.iter().all(|h| match state {
            1 => h.yes == 0,
            2 => h.no == 0,
            _ => h.yes == 0 && h.no == 0,
        }));
    }
}

#[tokio::test]
async fn distinct_competing_redemptions_rebuild_against_the_winning_successor() {
    let mut market = Market::new().await;
    let alice = key();
    let bob = key();
    let first = Holding {
        point: market.issue(&alice, 1).await,
        owner: alice,
        yes: 1,
        no: 1,
        native: 0,
    };
    let second = Holding {
        point: market.issue(&bob, 1).await,
        owner: bob,
        yes: 1,
        no: 1,
        native: 0,
    };
    market.fed.vote(5).await;
    let tx = resolve(&market, 1, 2000);
    market.fed.process(&tx, 2).await.unwrap();
    market.vault = point(&tx, 0);
    let first_tx = burn_transaction(&market, &first, 3, 1, (1, 0), 1000, 1000);
    let stale_tx = burn_transaction(&market, &second, 3, 1, (1, 0), 1000, 1000);
    assert_ne!(first_tx.tx_hash(), stale_tx.tx_hash());
    market.fed.check_submission(&first_tx, 3).await.unwrap();
    market.fed.check_submission(&stale_tx, 3).await.unwrap();
    market.fed.process(&first_tx, 3).await.unwrap();
    assert_error(market.fed.process(&stale_tx, 3).await, "already spent");
    assert!(market.fed.contract(second.point).await.is_some());
    assert!(market.fed.contract(point(&stale_tx, 1)).await.is_none());
    market.vault = point(&first_tx, 0);
    let rebuilt = burn_transaction(&market, &second, 3, 1, (1, 0), 0, 1000);
    market.fed.process(&rebuilt, 4).await.unwrap();
    assert_eq!(
        market
            .fed
            .contract(point(&rebuilt, 0))
            .await
            .unwrap()
            .output
            .amount,
        Amount::ZERO
    );
}

fn balance_change(tx: &mut Transaction, input_msats: u64, change_index: usize) -> u64 {
    let input_fees: u64 = tx
        .inputs
        .iter()
        .filter_map(|input| input.as_any().downcast_ref::<ContractInput>())
        .map(|input| {
            fedimint_simplicity_common::runtime::input_fee(input)
                .unwrap()
                .msats
        })
        .sum();
    let output_fees: u64 = tx
        .outputs
        .iter()
        .filter_map(|output| output.as_any().downcast_ref::<ContractOutput>())
        .map(|output| output_fee(output).msats)
        .sum();
    let other_outputs: u64 = tx
        .outputs
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != change_index)
        .map(|(_, output)| {
            if let Some(contract) = output.as_any().downcast_ref::<ContractOutput>() {
                contract.amount.msats
            } else {
                output
                    .as_any()
                    .downcast_ref::<MintOutput>()
                    .unwrap()
                    .ensure_v0_ref()
                    .unwrap()
                    .denomination
                    .amount()
                    .msats
            }
        })
        .sum();
    let fees = input_fees + output_fees; // This fixture configures zero mint fees.
    let mut change = tx.outputs[change_index]
        .as_any()
        .downcast_ref::<ContractOutput>()
        .unwrap()
        .clone();
    change.amount = Amount::from_msats(input_msats.checked_sub(other_outputs + fees).unwrap());
    tx.outputs[change_index] = output(change);
    fees
}

#[tokio::test]
async fn exact_ecash_funding_charges_static_fees_returns_change_and_rolls_back_shortfall() {
    let mut market = Market::new().await;
    let owner = key();
    let program = market::owner_program(owner.x_only_public_key().0).unwrap();
    let request = MintRequest::new(Denomination(20));
    let funding = market.fed.fund(vec![request.output()]).await;
    let note = market.fed.note(&request, point(&funding, 0)).await;
    let (mut issue, _) = issue_transaction(&market, &owner, 8, 8, 8000, 0);
    // Replace the dummy sponsor with exactly one real ecash note.
    issue.inputs.pop();
    issue
        .inputs
        .push(DynInput::from_typed(MINT, MintInput::new_v0(note)));
    issue.outputs.push(output(
        program
            .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[], &[]))
            .unwrap(),
    ));
    let initial = 1 << 20;
    let issue_fees = balance_change(&mut issue, initial, 3);
    assert!(issue_fees > 0);
    sign_transaction(&mut issue, &[market.operator, request.key]).unwrap();
    let mut short = issue.clone();
    let mut change = short.outputs[3]
        .as_any()
        .downcast_ref::<ContractOutput>()
        .unwrap()
        .clone();
    change.amount += Amount::from_msats(1);
    short.outputs[3] = output(change);
    sign_transaction(&mut short, &[market.operator, request.key]).unwrap();
    assert_error(market.fed.process(&short, 1).await, "unbalanced");
    assert!(market.fed.contract(market.vault).await.is_some());
    assert!(market.fed.contract(point(&short, 1)).await.is_none());
    // Reusing the same mint note proves the failed transaction rolled it back.
    market.fed.process(&issue, 1).await.unwrap();
    market.vault = point(&issue, 0);
    let positions = point(&issue, 1);
    let mut change_point = point(&issue, 3);
    let mut change_amount = initial - 8000 - issue_fees;
    assert_eq!(
        market
            .fed
            .contract(change_point)
            .await
            .unwrap()
            .output
            .amount
            .msats,
        change_amount
    );

    market.fed.vote(5).await;
    let mut resolution = transaction(
        vec![
            market.input(2, 1, &market.oracle),
            owner_input(&program, change_point, &owner, placeholder_signature()),
        ],
        vec![
            market.vault_output(8000, 1),
            output(
                program
                    .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[], &[]))
                    .unwrap(),
            ),
        ],
    );
    let resolution_fees = balance_change(&mut resolution, 8000 + change_amount, 1);
    sign_owner(&mut resolution, 1, &program, change_point, &owner);
    sign_transaction(&mut resolution, &[market.operator, owner]).unwrap();
    market.fed.process(&resolution, 2).await.unwrap();
    market.vault = point(&resolution, 0);
    change_point = point(&resolution, 1);
    change_amount -= resolution_fees;

    let payout = MintRequest::new(Denomination(12));
    let mut redeem = transaction(
        vec![
            market.input(3, 1, &market.oracle),
            owner_input(&program, positions, &owner, placeholder_signature()),
            owner_input(&program, change_point, &owner, placeholder_signature()),
        ],
        vec![
            market.vault_output(0, 1),
            payout.output(),
            output(
                program
                    .asset_output(
                        Amount::ZERO,
                        [0; 32],
                        vec![],
                        bundle(&[(market.terms.no, 8)], &[]),
                    )
                    .unwrap(),
            ),
            actions(&[], &[(market.terms.yes, 8)]),
        ],
    );
    let redeem_fees = balance_change(&mut redeem, 8000 + change_amount, 2);
    sign_owner(&mut redeem, 1, &program, positions, &owner);
    sign_owner(&mut redeem, 2, &program, change_point, &owner);
    sign_transaction(&mut redeem, &[market.operator, owner, owner]).unwrap();
    market.fed.process(&redeem, 3).await.unwrap();
    let final_note = market.fed.note(&payout, point(&redeem, 1)).await;
    let final_change = market
        .fed
        .contract(point(&redeem, 2))
        .await
        .unwrap()
        .output
        .amount
        .msats;
    assert_eq!(
        final_note.amount().msats + final_change + issue_fees + resolution_fees + redeem_fees,
        initial
    );
    assert_eq!(
        market
            .fed
            .contract(point(&redeem, 0))
            .await
            .unwrap()
            .output
            .amount,
        Amount::ZERO
    );
}

#[tokio::test]
async fn admitted_transactions_are_revalidated_when_the_consensus_clock_changes() {
    let market = Market::new().await;
    market.fed.vote(9).await;
    let (mut issue, sponsor) = issue_transaction(&market, &key(), 1, 1, 1000, 0);
    sign_transaction(&mut issue, &[market.operator, sponsor]).unwrap();
    let resolution = resolve(&market, 1, 0);
    market.fed.check_submission(&issue, 2).await.unwrap();
    market.fed.check_submission(&resolution, 2).await.unwrap();
    market.fed.vote(10).await;
    for tx in [&issue, &resolution] {
        assert_error(market.fed.process(tx, 3).await, "program rejected");
        assert!(market.fed.contract(market.vault).await.is_some());
        assert!(market.fed.contract(point(tx, 0)).await.is_none());
    }
    market
        .fed
        .process(&resolve(&market, 3, 0), 3)
        .await
        .unwrap();
}
