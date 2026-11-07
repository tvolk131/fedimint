//! Exact ecash funding through the real core processor. Static fees are
//! charged, change returns as a contract output, and a one-msat shortfall rolls
//! back the note and every write. Policies are plain owner programs, so a
//! failure here is a funding or accounting failure, not a covenant one.
use super::*;

/// Set the change output so the transaction pays exactly its static fees, and
/// return those fees. The input programs must already be in their final pruned
/// form: their size is part of the fee.
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
    let fed = Harness::new();
    let creator = key();
    let owner = key();
    let program = owner_program(owner.x_only_public_key().0).unwrap();
    let native = |msats: u64, assets: AssetBundle| {
        output(
            program
                .asset_output(Amount::from_msats(msats), [0; 32], vec![], assets)
                .unwrap(),
        )
    };
    let request = MintRequest::new(Denomination(20));
    let funding = fed.fund(vec![request.output()]).await;
    let note = fed.note(&request, point(&funding, 0)).await;
    let initial = 1u64 << 20;
    assert_eq!(note.amount().msats, initial);

    // One real note funds a bank and, as exact change, everything else.
    let mut deposit = transaction(
        vec![DynInput::from_typed(MINT, MintInput::new_v0(note))],
        vec![native(8000, bundle(&[], &[])), native(0, bundle(&[], &[]))],
    );
    let deposit_fees = balance_change(&mut deposit, initial, 1);
    assert!(deposit_fees > 0);
    fed.sign(&mut deposit, &[request.key]).await.unwrap();
    let mut short = deposit.clone();
    let mut change = short.outputs[1]
        .as_any()
        .downcast_ref::<ContractOutput>()
        .unwrap()
        .clone();
    change.amount += Amount::from_msats(1);
    short.outputs[1] = output(change);
    fed.sign(&mut short, &[request.key]).await.unwrap();
    assert_error(fed.process(&short, 1).await, "unbalanced");
    assert!(fed.contract(point(&short, 0)).await.is_none());
    assert!(fed.contract(point(&short, 1)).await.is_none());
    // Reusing the same mint note proves the failed transaction rolled it back.
    fed.process(&deposit, 1).await.unwrap();
    let bank = point(&deposit, 0);
    let change_point = point(&deposit, 1);
    let change_amount = initial - 8000 - deposit_fees;
    assert_eq!(
        fed.contract(change_point)
            .await
            .unwrap()
            .output
            .amount
            .msats,
        change_amount
    );

    // Create a namespace from both contracts. Its fee is static as well, and
    // the change shrinks by exactly that fee.
    let (creation, ids) = assets::creation(federation_id(), SIMP, &creator, vec![0, 0]).unwrap();
    let mut create = transaction(
        vec![
            owner_input(&program, bank, &owner, placeholder_signature()),
            owner_input(&program, change_point, &owner, placeholder_signature()),
        ],
        vec![
            native(8000, bundle(&[], &ids)),
            output(
                assets::action_output(AssetActions {
                    creations: vec![creation],
                    ..Default::default()
                })
                .unwrap(),
            ),
            native(0, bundle(&[], &[])),
        ],
    );
    fed.prune(&mut create, 2).await;
    let create_fees = balance_change(&mut create, 8000 + change_amount, 2);
    assets::sign_creation(&mut create, federation_id(), SIMP, &creator).unwrap();
    sign_owner(&mut create, 0, &program, bank, &owner);
    sign_owner(&mut create, 1, &program, change_point, &owner);
    fed.sign(&mut create, &[owner, owner]).await.unwrap();
    fed.process(&create, 2).await.unwrap();
    let authority = point(&create, 0);
    let change_point = point(&create, 2);
    let change_amount = change_amount - create_fees;
    assert_eq!(
        fed.contract(change_point)
            .await
            .unwrap()
            .output
            .amount
            .msats,
        change_amount
    );

    // Issue tokens and pay a real note out of the same spend; the change is
    // again exact.
    let payout = MintRequest::new(Denomination(12));
    let mut issue = transaction(
        vec![
            owner_input(&program, authority, &owner, placeholder_signature()),
            owner_input(&program, change_point, &owner, placeholder_signature()),
        ],
        vec![
            native(8000, bundle(&[], &ids)),
            native(0, bundle(&[(ids[0], 8), (ids[1], 8)], &[])),
            actions(&[(ids[0], 8), (ids[1], 8)], &[]),
            payout.output(),
            native(0, bundle(&[], &[])),
        ],
    );
    fed.prune(&mut issue, 3).await;
    let issue_fees = balance_change(&mut issue, 8000 + change_amount, 4);
    sign_owner(&mut issue, 0, &program, authority, &owner);
    sign_owner(&mut issue, 1, &program, change_point, &owner);
    fed.sign(&mut issue, &[owner, owner]).await.unwrap();
    fed.process(&issue, 3).await.unwrap();
    let final_note = fed.note(&payout, point(&issue, 3)).await;
    let final_change = fed
        .contract(point(&issue, 4))
        .await
        .unwrap()
        .output
        .amount
        .msats;
    // Every msat is a note, a contract balance, or a fee.
    assert_eq!(
        final_note.amount().msats + final_change + 8000 + deposit_fees + create_fees + issue_fees,
        initial
    );
    assert_eq!(
        fed.contract(point(&issue, 1))
            .await
            .unwrap()
            .output
            .bundle(),
        Some(&bundle(&[(ids[0], 8), (ids[1], 8)], &[]))
    );
    assert!(fed.contract(authority).await.is_none());
}
