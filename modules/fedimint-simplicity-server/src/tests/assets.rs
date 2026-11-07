mod clocks;
mod contention;
mod context;
mod funding;
mod instances;
mod network;
mod resources;

use fedimint_simplicity_client::assets;
use fedimint_simplicity_common::ContractOutput;
use fedimint_simplicity_common::assets::{
    AssetActions, AssetAmount, AssetBundle, AssetExtension, AssetId,
};

use super::*;
use crate::db::AssetKey;

fn output(value: ContractOutput) -> DynOutput {
    DynOutput::from_typed(SIMP, value)
}
fn point(tx: &Transaction, index: u64) -> OutPoint {
    OutPoint {
        txid: tx.tx_hash(),
        out_idx: index,
    }
}
fn values(items: &[(AssetId, u64)]) -> Vec<AssetAmount> {
    let mut result = items
        .iter()
        .filter(|(_, q)| *q != 0)
        .map(|(asset, quantity)| AssetAmount {
            asset: *asset,
            quantity: *quantity,
        })
        .collect::<Vec<_>>();
    result.sort_by_key(|value| value.asset);
    result
}
fn bundle(items: &[(AssetId, u64)], authorities: &[AssetId]) -> AssetBundle {
    let mut authorities = authorities.to_vec();
    authorities.sort();
    AssetBundle {
        balances: values(items),
        authorities,
    }
}
fn actions(issue: &[(AssetId, u64)], burn: &[(AssetId, u64)]) -> DynOutput {
    output(
        assets::action_output(AssetActions {
            issuance: values(issue),
            burns: values(burn),
            ..Default::default()
        })
        .unwrap(),
    )
}
fn sponsored(inputs: Vec<DynInput>, outputs: Vec<DynOutput>) -> (Transaction, Keypair) {
    let sponsor = key();
    let mut tx = transaction(inputs, outputs);
    tx.inputs.push(DynInput::from_typed(
        DUMMY,
        DummyInput {
            amount: Amount::from_sats(100_000),
            unit: AmountUnit::BITCOIN,
            pub_key: sponsor.public_key(),
        },
    ));
    (tx, sponsor)
}
fn owner_input(
    program: &ContractProgram,
    point: OutPoint,
    owner: &Keypair,
    signature: Value,
) -> DynInput {
    DynInput::from_typed(
        SIMP,
        program
            .input(
                point,
                owner.public_key(),
                witnesses([("SIGNATURE", signature)]),
            )
            .unwrap(),
    )
}
fn sign_owner(
    tx: &mut Transaction,
    index: usize,
    program: &ContractProgram,
    point: OutPoint,
    owner: &Keypair,
) {
    let signature = assets::signature_value(federation_id(), SIMP, tx, owner).unwrap();
    tx.inputs[index] = owner_input(program, point, owner, signature);
}
fn assert_error(result: anyhow::Result<()>, expected: &str) {
    let error = format!("{:#}", result.unwrap_err());
    assert!(
        error.contains(expected),
        "expected {expected:?}, got {error}"
    );
}

#[tokio::test]
async fn namespace_authority_and_conservation_cannot_be_bypassed() {
    let fed = Harness::new();
    let creator = key();
    let owner = key();
    let program = owner_program(owner.x_only_public_key().0).unwrap();
    let (creation, ids) = assets::creation(federation_id(), SIMP, &creator, vec![0, 0, 0]).unwrap();
    let initial = program
        .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[], &ids))
        .unwrap();
    let action = assets::action_output(AssetActions {
        creations: vec![creation],
        ..Default::default()
    })
    .unwrap();
    let (mut create, sponsor) = sponsored(vec![], vec![output(initial.clone()), output(action)]);
    // Pin the full three-asset creation fee independently of the fee helper:
    // two 100-msat bases, 206 extension bytes and three 100-msat asset charges.
    create.inputs[0] = DynInput::from_typed(
        DUMMY,
        DummyInput {
            amount: Amount::from_msats(706),
            unit: AmountUnit::BITCOIN,
            pub_key: sponsor.public_key(),
        },
    );
    fed.sign(&mut create, &[sponsor]).await.unwrap();
    assert_error(fed.process(&create, 0).await, "creation authorization");
    assets::sign_creation(&mut create, federation_id(), SIMP, &creator).unwrap();
    fed.sign(&mut create, &[sponsor]).await.unwrap();
    let mut unbacked = create.clone();
    let mut inflated = initial.clone();
    if let Some(AssetExtension::Bundle(bundle)) = &mut inflated.extension {
        bundle.balances = values(&[(ids[0], 1)]);
    }
    unbacked.outputs[0] = output(inflated);
    assets::sign_creation(&mut unbacked, federation_id(), SIMP, &creator).unwrap();
    fed.sign(&mut unbacked, &[sponsor]).await.unwrap();
    assert_error(fed.process(&unbacked, 0).await, "asset transition");
    assert!(fed.contract(point(&create, 0)).await.is_none());
    let mut unfunded = create.clone();
    unfunded.inputs.clear();
    fed.sign(&mut unfunded, &[]).await.unwrap();
    assert_error(fed.process(&unfunded, 0).await, "unbalanced");
    let mut underfunded = create.clone();
    underfunded.inputs[0] = DynInput::from_typed(
        DUMMY,
        DummyInput {
            amount: Amount::from_msats(705),
            unit: AmountUnit::BITCOIN,
            pub_key: sponsor.public_key(),
        },
    );
    fed.sign(&mut underfunded, &[sponsor]).await.unwrap();
    assert_error(fed.process(&underfunded, 0).await, "unbalanced");
    assert!(
        fed.db
            .with_prefix_module_id(SIMP)
            .0
            .begin_transaction_nc()
            .await
            .get_value(&AssetKey(ids[0]))
            .await
            .is_none()
    );
    fed.process(&create, 0).await.unwrap();
    let authority = point(&create, 0);
    let mut replay = create.clone();
    replay.nonce = rand::random();
    assets::sign_creation(&mut replay, federation_id(), SIMP, &creator).unwrap();
    fed.sign(&mut replay, &[sponsor]).await.unwrap();
    assert_error(fed.process(&replay, 1).await, "namespace has already");
    // Namespace use is checked before the creation signature, which this
    // replay's changed nonce has invalidated.
    let mut stale = create.clone();
    stale.nonce = rand::random();
    fed.sign(&mut stale, &[sponsor]).await.unwrap();
    assert_error(fed.process(&stale, 1).await, "namespace has already");
    // No Simplicity input: forged balances still undergo module-wide
    // validation.
    let (mut forge, sponsor) = sponsored(
        vec![],
        vec![output(
            program
                .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[(ids[0], 1)], &[]))
                .unwrap(),
        )],
    );
    fed.sign(&mut forge, &[sponsor]).await.unwrap();
    assert_error(fed.process(&forge, 1).await, "asset transition");
    // Copying an authority is forbidden even when its owner signs.
    let (mut duplicate, sponsor) = sponsored(
        vec![owner_input(
            &program,
            authority,
            &owner,
            placeholder_signature(),
        )],
        vec![output(initial.clone()), output(initial.clone())],
    );
    sign_owner(&mut duplicate, 0, &program, authority, &owner);
    fed.sign(&mut duplicate, &[owner, sponsor]).await.unwrap();
    assert_error(fed.process(&duplicate, 1).await, "asset transition");
    assert!(fed.contract(authority).await.is_some());
    // Legitimate mint, followed by authority destruction. Creation key cannot
    // recreate the authorities after they leave the UTXO set.
    let (mut issue, sponsor) = sponsored(
        vec![owner_input(
            &program,
            authority,
            &owner,
            placeholder_signature(),
        )],
        vec![
            output(
                program
                    .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[(ids[0], 10)], &[]))
                    .unwrap(),
            ),
            actions(&[(ids[0], 10)], &[]),
        ],
    );
    sign_owner(&mut issue, 0, &program, authority, &owner);
    fed.sign(&mut issue, &[owner, sponsor]).await.unwrap();
    fed.process(&issue, 1).await.unwrap();
    assert_error(fed.process(&replay, 2).await, "namespace has already");
    // Spending the tokens alone grants no issuance authority.
    let token = point(&issue, 0);
    let (mut inflate, sponsor) = sponsored(
        vec![owner_input(
            &program,
            token,
            &owner,
            placeholder_signature(),
        )],
        vec![
            output(
                program
                    .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[(ids[0], 11)], &[]))
                    .unwrap(),
            ),
            actions(&[(ids[0], 1)], &[]),
        ],
    );
    sign_owner(&mut inflate, 0, &program, token, &owner);
    fed.sign(&mut inflate, &[owner, sponsor]).await.unwrap();
    assert_error(fed.process(&inflate, 2).await, "asset transition");
    assert!(fed.contract(token).await.is_some());
    let (mut transfer, sponsor) = sponsored(
        vec![owner_input(
            &program,
            token,
            &owner,
            placeholder_signature(),
        )],
        vec![
            output(
                program
                    .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[(ids[0], 10)], &[]))
                    .unwrap(),
            ),
            actions(&[], &[]),
        ],
    );
    sign_owner(&mut transfer, 0, &program, token, &owner);
    fed.sign(&mut transfer, &[owner, sponsor]).await.unwrap();
    let mut changed_burn = transfer.clone();
    changed_burn.outputs[0] = output(
        program
            .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[(ids[0], 9)], &[]))
            .unwrap(),
    );
    changed_burn.outputs[1] = actions(&[], &[(ids[0], 1)]);
    fed.sign(&mut changed_burn, &[owner, sponsor])
        .await
        .unwrap();
    assert_error(fed.process(&changed_burn, 3).await, "program rejected");
    fed.process(&transfer, 3).await.unwrap();
    let remaining = point(&transfer, 0);
    let (mut burn_all, sponsor) = sponsored(
        vec![owner_input(
            &program,
            remaining,
            &owner,
            placeholder_signature(),
        )],
        vec![actions(&[], &[(ids[0], 10)])],
    );
    sign_owner(&mut burn_all, 0, &program, remaining, &owner);
    fed.sign(&mut burn_all, &[owner, sponsor]).await.unwrap();
    fed.process(&burn_all, 4).await.unwrap();
    assert!(fed.contract(remaining).await.is_none());
    assert_error(fed.process(&replay, 5).await, "namespace has already");
}

#[tokio::test]
async fn asset_signatures_bind_operations_and_foreign_outputs_and_inputs_share_a_snapshot() {
    let fed = Harness::new();
    let owner = key();
    let first = owner_program(owner.x_only_public_key().0).unwrap();
    let later = ContractProgram::compile("fn main() { assert!(jet::eq_64(jet::fm_input_amount(0), 10000)); jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), witness::SIGNATURE); }", arguments([("OWNER", word(owner.x_only_public_key().0.serialize()))])).unwrap();
    let funding = fed
        .fund(vec![
            output(
                first
                    .asset_output(
                        Amount::from_msats(10_000),
                        [0; 32],
                        vec![],
                        bundle(&[], &[]),
                    )
                    .unwrap(),
            ),
            output(
                later
                    .asset_output(
                        Amount::from_msats(10_000),
                        [0; 32],
                        vec![],
                        bundle(&[], &[]),
                    )
                    .unwrap(),
            ),
        ])
        .await;
    let mint = MintRequest::new(Denomination(13));
    let (mut tx, sponsor) = sponsored(
        vec![
            owner_input(&first, point(&funding, 0), &owner, placeholder_signature()),
            owner_input(&later, point(&funding, 1), &owner, placeholder_signature()),
        ],
        vec![mint.output()],
    );
    sign_owner(&mut tx, 0, &first, point(&funding, 0), &owner);
    sign_owner(&mut tx, 1, &later, point(&funding, 1), &owner);
    fed.sign(&mut tx, &[owner, owner, sponsor]).await.unwrap();
    let mut substituted = tx.clone();
    substituted.outputs[0] = MintRequest::new(Denomination(13)).output();
    fed.sign(&mut substituted, &[owner, owner, sponsor])
        .await
        .unwrap();
    assert_error(fed.process(&substituted, 1).await, "program rejected");
    fed.process(&tx, 1).await.unwrap();
    let native = fed
        .fund(vec![output(
            later
                .output(Amount::from_msats(10_000), [0; 32], vec![])
                .unwrap(),
        )])
        .await;
    let (mut spend, sponsor) = sponsored(
        vec![owner_input(
            &later,
            point(&native, 0),
            &owner,
            placeholder_signature(),
        )],
        vec![],
    );
    let signature = signature_value(federation_id(), SIMP, &spend, &owner).unwrap();
    spend.inputs[0] = owner_input(&later, point(&native, 0), &owner, signature);
    fed.sign(&mut spend, &[owner, sponsor]).await.unwrap();
    fed.process(&spend, 2).await.unwrap();
}
