mod clocks;
mod context;
mod instances;
mod market_hardening;
mod network;
mod resources;

use fedimint_core::secp256k1::Message;
use fedimint_simplicity_client::{assets, market};
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

struct Market {
    fed: Harness,
    terms: market::BinaryMarket,
    program: ContractProgram,
    oracle: Keypair,
    operator: Keypair,
    vault: OutPoint,
}
impl Market {
    async fn new() -> Self {
        let fed = Harness::new();
        let creator = key();
        let oracle = key();
        let operator = key();
        let (creation, ids) =
            assets::creation(federation_id(), SIMP, &creator, vec![0, 0]).unwrap();
        let terms = market::BinaryMarket {
            federation: federation_id(),
            module: SIMP,
            yes: ids[0],
            no: ids[1],
            event: [1; 32],
            rules: [2; 32],
            oracle: oracle.x_only_public_key().0,
            resolution_start: 5,
            deadline: 10,
        };
        let program = terms.program().unwrap();
        let initial = program
            .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[], &ids))
            .unwrap();
        let (mut tx, sponsor) = sponsored(
            vec![],
            vec![
                output(initial),
                output(
                    assets::action_output(AssetActions {
                        creations: vec![creation],
                        ..Default::default()
                    })
                    .unwrap(),
                ),
            ],
        );
        assets::sign_creation(&mut tx, federation_id(), SIMP, &creator).unwrap();
        sign_transaction(&mut tx, &[sponsor]).unwrap();
        fed.process(&tx, 0).await.unwrap();
        let record = fed
            .db
            .with_prefix_module_id(SIMP)
            .0
            .begin_transaction_nc()
            .await
            .get_value(&AssetKey(ids[0]))
            .await
            .unwrap();
        let no_record = fed
            .db
            .with_prefix_module_id(SIMP)
            .0
            .begin_transaction_nc()
            .await
            .get_value(&AssetKey(ids[1]))
            .await
            .unwrap();
        terms.validate_genesis(&record, &no_record).unwrap();
        let mut fake_record = record.clone();
        fake_record.authority_cmr = [0; 32];
        assert!(terms.validate_genesis(&fake_record, &no_record).is_err());
        assert_eq!(record.authority_cmr, program.cmr());
        assert_eq!(record.authority_outpoint, point(&tx, 0));
        assert!(
            fed.contract(point(&tx, 1)).await.is_none(),
            "actions must not create a UTXO"
        );
        Self {
            fed,
            terms,
            program,
            oracle,
            operator,
            vault: point(&tx, 0),
        }
    }
    fn vault_output(&self, msats: u64, state: u8) -> DynOutput {
        output(
            self.program
                .asset_output(
                    Amount::from_msats(msats),
                    market::state(state).unwrap(),
                    vec![],
                    bundle(&[], &[self.terms.yes, self.terms.no]),
                )
                .unwrap(),
        )
    }
    fn input(&self, action: u8, outcome: u8, oracle: &Keypair) -> DynInput {
        let message = Message::from_digest(self.terms.attestation_message(outcome.max(1)).unwrap());
        let signature = Value::byte_array(
            *SECP256K1
                .sign_schnorr_no_aux_rand(&message, oracle)
                .as_ref(),
        );
        DynInput::from_typed(
            SIMP,
            self.program
                .input(
                    self.vault,
                    self.operator.public_key(),
                    witnesses([
                        ("ACTION", Value::u8(action)),
                        ("OUTCOME", Value::u8(outcome)),
                        ("ORACLE_SIGNATURE", signature),
                    ]),
                )
                .unwrap(),
        )
    }
    async fn issue(&mut self, owner: &Keypair, quantity: u64) -> OutPoint {
        let collateral = self
            .fed
            .contract(self.vault)
            .await
            .unwrap()
            .output
            .amount
            .msats;
        let owner_program = market::owner_program(owner.x_only_public_key().0).unwrap();
        let token_output = owner_program
            .asset_output(
                Amount::ZERO,
                [0; 32],
                vec![],
                bundle(
                    &[(self.terms.yes, quantity), (self.terms.no, quantity)],
                    &[],
                ),
            )
            .unwrap();
        // Fund collateral from an actual mint note, with separate fee
        // sponsorship.
        let request = MintRequest::new(Denomination(20));
        let issue = self.fed.fund(vec![request.output()]).await;
        let note = self.fed.note(&request, point(&issue, 0)).await;
        let (mut tx, sponsor) = sponsored(
            vec![
                self.input(0, 1, &self.oracle),
                DynInput::from_typed(MINT, MintInput::new_v0(note)),
            ],
            vec![
                self.vault_output(collateral + quantity * 1000, 0),
                output(token_output),
                actions(
                    &[(self.terms.yes, quantity), (self.terms.no, quantity)],
                    &[],
                ),
            ],
        );
        sign_transaction(&mut tx, &[self.operator, request.key, sponsor]).unwrap();
        self.fed.process(&tx, 1).await.unwrap();
        self.vault = point(&tx, 0);
        point(&tx, 1)
    }
}

#[tokio::test]
async fn binary_market_trades_recombines_resolves_and_redeems_to_ecash() {
    let mut market = Market::new().await;
    let alice = key();
    let bob = key();
    let alice_program = market::owner_program(alice.x_only_public_key().0).unwrap();
    let bob_program = market::owner_program(bob.x_only_public_key().0).unwrap();
    let yes = market.terms.yes;
    let no = market.terms.no;
    let original = market.issue(&alice, 64).await;
    // Recombine 16 pairs; retain 48 of each. Owner signature approves payout.
    let alice_change = alice_program
        .asset_output(
            Amount::ZERO,
            [0; 32],
            vec![],
            bundle(&[(yes, 48), (no, 48)], &[]),
        )
        .unwrap();
    let refund = alice_program
        .asset_output(
            Amount::from_msats(16_000),
            [0; 32],
            vec![],
            bundle(&[], &[]),
        )
        .unwrap();
    let (mut merge, sponsor) = sponsored(
        vec![
            market.input(1, 1, &market.oracle),
            owner_input(&alice_program, original, &alice, placeholder_signature()),
        ],
        vec![
            market.vault_output(48_000, 0),
            output(alice_change),
            output(refund),
            actions(&[], &[(yes, 16), (no, 16)]),
        ],
    );
    sign_owner(&mut merge, 1, &alice_program, original, &alice);
    sign_transaction(&mut merge, &[market.operator, alice, sponsor]).unwrap();
    market.fed.process(&merge, 2).await.unwrap();
    market.vault = point(&merge, 0);
    let positions = point(&merge, 1);
    // Bob buys 16 YES for ecash. The vault is neither consumed nor changed.
    let buyer_request = MintRequest::new(Denomination(16));
    let payment_request = MintRequest::new(Denomination(15));
    let issue = market.fed.fund(vec![buyer_request.output()]).await;
    let note = market.fed.note(&buyer_request, point(&issue, 0)).await;
    let (mut trade, sponsor) = sponsored(
        vec![
            owner_input(&alice_program, positions, &alice, placeholder_signature()),
            DynInput::from_typed(MINT, MintInput::new_v0(note)),
        ],
        vec![
            output(
                bob_program
                    .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[(yes, 16)], &[]))
                    .unwrap(),
            ),
            output(
                alice_program
                    .asset_output(
                        Amount::ZERO,
                        [0; 32],
                        vec![],
                        bundle(&[(yes, 32), (no, 48)], &[]),
                    )
                    .unwrap(),
            ),
            payment_request.output(),
        ],
    );
    sign_owner(&mut trade, 0, &alice_program, positions, &alice);
    sign_transaction(&mut trade, &[alice, buyer_request.key, sponsor]).unwrap();
    market.fed.process(&trade, 3).await.unwrap();
    assert!(market.fed.contract(market.vault).await.is_some());
    let bob_position = point(&trade, 0);
    assert_eq!(
        market
            .fed
            .note(&payment_request, point(&trade, 2))
            .await
            .amount(),
        Amount::from_msats(1 << 15)
    );
    // Oracle resolution is permissionless, but only in its committed window.
    let (mut resolve, sponsor) = sponsored(
        vec![market.input(2, 1, &market.oracle)],
        vec![market.vault_output(48_000, 1)],
    );
    sign_transaction(&mut resolve, &[market.operator, sponsor]).unwrap();
    assert_error(market.fed.process(&resolve, 4).await, "program rejected");
    market.fed.vote(5).await;
    let mut bad = resolve.clone();
    bad.inputs[0] = market.input(2, 1, &key());
    sign_transaction(&mut bad, &[market.operator, sponsor]).unwrap();
    assert_error(market.fed.process(&bad, 5).await, "program rejected");
    market.fed.process(&resolve, 5).await.unwrap();
    let old_vault = market.vault;
    market.vault = point(&resolve, 0);
    let (mut equivocate, sponsor) = sponsored(
        vec![market.input(2, 2, &market.oracle)],
        vec![market.vault_output(48_000, 2)],
    );
    sign_transaction(&mut equivocate, &[market.operator, sponsor]).unwrap();
    assert_error(market.fed.process(&equivocate, 6).await, "program rejected");
    assert!(market.fed.contract(old_vault).await.is_none());
    // Bob redeems his independently held YES, receiving a real ecash note plus
    // native change. His signature binds both payout destinations.
    let redemption = MintRequest::new(Denomination(13));
    let (mut redeem, sponsor) = sponsored(
        vec![
            market.input(3, 1, &market.oracle),
            owner_input(&bob_program, bob_position, &bob, placeholder_signature()),
        ],
        vec![
            market.vault_output(32_000, 1),
            redemption.output(),
            output(
                bob_program
                    .asset_output(
                        Amount::from_msats(16_000 - (1 << 13)),
                        [0; 32],
                        vec![],
                        bundle(&[], &[]),
                    )
                    .unwrap(),
            ),
            actions(&[], &[(yes, 16)]),
        ],
    );
    sign_owner(&mut redeem, 1, &bob_program, bob_position, &bob);
    sign_transaction(&mut redeem, &[market.operator, bob, sponsor]).unwrap();
    market.fed.process(&redeem, 6).await.unwrap();
    assert_error(market.fed.process(&redeem, 6).await, "already spent");
    let note = market.fed.note(&redemption, point(&redeem, 1)).await;
    let (mut spend_note, sponsor) = sponsored(
        vec![DynInput::from_typed(MINT, MintInput::new_v0(note))],
        vec![output(
            bob_program
                .output(Amount::from_msats(1 << 13), [0; 32], vec![])
                .unwrap(),
        )],
    );
    sign_transaction(&mut spend_note, &[redemption.key, sponsor]).unwrap();
    market.fed.process(&spend_note, 7).await.unwrap();
}

#[tokio::test]
async fn namespace_authority_and_conservation_cannot_be_bypassed() {
    let fed = Harness::new();
    let creator = key();
    let owner = key();
    let program = market::owner_program(owner.x_only_public_key().0).unwrap();
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
    sign_transaction(&mut create, &[sponsor]).unwrap();
    assert_error(fed.process(&create, 0).await, "creation authorization");
    assets::sign_creation(&mut create, federation_id(), SIMP, &creator).unwrap();
    sign_transaction(&mut create, &[sponsor]).unwrap();
    let mut unbacked = create.clone();
    let mut inflated = initial.clone();
    if let Some(AssetExtension::Bundle(bundle)) = &mut inflated.extension {
        bundle.balances = values(&[(ids[0], 1)]);
    }
    unbacked.outputs[0] = output(inflated);
    assets::sign_creation(&mut unbacked, federation_id(), SIMP, &creator).unwrap();
    sign_transaction(&mut unbacked, &[sponsor]).unwrap();
    assert_error(fed.process(&unbacked, 0).await, "asset transition");
    assert!(fed.contract(point(&create, 0)).await.is_none());
    let mut unfunded = create.clone();
    unfunded.inputs.clear();
    sign_transaction(&mut unfunded, &[]).unwrap();
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
    sign_transaction(&mut underfunded, &[sponsor]).unwrap();
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
    sign_transaction(&mut replay, &[sponsor]).unwrap();
    assert_error(fed.process(&replay, 1).await, "namespace has already");
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
    sign_transaction(&mut forge, &[sponsor]).unwrap();
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
    sign_transaction(&mut duplicate, &[owner, sponsor]).unwrap();
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
    sign_transaction(&mut issue, &[owner, sponsor]).unwrap();
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
    sign_transaction(&mut inflate, &[owner, sponsor]).unwrap();
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
    sign_transaction(&mut transfer, &[owner, sponsor]).unwrap();
    let mut changed_burn = transfer.clone();
    changed_burn.outputs[0] = output(
        program
            .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[(ids[0], 9)], &[]))
            .unwrap(),
    );
    changed_burn.outputs[1] = actions(&[], &[(ids[0], 1)]);
    sign_transaction(&mut changed_burn, &[owner, sponsor]).unwrap();
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
    sign_transaction(&mut burn_all, &[owner, sponsor]).unwrap();
    fed.process(&burn_all, 4).await.unwrap();
    assert!(fed.contract(remaining).await.is_none());
    assert_error(fed.process(&replay, 5).await, "namespace has already");
}

#[tokio::test]
async fn market_rejects_unbacked_issuance_and_overflow_without_consuming_authorities() {
    let market = Market::new().await;
    let owner = key();
    let program = market::owner_program(owner.x_only_public_key().0).unwrap();
    for (quantity, collateral) in [(1u64, 0), (u64::MAX / 1000 + 1, 384)] {
        let (mut tx, sponsor) = sponsored(
            vec![market.input(0, 1, &market.oracle)],
            vec![
                market.vault_output(collateral, 0),
                output(
                    program
                        .asset_output(
                            Amount::ZERO,
                            [0; 32],
                            vec![],
                            bundle(
                                &[(market.terms.yes, quantity), (market.terms.no, quantity)],
                                &[],
                            ),
                        )
                        .unwrap(),
                ),
                actions(
                    &[(market.terms.yes, quantity), (market.terms.no, quantity)],
                    &[],
                ),
            ],
        );
        sign_transaction(&mut tx, &[market.operator, sponsor]).unwrap();
        assert_error(market.fed.process(&tx, 1).await, "program rejected");
        assert!(market.fed.contract(market.vault).await.is_some());
        assert!(market.fed.contract(point(&tx, 1)).await.is_none());
    }
}

#[tokio::test]
async fn no_invalid_and_timeout_settlement_pay_current_token_holders() {
    // Oracle NO, oracle INVALID, and an INVALID timeout without a valid oracle.
    for (outcome, timeout) in [(2, false), (3, false), (3, true)] {
        let mut market = Market::new().await;
        let owner = key();
        let program = market::owner_program(owner.x_only_public_key().0).unwrap();
        let positions = market.issue(&owner, 8).await;
        market.fed.vote(if timeout { 10 } else { 5 }).await;
        let wrong_oracle = key();
        let oracle = if timeout {
            &wrong_oracle
        } else {
            &market.oracle
        };
        let (mut resolve, sponsor) = sponsored(
            vec![market.input(2, outcome, oracle)],
            vec![market.vault_output(8_000, outcome)],
        );
        sign_transaction(&mut resolve, &[market.operator, sponsor]).unwrap();
        market.fed.process(&resolve, 2).await.unwrap();
        market.vault = point(&resolve, 0);
        let yes = market.terms.yes;
        let no = market.terms.no;
        // Redeem all NO; retain YES. NO pays 1000/unit, INVALID 500/unit.
        let payout = if outcome == 2 { 8_000 } else { 4_000 };
        let (mut redeem, sponsor) = sponsored(
            vec![
                market.input(3, outcome, &market.oracle),
                owner_input(&program, positions, &owner, placeholder_signature()),
            ],
            vec![
                market.vault_output(8_000 - payout, outcome),
                output(
                    program
                        .asset_output(
                            Amount::from_msats(payout),
                            [0; 32],
                            vec![],
                            bundle(&[(yes, 8)], &[]),
                        )
                        .unwrap(),
                ),
                actions(&[], &[(no, 8)]),
            ],
        );
        sign_owner(&mut redeem, 1, &program, positions, &owner);
        sign_transaction(&mut redeem, &[market.operator, owner, sponsor]).unwrap();
        // Overpay by one msat: conservation still holds but the vault rejects
        // it.
        let mut overpay = redeem.clone();
        overpay.outputs[0] = market.vault_output((8_000 - payout).saturating_sub(1), outcome);
        if payout < 8_000 {
            sign_owner(&mut overpay, 1, &program, positions, &owner);
            sign_transaction(&mut overpay, &[market.operator, owner, sponsor]).unwrap();
            assert_error(market.fed.process(&overpay, 3).await, "program rejected");
        }
        market.fed.process(&redeem, 3).await.unwrap();
        assert_eq!(
            market
                .fed
                .contract(point(&redeem, 1))
                .await
                .unwrap()
                .output
                .amount
                .msats,
            payout
        );
    }
}

#[tokio::test]
async fn asset_signatures_bind_operations_and_foreign_outputs_and_inputs_share_a_snapshot() {
    let fed = Harness::new();
    let owner = key();
    let first = market::owner_program(owner.x_only_public_key().0).unwrap();
    let later = ContractProgram::compile("fn main() { assert!(jet::eq_64(jet::fm_input_amount(0), 10000)); jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), witness::SIGNATURE); }", arguments([("OWNER", market::word(owner.x_only_public_key().0.serialize()))])).unwrap();
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
    sign_transaction(&mut tx, &[owner, owner, sponsor]).unwrap();
    let mut substituted = tx.clone();
    substituted.outputs[0] = MintRequest::new(Denomination(13)).output();
    sign_transaction(&mut substituted, &[owner, owner, sponsor]).unwrap();
    assert_error(fed.process(&substituted, 1).await, "program rejected");
    fed.process(&tx, 1).await.unwrap();
    // The same new context jet is never enabled for a legacy contract.
    let legacy = fed
        .fund(vec![output(
            later
                .output(Amount::from_msats(10_000), [0; 32], vec![])
                .unwrap(),
        )])
        .await;
    let (mut spend, sponsor) = sponsored(
        vec![owner_input(
            &later,
            point(&legacy, 0),
            &owner,
            placeholder_signature(),
        )],
        vec![],
    );
    let signature = signature_value(federation_id(), SIMP, &spend, &owner).unwrap();
    spend.inputs[0] = owner_input(&later, point(&legacy, 0), &owner, signature);
    sign_transaction(&mut spend, &[owner, sponsor]).unwrap();
    assert_error(fed.process(&spend, 2).await, "execution version");
}
