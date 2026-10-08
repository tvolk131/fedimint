use bitcoin::hashes::Hash;
use fedimint_core::TransactionId;
use fedimint_core::secp256k1::{SECP256K1, SecretKey};
use fedimint_core::transaction::TransactionSignature;

use super::*;
use crate::compiler::witnesses;

#[test]
fn finalization_checks_the_combined_resource_budget_before_submission() {
    let owner = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[1; 32]).unwrap());
    let program = crate::market::owner_program(owner.x_only_public_key().0).unwrap();
    let authorization = Authorization {
        federation: FederationId(Hash::all_zeros()),
        module: 4,
        spends: vec![],
        creations: vec![],
        receipt: None,
        max_fee: None,
        snapshot: Default::default(),
    };
    for count in [32, 38] {
        let tx = Transaction {
            inputs: (0..count)
                .map(|index| {
                    DynInput::from_typed(
                        if index % 2 == 0 { 4 } else { 7 },
                        program
                            .input(
                                OutPoint {
                                    txid: TransactionId::from_raw_hash(Hash::all_zeros()),
                                    out_idx: index,
                                },
                                owner.public_key(),
                                witnesses([("SIGNATURE", crate::placeholder_signature())]),
                            )
                            .unwrap(),
                    )
                })
                .collect(),
            outputs: vec![],
            nonce: [0; 8],
            signatures: TransactionSignature::NaiveMultisig(vec![]),
        };
        let result = authorization.verify_finalized(&tx);
        if count == 32 {
            result.unwrap();
        } else {
            assert!(result.unwrap_err().to_string().contains("resource limit"));
        }
    }
}

#[test]
fn final_funding_fee_cannot_exceed_the_attempts_remaining_budget() {
    let authorization = Authorization {
        federation: FederationId(Hash::all_zeros()),
        module: 4,
        spends: vec![],
        creations: vec![],
        receipt: None,
        max_fee: Some(fedimint_core::Amount::from_msats(317)),
        snapshot: Default::default(),
    };
    // A point-in-time quote is not authority to spend more after note inventory
    // changes. The finalizer checks the real funded transaction, including dust.
    for fee in [0, 316, 317, 318, 10_000] {
        assert_eq!(
            authorization
                .verify_fees(&fedimint_core::module::Amounts::new_bitcoin(
                    fedimint_core::Amount::from_msats(fee)
                ))
                .is_ok(),
            fee <= 317
        );
    }
}

fn pruning_authorization(source: &str) -> (Authorization, Transaction) {
    use crate::compiler::{U256, Value, ValueConstructible, arguments};
    let key = Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[7; 32]).unwrap());
    let program = ContractProgram::compile(
        source,
        arguments([(
            "OWNER",
            Value::u256(U256::from_byte_array(key.x_only_public_key().0.serialize())),
        )]),
    )
    .unwrap();
    let point = OutPoint {
        txid: TransactionId::from_raw_hash(Hash::all_zeros()),
        out_idx: 0,
    };
    let output = program
        .output(fedimint_core::Amount::from_sats(10), [0; 32], vec![])
        .unwrap();
    let input = program
        .input(
            point,
            key.public_key(),
            witnesses([("SIGNATURE", crate::placeholder_signature())]),
        )
        .unwrap();
    let authorization = Authorization {
        federation: FederationId(Hash::all_zeros()),
        module: 4,
        spends: vec![PreparedSpend {
            outpoint: point,
            version: 0,
            key,
            program,
            witnesses: witnesses([]),
            signature_witness: Some("SIGNATURE".to_owned()),
        }],
        creations: vec![],
        receipt: None,
        max_fee: None,
        snapshot: crate::pruning::PruningSnapshot {
            session_index: 3,
            block_count: 10,
            contracts: [(
                point,
                common::StoredContract {
                    output,
                    creation_session: 1,
                    creation_block_count: 5,
                },
            )]
            .into(),
        },
    };
    let mut tx = Transaction {
        inputs: vec![DynInput::from_typed(4, input)],
        outputs: vec![],
        nonce: [0; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    };
    for (index, input) in authorization.pruned_inputs(&tx).unwrap() {
        tx.inputs[index] = input;
    }
    (authorization, tx)
}

#[test]
fn pruning_precedes_funding_and_final_signatures_still_authorize_the_real_intent() {
    let (authorization, mut tx) = pruning_authorization(
        "fn main() { jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), witness::SIGNATURE); match jet::lt_64(jet::fm_session_index(), 5) { true => {}, false => { assert!(jet::eq_64(jet::fm_block_count(), 20)); }, } }",
    );
    let draft = tx.inputs[0].clone();
    tx.nonce = [9; 8];
    for (index, input) in authorization.finalize_inputs(&tx).unwrap() {
        tx.inputs[index] = input;
    }
    let input = tx.inputs[0]
        .as_any()
        .downcast_ref::<common::ContractInput>()
        .unwrap();
    let env = authorization
        .snapshot
        .environment(authorization.federation, 4, &tx, 0)
        .unwrap();
    assert!(common::runtime::execute(input, &env).is_ok());
    let draft = draft
        .as_any()
        .downcast_ref::<common::ContractInput>()
        .unwrap();
    assert_eq!(
        common::runtime::input_fee(draft),
        common::runtime::input_fee(input)
    );
    assert!(
        common::runtime::execute(draft, &env).is_err(),
        "draft signature must not authorize the final nonce"
    );
    assert_eq!(
        common::runtime::decode_program(input)
            .unwrap()
            .cmr()
            .to_byte_array(),
        env.current.cmr
    );
}

#[test]
fn a_funding_dependent_branch_cannot_silently_change_pruning_fees() {
    let (authorization, mut tx) = pruning_authorization(
        "fn main() { let signature: Signature = witness::SIGNATURE; jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), signature); match jet::eq_32(jet::fm_output_count(), 0) { true => {}, false => { jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), signature); }, } }",
    );
    tx.outputs.push(DynOutput::from_typed(
        7,
        common::ContractOutput::action_output(Default::default()),
    ));
    assert!(
        authorization
            .finalize_inputs(&tx)
            .unwrap_err()
            .to_string()
            .contains("funding changed pruning fees")
    );
    // The low-level fully funded path is still expressible; it simply needs
    // funding selected for this final representation.
    let inputs = authorization.pruned_inputs(&tx).unwrap();
    for (index, input) in inputs {
        tx.inputs[index] = input;
    }
    let input = tx.inputs[0]
        .as_any()
        .downcast_ref::<common::ContractInput>()
        .unwrap();
    assert!(
        common::runtime::execute(
            input,
            &authorization
                .snapshot
                .environment(authorization.federation, 4, &tx, 0)
                .unwrap()
        )
        .is_ok()
    );
}

#[test]
fn version_restrictions_apply_to_revealed_code_after_pruning() {
    let (mut authorization, tx) = pruning_authorization(
        "fn main() { jet::bip_0340_verify((param::OWNER, jet::fm_sig_hash_all()), witness::SIGNATURE); match jet::lt_64(jet::fm_session_index(), 5) { true => {}, false => { assert!(jet::eq_32(jet::fm_input_version(0), 0)); }, } }",
    );
    // The v1-only jet is hidden and therefore is not part of the submitted v0
    // program's allowlist check, exactly as in guardian validation.
    assert!(authorization.finalize_inputs(&tx).is_ok());
    authorization.snapshot.session_index = 6;
    assert!(authorization.pruned_inputs(&tx).is_err());
}
