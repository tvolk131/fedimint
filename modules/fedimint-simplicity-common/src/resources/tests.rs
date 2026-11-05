use std::sync::Arc;

use bitcoin::hashes::Hash;
use fedimint_core::core::{DynInput, DynOutput};
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey};
use fedimint_core::transaction::TransactionSignature;
use fedimint_core::{Amount, OutPoint, TransactionId};
use simplicity::ConstructNode;
use simplicity::node::CoreConstructible;

use super::*;
use crate::assets::{AssetActions, AssetBundle, AssetCreation, AssetExtension};

mod structure;

fn input(program: Vec<u8>) -> ContractInput {
    ContractInput {
        outpoint: OutPoint {
            txid: TransactionId::from_raw_hash(Hash::all_zeros()),
            out_idx: 0,
        },
        claim_key: Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[1; 32]).unwrap())
            .public_key(),
        program,
        witness: vec![],
    }
}

fn transaction(inputs: Vec<DynInput>, outputs: Vec<DynOutput>) -> Transaction {
    Transaction {
        inputs,
        outputs,
        nonce: [0; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    }
}

fn units(mut count: usize) -> Vec<u8> {
    simplicity::types::Context::with_context(|ctx| {
        let mut power: Arc<ConstructNode> = Arc::unit(&ctx);
        let mut result = None;
        while count != 0 {
            if count & 1 != 0 {
                result = Some(match result {
                    None => power.clone(),
                    Some(previous) => Arc::comp(&previous, &power).unwrap(),
                });
            }
            count >>= 1;
            power = Arc::comp(&power, &power).unwrap();
        }
        result
            .unwrap()
            .finalize_types()
            .unwrap()
            .to_vec_without_witness()
    })
}

fn creations(count: usize, destination: u32) -> ContractOutput {
    ContractOutput {
        version: 1,
        amount: Amount::ZERO,
        cmr: [0; 32],
        state: [0; 32],
        recovery: vec![],
        extension: Some(AssetExtension::Actions(AssetActions {
            creations: (0..count)
                .map(|index| AssetCreation {
                    key: Keypair::from_secret_key(
                        SECP256K1,
                        &SecretKey::from_slice(&[(index + 1) as u8; 32]).unwrap(),
                    )
                    .public_key(),
                    authority_outputs: vec![destination],
                    signature: Signature::from_slice(&[0; 64]).unwrap(),
                })
                .collect(),
            ..Default::default()
        })),
    }
}

fn bundle() -> ContractOutput {
    ContractOutput {
        version: 1,
        amount: fedimint_core::Amount::ZERO,
        cmr: [0; 32],
        state: [0; 32],
        recovery: vec![],
        extension: Some(AssetExtension::Bundle(AssetBundle::default())),
    }
}

#[test]
fn cost_is_exact_inclusive_and_shared_across_instances() {
    // Unit composition costs (2*n - 1)*100. These small encodings have
    // individually acceptable bounds whose sum is exactly the shared limit.
    for (tail, expected) in [
        (1808, Ok(())),
        (1809, Ok(())),
        (1810, Err(ContractError::Limit)),
    ] {
        let first = input(units(8192));
        let mut second = input(units(tail));
        second.outpoint.out_idx = 1;
        let cost = runtime::decode_program(&first).unwrap().bounds().cost
            + runtime::decode_program(&second).unwrap().bounds().cost;
        assert_eq!(
            cost,
            Cost::from_milliweight(2_000_000 + (tail as u32 - 1808) * 200 - 200)
        );
        for instances in [[4, 4], [4, 7], [7, 4]] {
            let tx = transaction(
                vec![
                    DynInput::from_typed(instances[0], first.clone()),
                    DynInput::from_typed(instances[1], second.clone()),
                ],
                vec![],
            );
            assert_eq!(check_transaction(&tx), expected);
        }
    }
}

#[test]
fn combined_bytes_and_individual_lengths_are_checked_before_decoding() {
    let mut first = input(vec![]);
    first.witness = vec![0; MAX_WITNESS_BYTES];
    let second = first.clone();
    // Exactly 16 KiB reaches decoding, where this malformed program fails.
    let tx = transaction(
        vec![
            DynInput::from_typed(4, first.clone()),
            DynInput::from_typed(7, second.clone()),
        ],
        vec![],
    );
    assert_eq!(check_transaction(&tx), Err(ContractError::Program));
    first.program.push(0);
    let mut tx = transaction(
        vec![
            DynInput::from_typed(4, first.clone()),
            DynInput::from_typed(7, second),
        ],
        vec![],
    );
    for _ in 0..2 {
        assert_eq!(check_transaction(&tx), Err(ContractError::Limit));
        tx.inputs.reverse();
    }
    // A later oversized input must also fail before decoding the first one.
    for (program, witness) in [
        (vec![0; MAX_PROGRAM_BYTES + 1], vec![]),
        (vec![], vec![0; MAX_WITNESS_BYTES + 1]),
    ] {
        let mut oversized = input(program);
        oversized.witness = witness;
        let tx = transaction(
            vec![
                DynInput::from_typed(4, input(vec![])),
                DynInput::from_typed(7, oversized),
            ],
            vec![],
        );
        assert_eq!(check_transaction(&tx), Err(ContractError::Limit));
    }
}

#[test]
fn creation_signatures_share_the_execution_budget_including_output_only_instances() {
    let tx = transaction(
        vec![],
        vec![
            DynOutput::from_typed(4, creations(10, 2)),
            DynOutput::from_typed(7, creations(10, 3)),
            DynOutput::from_typed(4, bundle()),
            DynOutput::from_typed(7, bundle()),
        ],
    );
    assert_eq!(check_transaction(&tx), Ok(()));
    let mut over = tx.clone();
    over.outputs[1] = DynOutput::from_typed(7, creations(11, 3));
    assert_eq!(check_transaction(&over), Err(ContractError::Limit));
    // Even the minimum valid input costs something: there is no separate
    // allowance for programs after spending the entire budget on creation.
    let mut over = tx;
    over.inputs.push(DynInput::from_typed(9, input(units(1))));
    assert_eq!(check_transaction(&over), Err(ContractError::Limit));
    for (count, expected) in [(500, Ok(())), (501, Err(ContractError::Limit))] {
        assert_eq!(
            check_transaction(&transaction(
                vec![DynInput::from_typed(4, input(units(count)))],
                vec![
                    DynOutput::from_typed(7, creations(19, 1)),
                    DynOutput::from_typed(7, bundle())
                ]
            )),
            expected
        );
    }
}

#[test]
fn counted_payload_excludes_recovery_and_counts_every_repeated_program() {
    let program = input(units(8192));
    assert_eq!(
        check_transaction(&transaction(
            vec![DynInput::from_typed(4, program.clone())],
            vec![]
        )),
        Ok(())
    );
    assert_eq!(
        check_transaction(&transaction(
            vec![
                DynInput::from_typed(4, program.clone()),
                DynInput::from_typed(7, program)
            ],
            vec![]
        )),
        Err(ContractError::Limit)
    );
    let mut output = bundle();
    output.recovery = vec![0; crate::MAX_RECOVERY_BYTES];
    // Recovery bytes retain their separate bounds and outer transaction limit.
    assert_eq!(
        check_transaction(&transaction(
            vec![],
            vec![DynOutput::from_typed(4, output); MAX_CONTRACTS]
        )),
        Ok(())
    );
}

#[test]
fn truncated_and_mutated_encodings_cannot_panic_resource_verification() {
    let program = units(8192);
    for len in 0..program.len() {
        assert!(
            check_transaction(&transaction(
                vec![DynInput::from_typed(4, input(program[..len].to_vec()))],
                vec![]
            ))
            .is_err()
        );
    }
    // Exercise declarations, sharing references and combinator tags around a
    // known compact DAG. A mutation can legitimately encode another program.
    for bit in 0..program.len() * 8 {
        let mut changed = program.clone();
        changed[bit / 8] ^= 1 << (bit % 8);
        let _ = check_transaction(&transaction(
            vec![DynInput::from_typed(4, input(changed))],
            vec![],
        ));
    }
}
