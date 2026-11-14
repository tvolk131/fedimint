use std::sync::Arc;

use bitcoin::hashes::Hash;
use fedimint_core::core::{DynInput, DynOutput};
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey};
use fedimint_core::transaction::TransactionSignature;
use fedimint_core::{OutPoint, TransactionId};
use simplicity::ConstructNode;
use simplicity::node::CoreConstructible;

use super::*;
use crate::assets::{AssetActions, AssetBundle, AssetCreation};

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

fn out(instance: ModuleInstanceId, output: impl Into<SimplicityOutput>) -> DynOutput {
    DynOutput::from_typed(instance, output.into())
}

fn creations(count: usize, destination: u32) -> ActionOutput {
    ActionOutput {
        recovery: vec![],
        actions: AssetActions {
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
        },
    }
}

fn bundle() -> ContractOutput {
    ContractOutput {
        version: 1,
        amount: fedimint_core::Amount::ZERO,
        cmr: [0; 32],
        state: [0; 32],
        recovery: vec![],
        assets: AssetBundle::default(),
    }
}

#[test]
fn cost_is_exact_inclusive_and_per_instance() {
    // Unit composition costs (2*n - 1)*100. These small encodings have
    // individually acceptable bounds whose sum is exactly one instance's limit.
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
        let spend = |instances: &[ModuleInstanceId]| {
            transaction(
                instances
                    .iter()
                    .zip([&first, &second].into_iter().cycle())
                    .map(|(instance, input)| DynInput::from_typed(*instance, input.clone()))
                    .collect(),
                vec![],
            )
        };
        for instance in [4, 7] {
            assert_eq!(check_transaction(&spend(&[instance, instance])), expected);
        }
        // Split across instances, neither instance comes near its budget.
        for instances in [[4, 7], [7, 4]] {
            assert_eq!(check_transaction(&spend(&instances)), Ok(()));
        }
        // Each instance may spend up to its own budget in the same transaction.
        assert_eq!(check_transaction(&spend(&[4, 4, 7, 7])), expected);
    }
}

#[test]
fn combined_bytes_per_instance_and_individual_lengths_are_checked_before_decoding() {
    let mut first = input(vec![]);
    first.witness = vec![0; MAX_WITNESS_BYTES];
    let mut second = first.clone();
    second.outpoint.out_idx = 1;
    // Exactly 16 KiB in one instance reaches decoding, where this malformed
    // program fails.
    let tx = transaction(
        vec![
            DynInput::from_typed(4, first.clone()),
            DynInput::from_typed(4, second.clone()),
        ],
        vec![],
    );
    assert_eq!(check_transaction(&tx), Err(ContractError::Program));
    first.program.push(0);
    for instances in [[4, 7], [7, 4]] {
        let mut tx = transaction(
            vec![
                DynInput::from_typed(instances[0], first.clone()),
                DynInput::from_typed(instances[1], second.clone()),
            ],
            vec![],
        );
        for _ in 0..2 {
            // Bytes are counted per instance, so split inputs reach decoding.
            assert_eq!(check_transaction(&tx), Err(ContractError::Program));
            tx.inputs.reverse();
        }
    }
    let mut tx = transaction(
        vec![
            DynInput::from_typed(4, first.clone()),
            DynInput::from_typed(4, second),
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
fn creation_signatures_share_their_instance_execution_budget_including_output_only_instances() {
    let tx = transaction(
        vec![],
        vec![
            out(4, creations(20, 2)),
            out(7, creations(20, 3)),
            out(4, bundle()),
            out(7, bundle()),
        ],
    );
    // Each instance spends exactly its own whole budget on creations.
    assert_eq!(check_transaction(&tx), Ok(()));
    for (index, instance, destination) in [(0, 4, 2), (1, 7, 3)] {
        let mut over = tx.clone();
        over.outputs[index] = out(instance, creations(21, destination));
        assert_eq!(check_transaction(&over), Err(ContractError::Limit));
    }
    // Even the minimum valid input costs something: there is no separate
    // allowance for programs after spending the entire budget on creation.
    for instance in [4, 7] {
        let mut over = tx.clone();
        over.inputs
            .push(DynInput::from_typed(instance, input(units(1))));
        assert_eq!(check_transaction(&over), Err(ContractError::Limit));
    }
    // Another instance's budget is untouched.
    let mut other = tx;
    other.inputs.push(DynInput::from_typed(9, input(units(1))));
    assert_eq!(check_transaction(&other), Ok(()));
    for (count, expected) in [(500, Ok(())), (501, Err(ContractError::Limit))] {
        let spend = |instance| {
            transaction(
                vec![DynInput::from_typed(instance, input(units(count)))],
                vec![out(7, creations(19, 1)), out(7, bundle())],
            )
        };
        assert_eq!(check_transaction(&spend(7)), expected);
        assert_eq!(check_transaction(&spend(4)), Ok(()));
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
    let mut repeated = program.clone();
    repeated.outpoint.out_idx = 1;
    assert_eq!(
        check_transaction(&transaction(
            vec![
                DynInput::from_typed(4, program.clone()),
                DynInput::from_typed(4, repeated)
            ],
            vec![]
        )),
        Err(ContractError::Limit)
    );
    // Another instance counts its own copy against its own budget.
    assert_eq!(
        check_transaction(&transaction(
            vec![
                DynInput::from_typed(4, program.clone()),
                DynInput::from_typed(7, program)
            ],
            vec![]
        )),
        Ok(())
    );
    let mut output = bundle();
    output.recovery = vec![0; MAX_RECOVERY_BYTES];
    // Recovery bytes retain their separate bounds and outer transaction limit.
    assert_eq!(
        check_transaction(&transaction(vec![], vec![out(4, output); MAX_CONTRACTS])),
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
