//! Real core admission/consensus must reject resource abuse before execution.
//! Limits apply to each module instance separately.
use std::sync::Arc;

use fedimint_core::TransactionId;
use fedimint_simplicity_common::limits::MAX_TRANSACTION_MILLIWEIGHT;
use fedimint_simplicity_common::runtime;
use simplicity::node::CoreConstructible;
use simplicity::{ConstructNode, Cost};

use super::instances::{OTHER, harness, snapshot};
use super::*;

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

fn raw_input(program: Vec<u8>, owner: &Keypair) -> ContractInput {
    ContractInput {
        outpoint: OutPoint {
            txid: TransactionId::from_raw_hash(Hash::all_zeros()),
            out_idx: 0,
        },
        claim_key: owner.public_key(),
        program,
        witness: vec![],
    }
}

#[tokio::test]
async fn per_instance_cost_budget_accepts_exact_boundary_and_rejects_before_execution() {
    let fed = harness();
    let owner = key();
    let mut inputs = [
        (SIMP, raw_input(units(8192), &owner)),
        (SIMP, raw_input(units(1809), &owner)),
        (SIMP, raw_input(units(1810), &owner)),
        (SIMP, raw_input(units(8192), &owner)),
        (OTHER, raw_input(units(1810), &owner)),
    ];
    let outputs = inputs
        .iter()
        .map(|(module, input)| {
            let decoded = runtime::decode_program(input).unwrap();
            DynOutput::from_typed(
                *module,
                SimplicityOutput::from(ContractOutput {
                    version: fedimint_simplicity_common::EXECUTION_VERSION,
                    amount: Amount::from_sats(100),
                    cmr: decoded.cmr().to_byte_array(),
                    state: [0; 32],
                    recovery: vec![],
                    assets: AssetBundle::default(),
                }),
            )
        })
        .collect();
    let funding = fed.fund(outputs).await;
    for (index, (_, input)) in inputs.iter_mut().enumerate() {
        input.outpoint = point(&funding, index as u64);
    }
    let spend = |indices: [usize; 2]| {
        let (mut tx, sponsor) = sponsored(
            indices
                .into_iter()
                .map(|index| DynInput::from_typed(inputs[index].0, inputs[index].1.clone()))
                .collect(),
            vec![],
        );
        sign_transaction(&mut tx, &[owner, owner, sponsor]).unwrap();
        tx
    };
    let cost = |index: usize| {
        runtime::decode_program(&inputs[index].1)
            .unwrap()
            .bounds()
            .cost
    };
    assert_eq!(
        cost(0) + cost(1),
        Cost::from_milliweight(MAX_TRANSACTION_MILLIWEIGHT)
    );
    let before = snapshot(&fed).await;
    for indices in [[0, 2], [2, 0]] {
        // Known state and matching commitment, only 200 milliweight over the
        // instance's cap. Unknown references now reject in the earlier state
        // phase.
        let over = spend(indices);
        assert_error(fed.check_submission(&over, 0).await, "resource limit");
        assert_error(fed.process(&over, 0).await, "resource limit");
        assert_eq!(snapshot(&fed).await, before);
    }
    // Exactly the cap within one instance, and the same 200 milliweight over
    // split across two instances, which each have their own budget.
    for indices in [[0, 1], [3, 4]] {
        let valid = spend(indices);
        fed.check_submission(&valid, 0).await.unwrap();
        fed.process(&valid, 0).await.unwrap();
        for index in indices {
            let (module, input) = &inputs[index];
            let db = fed.db.with_prefix_module_id(*module).0;
            assert!(
                db.begin_transaction_nc()
                    .await
                    .get_value(&ContractKey(input.outpoint))
                    .await
                    .is_none()
            );
        }
    }
}

#[tokio::test]
async fn combined_instance_bytes_reject_before_program_decoding_in_both_core_modes() {
    let fed = harness();
    let owner = key();
    let mut input = raw_input(vec![], &owner);
    input.witness = vec![0; MAX_WITNESS_BYTES];
    let mut second = input.clone();
    second.program = vec![0];
    second.outpoint.out_idx = 1;
    let spend = |modules: [u16; 2]| {
        let (mut tx, sponsor) = sponsored(
            vec![
                DynInput::from_typed(modules[0], input.clone()),
                DynInput::from_typed(modules[1], second.clone()),
            ],
            vec![],
        );
        sign_transaction(&mut tx, &[owner, owner, sponsor]).unwrap();
        tx
    };
    let before = snapshot(&fed).await;
    // Both inputs are malformed and unknown, but the byte limit wins before
    // either the decoder or database lookup can run.
    let tx = spend([SIMP, SIMP]);
    assert_error(fed.check_submission(&tx, 0).await, "resource limit");
    assert_error(fed.process(&tx, 0).await, "resource limit");
    assert_eq!(snapshot(&fed).await, before);
    // Split across instances, each instance's bytes fit, so the unknown
    // contract is what rejects them.
    let tx = spend([SIMP, OTHER]);
    assert_error(
        fed.check_submission(&tx, 0).await,
        "contract does not exist",
    );
    assert_error(fed.process(&tx, 0).await, "contract does not exist");
    assert_eq!(snapshot(&fed).await, before);
}

#[tokio::test]
async fn creation_authorizations_share_their_instance_budget_without_contract_inputs() {
    // 20 creations spend an instance's whole budget, and each instance has its
    // own.
    for counts in [[21, 20], [20, 21], [20, 20]] {
        let fed = harness();
        let keys = counts.map(|count| (0..count).map(|_| key()).collect::<Vec<_>>());
        let program = ContractProgram::compile("fn main() {}", Default::default()).unwrap();
        let mut outputs = vec![];
        let mut origins = vec![];
        for (index, module) in [SIMP, OTHER].into_iter().enumerate() {
            let mut creations = vec![];
            let mut ids = vec![];
            for key in &keys[index] {
                let (creation, created) =
                    assets::creation(federation_id(), module, key, vec![(2 * index) as u32])
                        .unwrap();
                creations.push(creation);
                ids.extend(created);
            }
            origins.extend(ids.iter().map(|id| (module, *id)));
            outputs.push(DynOutput::from_typed(
                module,
                SimplicityOutput::from(
                    program
                        .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[], &ids))
                        .unwrap(),
                ),
            ));
            outputs.push(DynOutput::from_typed(
                module,
                SimplicityOutput::from(
                    assets::action_output(AssetActions {
                        creations,
                        ..Default::default()
                    })
                    .unwrap(),
                ),
            ));
        }
        let (mut tx, sponsor) = sponsored(vec![], outputs);
        for (module, keys) in [SIMP, OTHER].into_iter().zip(&keys) {
            for key in keys {
                assets::sign_creation(&mut tx, federation_id(), module, key).unwrap();
            }
        }
        sign_transaction(&mut tx, &[sponsor]).unwrap();
        if counts.contains(&21) {
            let before = snapshot(&fed).await;
            assert_error(fed.check_submission(&tx, 0).await, "resource limit");
            assert_error(fed.process(&tx, 0).await, "resource limit");
            assert_eq!(snapshot(&fed).await, before);
        } else {
            fed.check_submission(&tx, 0).await.unwrap();
            fed.process(&tx, 0).await.unwrap();
            for (module, id) in origins {
                let db = fed.db.with_prefix_module_id(module).0;
                assert!(
                    db.begin_transaction_nc()
                        .await
                        .get_value(&AssetKey(id))
                        .await
                        .is_some()
                );
            }
        }
    }
}
