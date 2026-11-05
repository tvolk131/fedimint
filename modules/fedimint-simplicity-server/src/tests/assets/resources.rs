//! Real core admission/consensus must reject resource abuse before execution,
//! including transactions splitting their work across module instances.
use std::sync::Arc;

use fedimint_core::TransactionId;
use fedimint_simplicity_common::{resources, runtime};
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
async fn shared_cost_budget_accepts_exact_boundary_and_rejects_before_execution() {
    let fed = harness();
    let owner = key();
    let mut inputs = [
        raw_input(units(8192), &owner),
        raw_input(units(1809), &owner),
        raw_input(units(1810), &owner),
    ];
    let outputs = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let decoded = runtime::decode_program(input).unwrap();
            DynOutput::from_typed(
                if index == 0 { SIMP } else { OTHER },
                ContractOutput {
                    version: u32::from(index != 0),
                    amount: Amount::from_sats(100),
                    cmr: decoded.cmr().to_byte_array(),
                    state: [0; 32],
                    recovery: vec![],
                    extension: (index != 0).then(|| AssetExtension::Bundle(AssetBundle::default())),
                },
            )
        })
        .collect();
    let funding = fed.fund(outputs).await;
    for (index, input) in inputs.iter_mut().enumerate() {
        input.outpoint = point(&funding, index as u64);
    }
    let (mut valid, sponsor) = sponsored(
        vec![
            DynInput::from_typed(SIMP, inputs[0].clone()),
            DynInput::from_typed(OTHER, inputs[1].clone()),
        ],
        vec![],
    );
    sign_transaction(&mut valid, &[owner, owner, sponsor]).unwrap();
    assert_eq!(
        runtime::decode_program(&inputs[0]).unwrap().bounds().cost
            + runtime::decode_program(&inputs[1]).unwrap().bounds().cost,
        Cost::from_milliweight(resources::MAX_TRANSACTION_MILLIWEIGHT)
    );
    let before = snapshot(&fed).await;
    for reverse in [false, true] {
        let mut over = valid.clone();
        // Known state and matching commitment, only 200 milliweight over the
        // shared cap. Unknown references now reject in the earlier state phase.
        over.inputs[1] = DynInput::from_typed(OTHER, inputs[2].clone());
        if reverse {
            over.inputs.swap(0, 1);
        }
        sign_transaction(&mut over, &[owner, owner, sponsor]).unwrap();
        assert_error(fed.check_submission(&over, 0).await, "resource limit");
        assert_error(fed.process(&over, 0).await, "resource limit");
        assert_eq!(snapshot(&fed).await, before);
    }
    fed.check_submission(&valid, 0).await.unwrap();
    fed.process(&valid, 0).await.unwrap();
    for (index, module) in [SIMP, OTHER].into_iter().enumerate() {
        let db = fed.db.with_prefix_module_id(module).0;
        assert!(
            db.begin_transaction_nc()
                .await
                .get_value(&ContractKey(inputs[index].outpoint))
                .await
                .is_none()
        );
    }
}

#[tokio::test]
async fn combined_bytes_reject_before_program_decoding_in_both_core_modes() {
    let fed = harness();
    let owner = key();
    let mut input = raw_input(vec![], &owner);
    input.witness = vec![0; MAX_WITNESS_BYTES];
    let mut second = input.clone();
    second.program = vec![0];
    let (mut tx, sponsor) = sponsored(
        vec![
            DynInput::from_typed(SIMP, input),
            DynInput::from_typed(OTHER, second),
        ],
        vec![],
    );
    sign_transaction(&mut tx, &[owner, owner, sponsor]).unwrap();
    let before = snapshot(&fed).await;
    // Both inputs are malformed and unknown, but the byte limit wins before
    // either the decoder or database lookup can run.
    assert_error(fed.check_submission(&tx, 0).await, "resource limit");
    assert_error(fed.process(&tx, 0).await, "resource limit");
    assert_eq!(snapshot(&fed).await, before);
}

#[tokio::test]
async fn creation_authorizations_share_one_budget_without_contract_inputs() {
    for count in [21, 20] {
        let fed = harness();
        let keys = (0..count).map(|_| key()).collect::<Vec<_>>();
        let program = ContractProgram::compile("fn main() {}", Default::default()).unwrap();
        let mut outputs = vec![];
        let mut origins = vec![];
        for (index, module) in [SIMP, OTHER].into_iter().enumerate() {
            let mut creations = vec![];
            let mut ids = vec![];
            for key in keys.iter().skip(index).step_by(2) {
                let (creation, created) =
                    assets::creation(federation_id(), module, key, vec![(2 * index) as u32])
                        .unwrap();
                creations.push(creation);
                ids.extend(created);
            }
            origins.extend(ids.iter().map(|id| (module, *id)));
            outputs.push(DynOutput::from_typed(
                module,
                program
                    .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[], &ids))
                    .unwrap(),
            ));
            outputs.push(DynOutput::from_typed(
                module,
                assets::action_output(AssetActions {
                    creations,
                    ..Default::default()
                })
                .unwrap(),
            ));
        }
        let (mut tx, sponsor) = sponsored(vec![], outputs);
        for (index, key) in keys.iter().enumerate() {
            assets::sign_creation(
                &mut tx,
                federation_id(),
                if index % 2 == 0 { SIMP } else { OTHER },
                key,
            )
            .unwrap();
        }
        sign_transaction(&mut tx, &[sponsor]).unwrap();
        if count == 21 {
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
