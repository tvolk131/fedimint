use fedimint_core::core::DynInputError;
use fedimint_core::transaction::TransactionError;

use super::*;
use crate::assets::{AssetAmount, AssetId};

fn malformed_program() -> Transaction {
    transaction(vec![DynInput::from_typed(4, input(vec![]))], vec![])
}

#[test]
fn duplicate_references_are_scoped_to_instances_and_precede_decoding() {
    let mut tx = malformed_program();
    tx.inputs.push(tx.inputs[0].clone());
    assert_eq!(check_transaction(&tx), Err(ContractError::UnknownContract));

    // Same outpoint in a different instance is not a duplicate. Reach the
    // malformed program instead, regardless of instance/input order.
    tx.inputs[1] = DynInput::from_typed(7, input(vec![]));
    for _ in 0..2 {
        assert_eq!(check_transaction(&tx), Err(ContractError::Program));
        tx.inputs.reverse();
    }
    let mut oversized = input(vec![0; MAX_PROGRAM_BYTES + 1]);
    oversized.outpoint.out_idx = 1;
    tx.inputs = vec![
        tx.inputs[0].clone(),
        tx.inputs[0].clone(),
        DynInput::from_typed(4, oversized),
    ];
    assert_eq!(check_transaction(&tx), Err(ContractError::Limit));
}

#[test]
fn output_structure_is_checked_across_instances_before_decoding() {
    let mut cases = vec![];
    for (version, extension) in [
        (2, None),
        (1, None),
        (0, Some(AssetExtension::Bundle(AssetBundle::default()))),
    ] {
        let mut output = bundle();
        output.version = version;
        output.extension = extension;
        cases.push((output, ContractError::Version));
    }
    let mut output = bundle();
    output.recovery = vec![0; MAX_RECOVERY_BYTES + 1];
    cases.push((output, ContractError::Limit));
    let mut output = bundle();
    output.amount = fedimint_core::Amount::from_msats(2_100_000_000_000_000_001);
    cases.push((output, ContractError::Limit));
    for balances in [
        vec![AssetAmount {
            asset: AssetId([1; 32]),
            quantity: 0,
        }],
        vec![
            AssetAmount {
                asset: AssetId([1; 32]),
                quantity: 1
            };
            2
        ],
        vec![
            AssetAmount {
                asset: AssetId([2; 32]),
                quantity: 1,
            },
            AssetAmount {
                asset: AssetId([1; 32]),
                quantity: 1,
            },
        ],
    ] {
        let mut output = bundle();
        output.extension = Some(AssetExtension::Bundle(AssetBundle {
            balances,
            authorities: vec![],
        }));
        cases.push((output, ContractError::Assets));
    }
    let mut output = bundle();
    output.extension = Some(AssetExtension::Bundle(AssetBundle {
        balances: vec![],
        authorities: vec![AssetId([1; 32]); 2],
    }));
    cases.push((output, ContractError::Assets));
    for (output, error) in cases {
        for instance in [4, 7] {
            let mut tx = malformed_program();
            tx.outputs = vec![
                DynOutput::from_typed(4, bundle()),
                DynOutput::from_typed(instance, output.clone()),
            ];
            for _ in 0..2 {
                assert_eq!(check_transaction(&tx), Err(error.clone()));
                tx.outputs.reverse();
            }
        }
    }
}

#[test]
fn action_shape_and_creation_destinations_precede_decoding() {
    let mut tx = malformed_program();
    let action = creations(1, 1);
    tx.outputs = vec![
        DynOutput::from_typed(4, action.clone()),
        DynOutput::from_typed(4, bundle()),
    ];
    assert_eq!(check_transaction(&tx), Err(ContractError::Program));

    // Out-of-range, foreign-instance, v0 and action-output destinations fail.
    for destination in [
        None,
        Some(DynOutput::from_typed(7, bundle())),
        Some(DynOutput::from_typed(
            4,
            ContractOutput {
                version: 0,
                extension: None,
                ..bundle()
            },
        )),
        Some(DynOutput::from_typed(
            4,
            ContractOutput::action_output(AssetActions::default()),
        )),
    ] {
        tx.outputs = vec![DynOutput::from_typed(4, action.clone())];
        tx.outputs.extend(destination);
        assert_eq!(check_transaction(&tx), Err(ContractError::Assets));
    }
    let mut multiple = creations(1, 1);
    let Some(AssetExtension::Actions(actions)) = &mut multiple.extension else {
        unreachable!()
    };
    actions.creations[0].authority_outputs.push(1);
    tx.outputs = vec![
        DynOutput::from_typed(4, multiple.clone()),
        DynOutput::from_typed(4, bundle()),
    ];
    // Different asset ordinals may share one destination; no unique-index rule.
    assert_eq!(check_transaction(&tx), Err(ContractError::Program));
    let Some(AssetExtension::Actions(actions)) = &mut multiple.extension else {
        unreachable!()
    };
    actions.creations.push(actions.creations[0].clone());
    tx.outputs[0] = DynOutput::from_typed(4, multiple);
    assert_eq!(check_transaction(&tx), Err(ContractError::NamespaceUsed));

    let mut oversized = creations(1, 1);
    let Some(AssetExtension::Actions(actions)) = &mut oversized.extension else {
        unreachable!()
    };
    actions.creations[0].authority_outputs = vec![1; MAX_ASSETS + 1];
    tx.outputs[0] = DynOutput::from_typed(4, oversized);
    assert_eq!(check_transaction(&tx), Err(ContractError::Limit));
    let mut empty = creations(1, 1);
    let Some(AssetExtension::Actions(actions)) = &mut empty.extension else {
        unreachable!()
    };
    actions.creations[0].authority_outputs.clear();
    tx.outputs[0] = DynOutput::from_typed(4, empty);
    assert_eq!(check_transaction(&tx), Err(ContractError::Limit));

    let mut valued_action = action;
    valued_action.amount = fedimint_core::Amount::from_msats(1);
    tx.outputs[0] = DynOutput::from_typed(4, valued_action);
    assert_eq!(check_transaction(&tx), Err(ContractError::Assets));
}

#[test]
fn action_outputs_and_creation_keys_are_scoped_to_each_instance() {
    let mut tx = transaction(
        vec![],
        vec![
            DynOutput::from_typed(4, creations(1, 1)),
            DynOutput::from_typed(4, bundle()),
            DynOutput::from_typed(7, creations(1, 3)),
            DynOutput::from_typed(7, bundle()),
        ],
    );
    assert_eq!(check_transaction(&tx), Ok(()));
    tx.outputs.push(DynOutput::from_typed(
        4,
        ContractOutput::action_output(AssetActions::default()),
    ));
    assert_eq!(check_transaction(&tx), Err(ContractError::Assets));
}

#[test]
fn signature_envelope_fails_before_decoding_but_unsigned_preflight_still_works() {
    let mut tx = malformed_program();
    assert_eq!(
        check_signed_transaction(&tx, 4),
        Err(TransactionError::InvalidWitnessLength)
    );
    tx.signatures = TransactionSignature::Default {
        variant: 17,
        bytes: vec![],
    };
    assert_eq!(
        check_signed_transaction(&tx, 4),
        Err(TransactionError::UnsupportedSignatureScheme { variant: 17 })
    );
    for count in [1, 2] {
        tx.signatures = TransactionSignature::NaiveMultisig(vec![
            Signature::from_slice(&[0; 64])
                .unwrap();
            count
        ]);
        let expected = if count == 1 {
            TransactionError::Input(DynInputError::from_typed(4, ContractError::Program))
        } else {
            TransactionError::InvalidWitnessLength
        };
        assert_eq!(check_signed_transaction(&tx, 4), Err(expected));
    }
    let tx = transaction(vec![DynInput::from_typed(4, input(units(1)))], vec![]);
    assert_eq!(check_transaction(&tx), Ok(()));
    assert_eq!(
        check_signed_transaction(&tx, 4),
        Err(TransactionError::InvalidWitnessLength)
    );
}
