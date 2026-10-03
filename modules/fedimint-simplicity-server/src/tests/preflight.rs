use fedimint_core::core::DynInputError;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_simplicity_common::ContractOutput;
use fedimint_simplicity_common::assets::{AssetActions, AssetCreation};

use super::*;

#[tokio::test]
async fn structural_errors_precede_decoding_in_submission_and_consensus() {
    let fed = Harness::new();
    let owner = key();
    let input = ContractInput {
        outpoint: OutPoint {
            txid: fedimint_core::TransactionId::from_raw_hash(sha256::Hash::all_zeros()),
            out_idx: 0,
        },
        claim_key: owner.public_key(),
        program: vec![],
        witness: vec![],
    };
    let mut tx = transaction(vec![DynInput::from_typed(SIMP, input.clone())], vec![]);
    sign_transaction(&mut tx, &[owner]).unwrap();
    let module_error = |error| TransactionError::Input(DynInputError::from_typed(SIMP, error));
    let mut cases = vec![(tx.clone(), module_error(ContractError::Program))];
    let mut duplicate = tx.clone();
    duplicate.inputs.push(duplicate.inputs[0].clone());
    // Also has the wrong signature count, fixing precedence explicitly.
    cases.push((duplicate, module_error(ContractError::UnknownContract)));
    let mut bad_output = tx.clone();
    bad_output.outputs.push(DynOutput::from_typed(
        SIMP,
        ContractOutput {
            version: 2,
            amount: Amount::ZERO,
            cmr: [0; 32],
            state: [0; 32],
            recovery: vec![],
            extension: None,
        },
    ));
    cases.push((bad_output, module_error(ContractError::Version)));
    let mut bad_destination = tx.clone();
    bad_destination.outputs.push(DynOutput::from_typed(
        SIMP,
        ContractOutput::action_output(AssetActions {
            creations: vec![AssetCreation {
                key: owner.public_key(),
                authority_outputs: vec![u32::MAX],
                signature: Signature::from_slice(&[0; 64]).unwrap(),
            }],
            ..Default::default()
        }),
    ));
    cases.push((bad_destination, module_error(ContractError::Assets)));
    let mut missing_signature = tx.clone();
    missing_signature.signatures = TransactionSignature::NaiveMultisig(vec![]);
    cases.push((missing_signature, TransactionError::InvalidWitnessLength));
    tx.signatures = TransactionSignature::Default {
        variant: 42,
        bytes: vec![],
    };
    cases.push((
        tx.clone(),
        TransactionError::UnsupportedSignatureScheme { variant: 42 },
    ));
    tx.inputs[0] = DynInput::from_typed(
        SIMP,
        ContractInput {
            program: vec![0; MAX_PROGRAM_BYTES + 1],
            ..input
        },
    );
    cases.push((tx, module_error(ContractError::Limit)));

    for (tx, expected) in cases {
        for mode in [TxProcessingMode::Submission, TxProcessingMode::Consensus] {
            let mut dbtx = fed.db.begin_transaction_nc().await;
            dbtx.ignore_uncommitted();
            assert_eq!(
                process_transaction_with_dbtx(
                    fed.modules.clone(),
                    &mut dbtx,
                    &tx,
                    CoreConsensusVersion::new(2, 1),
                    mode,
                    TransactionConsensusContext {
                        federation_id: federation_id(),
                        session_index: 0
                    },
                )
                .await,
                Err(expected.clone())
            );
        }
    }
}
