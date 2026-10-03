use bitcoin::hashes::{Hash, sha256};
use fedimint_core::core::DynInput;
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::module::CoreConsensusVersion;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey};
use fedimint_core::transaction::{Transaction, TransactionSignature};
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_server::consensus::transaction::{TxProcessingMode, process_transaction_with_dbtx};
use fedimint_server_core::{
    DynServerModule, ServerModule, ServerModuleRegistry, TransactionConsensusContext,
};
use fedimint_simplicity_client::compiler::{Value, arguments, witnesses};
use fedimint_simplicity_client::{ContractProgram, sign_transaction};
use simplicity::ConstructNode;
use simplicity::node::CoreConstructible;

use super::*;
use crate::{Simplicity, validation};

fn owner() -> Keypair {
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[1; 32]).unwrap())
}

fn spend(index: u64, valid: bool) -> (ContractInput, StoredContract) {
    let program =
        ContractProgram::compile("fn main() { assert!(witness::OK); }", arguments([])).unwrap();
    let input = program
        .input(
            OutPoint {
                txid: TransactionId::from_raw_hash(sha256::Hash::all_zeros()),
                out_idx: index,
            },
            owner().public_key(),
            witnesses([("OK", Value::from(valid))]),
        )
        .unwrap();
    let stored = StoredContract {
        output: program
            .output(Amount::from_sats(100), [0; 32], vec![])
            .unwrap(),
        creation_session: 0,
        creation_block_count: 0,
    };
    (input, stored)
}

fn transaction(inputs: Vec<(u16, ContractInput)>) -> Transaction {
    let mut tx = Transaction {
        inputs: inputs
            .into_iter()
            .map(|(id, input)| DynInput::from_typed(id, input))
            .collect(),
        outputs: vec![],
        nonce: [0; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    };
    let keys = vec![owner(); tx.inputs.len()];
    sign_transaction(&mut tx, &keys).unwrap();
    tx
}

fn context(tx: &Transaction, instance: u16) -> ModuleTransactionContext<'_> {
    ModuleTransactionContext {
        transaction: tx,
        consensus: TransactionConsensusContext {
            federation_id: fedimint_core::config::FederationId(sha256::Hash::all_zeros()),
            session_index: 0,
        },
        module_instance_id: instance,
        preparation: None,
        validation: None,
    }
}

fn federation() -> (Database, ServerModuleRegistry) {
    let decoders = ModuleDecoderRegistry::new(
        [4, 7].map(|id| (id, fedimint_simplicity_common::KIND, Simplicity::decoder())),
    );
    let modules = ServerModuleRegistry::new([4, 7].map(|id| {
        (
            id,
            fedimint_simplicity_common::KIND,
            DynServerModule::from(Simplicity::new_for_testing(vec![0.into()]).unwrap()),
        )
    }));
    (Database::new(MemDatabase::new(), decoders), modules)
}

async fn seed(db: &Database, instance: u16, input: &ContractInput, stored: &StoredContract) {
    let mut tx = db.begin_transaction().await;
    tx.to_ref_with_prefix_module_id(instance)
        .0
        .insert_entry(&ContractKey(input.outpoint), stored)
        .await;
    tx.commit_tx_result().await.unwrap();
}

async fn check(
    db: &Database,
    modules: &ServerModuleRegistry,
    tx: &Transaction,
    expected: Result<(), TransactionError>,
) {
    for mode in [TxProcessingMode::Submission, TxProcessingMode::Consensus] {
        let mut dbtx = db.begin_transaction_nc().await;
        dbtx.ignore_uncommitted();
        assert_eq!(
            process_transaction_with_dbtx(
                modules.clone(),
                &mut dbtx,
                tx,
                CoreConsensusVersion::new(2, 1),
                mode,
                context(tx, 4).consensus
            )
            .await,
            expected
        );
    }
}

#[tokio::test]
async fn all_instances_resolve_before_decoding_and_check_commitments_before_execution() {
    for ids in [[4, 4], [4, 7], [7, 4]] {
        let (db, modules) = federation();
        let (first, stored_first) = spend(0, false);
        let (last, mut stored_last) = spend(1, true);
        seed(&db, ids[0], &first, &stored_first).await;
        let mut malformed = first.clone();
        malformed.program.clear();
        let tx = transaction(vec![(ids[0], malformed), (ids[1], last.clone())]);
        // Missing later state wins even over an earlier malformed program.
        check(
            &db,
            &modules,
            &tx,
            Err(input_error(ids[1], ContractError::UnknownContract)),
        )
        .await;
        seed(&db, ids[1], &last, &stored_last).await;
        check(
            &db,
            &modules,
            &tx,
            Err(input_error(ids[0], ContractError::Program)),
        )
        .await;
        let tx = transaction(vec![(ids[0], first.clone()), (ids[1], last.clone())]);
        stored_last.output.cmr = [0; 32];
        seed(&db, ids[1], &last, &stored_last).await;
        // The earlier program would fail if it ran; the late CMR must win.
        check(
            &db,
            &modules,
            &tx,
            Err(input_error(ids[1], ContractError::Commitment)),
        )
        .await;
        stored_last.output.cmr = runtime::decode_program(&last)
            .unwrap()
            .cmr()
            .to_byte_array();
        seed(&db, ids[1], &last, &stored_last).await;
        check(
            &db,
            &modules,
            &tx,
            Err(input_error(ids[0], ContractError::Rejected)),
        )
        .await;
        let (first, stored_first) = spend(0, true);
        seed(&db, ids[0], &first, &stored_first).await;
        // Same CMR/program, different witnesses: never reuse a decoded
        // witness merely because another input has the same policy.
        let (bad_last, _) = spend(1, false);
        let mixed = transaction(vec![(ids[0], first.clone()), (ids[1], bad_last)]);
        check(
            &db,
            &modules,
            &mixed,
            Err(input_error(ids[1], ContractError::Rejected)),
        )
        .await;
        let tx = transaction(vec![(ids[0], first.clone()), (ids[1], last)]);
        check(&db, &modules, &tx, Ok(())).await;
        // A successful admission attempt does not cache state for the next one.
        let mut dbtx = db.begin_transaction().await;
        dbtx.to_ref_with_prefix_module_id(ids[0])
            .0
            .remove_entry(&ContractKey(first.outpoint))
            .await;
        dbtx.commit_tx_result().await.unwrap();
        check(
            &db,
            &modules,
            &tx,
            Err(input_error(ids[0], ContractError::UnknownContract)),
        )
        .await;
    }
}

fn units(count: usize) -> Vec<u8> {
    simplicity::types::Context::with_context(|ctx| {
        let mut power: Arc<ConstructNode> = Arc::unit(&ctx);
        for _ in 0..count {
            power = Arc::comp(&power, &power).unwrap();
        }
        power.finalize_types().unwrap().to_vec_without_witness()
    })
}

#[tokio::test]
async fn later_execution_version_failure_precedes_earlier_vm_failure() {
    let (db, modules) = federation();
    let (first, stored) = spend(0, false);
    seed(&db, 4, &first, &stored).await;
    let (mut last, mut stored) = spend(1, true);
    last.program = simplicity::types::Context::with_context(|ctx| {
        let word: Arc<ConstructNode> = Arc::const_word(
            &ctx,
            simplicity::Value::from_byte_array([0; 16])
                .to_word()
                .unwrap(),
        );
        let jet = Arc::jet(
            &ctx,
            &fedimint_simplicity_common::jet::FedimintJet::Core(simplicity::jet::Core::Multiply64),
        );
        Arc::comp(&Arc::comp(&word, &jet).unwrap(), &Arc::unit(&ctx))
            .unwrap()
            .finalize_types()
            .unwrap()
            .to_vec_without_witness()
    });
    last.witness.clear();
    stored.output.cmr = runtime::decode_program(&last)
        .unwrap()
        .cmr()
        .to_byte_array();
    seed(&db, 7, &last, &stored).await;
    let tx = transaction(vec![(4, first), (7, last)]);
    check(
        &db,
        &modules,
        &tx,
        Err(input_error(7, ContractError::Version)),
    )
    .await;
}

#[test]
fn retention_accounting_has_inclusive_boundaries_and_counts_large_values() {
    for bytes in [32, 4096] {
        let program = simplicity::types::Context::with_context(|ctx| {
            let word = simplicity::Value::from_byte_array([0; 4096]);
            let word = if bytes == 32 {
                simplicity::Value::from_byte_array([0; 32])
            } else {
                word
            };
            let node: Arc<ConstructNode> = Arc::const_word(&ctx, word.to_word().unwrap());
            Arc::comp(&node, &Arc::unit(&ctx))
                .unwrap()
                .finalize_types()
                .unwrap()
                .to_vec_without_witness()
        });
        let (mut input, _) = spend(0, true);
        input.program = program;
        input.witness.clear();
        let decoded = runtime::decode_program(&input).unwrap();
        let charge = retention::charge(&decoded, RETENTION_BUDGET).unwrap();
        assert!(charge > bytes);
        assert_eq!(retention::charge(&decoded, charge), Some(charge));
        assert_eq!(retention::charge(&decoded, charge - 1), None);
        assert_eq!(retention::charge(&decoded, 0), None);
    }
}

#[tokio::test]
async fn aggregate_cost_is_checked_across_instances_before_any_execution() {
    let (db, modules) = federation();
    let (first, stored) = spend(0, false);
    seed(&db, 4, &first, &stored).await;
    let mut inputs = vec![(4, first)];
    for (id, index) in [(4, 1), (7, 2)] {
        let (mut input, mut stored) = spend(index, true);
        input.program = units(13); // 1,638,300 milliweight each, individually valid.
        input.witness.clear();
        stored.output.cmr = runtime::decode_program(&input)
            .unwrap()
            .cmr()
            .to_byte_array();
        seed(&db, id, &input, &stored).await;
        inputs.push((id, input));
    }
    check(
        &db,
        &modules,
        &transaction(inputs),
        Err(input_error(7, ContractError::Limit)),
    )
    .await;
}

#[tokio::test]
async fn retention_budget_changes_neither_execution_result_nor_fees() {
    for witnesses in [[true, true], [false, false], [true, false]] {
        let (db, _) = federation();
        let mut inputs = vec![];
        for (index, valid) in witnesses.into_iter().enumerate() {
            let (input, stored) = spend(index as u64, valid);
            seed(&db, 4, &input, &stored).await;
            inputs.push((4, input));
        }
        let tx = transaction(inputs);
        let module = Simplicity::new_for_testing(vec![0.into()]).unwrap();
        let first = tx.inputs[0]
            .as_any()
            .downcast_ref::<ContractInput>()
            .unwrap();
        let charge =
            retention::charge(&runtime::decode_program(first).unwrap(), RETENTION_BUDGET).unwrap();
        let mut results = vec![];
        for (budget, count) in [(0, 0), (charge, 1), (RETENTION_BUDGET, 2)] {
            let mut dbtx = db.begin_transaction_nc().await;
            let mut dbtx = dbtx.to_ref_with_prefix_module_id(4).0;
            let mut context = context(&tx, 4);
            let resolved = resolve(&mut dbtx, &context).await.unwrap();
            let prepared =
                prepare_with_budget(&context, BTreeMap::from([(4, resolved)]), budget).unwrap();
            assert_eq!(
                prepared.programs.values().filter(|p| p.is_some()).count(),
                count
            );
            let prepared = ModuleTransactionValidation::new(prepared);
            context.preparation = Some(&prepared);
            results.push(
                validation::validate(&module, &mut dbtx, &context)
                    .await
                    .map(|v| {
                        v.inputs
                            .into_iter()
                            .map(|i| (i.pub_key, i.amount.amounts, i.amount.fees))
                            .collect::<Vec<_>>()
                    }),
            );
        }
        assert_eq!(results[0], results[1]);
        assert_eq!(results[1], results[2]);
        if witnesses == [true, true] {
            assert!(results[0].is_ok());
        } else {
            assert_eq!(results[0], Err(input_error(4, ContractError::Rejected)));
        }
    }
}
