//! Deterministic workload families and single-fault validation-order probes.
//! All mutations are local; this harness never sends requests to a federation.
use std::time::Instant;

use fedimint_core::db::IDatabaseTransactionOpsCore;
use futures::StreamExt;

use super::*;

pub const CASES: &[&str] = &[
    "constants_256x32",
    "constants_1024x15",
    "constants_2048x7",
    "constants_4096x3",
    "constants_packed",
    "packed_missing_first",
    "packed_missing_last",
    "packed_duplicate",
    "packed_bad_cmr_first",
    "packed_bad_cmr_last",
    "packed_bad_output",
    "packed_trailing_witness_first",
    "packed_trailing_witness_last",
    "packed_bad_outer_signature",
    "packed_missing_outer_signature",
    "packed_underfunded",
    "chain_256",
    "chain_768",
    "chain_768x2",
    "balanced_512",
    "balanced_768",
    "balanced_768x2",
    "mixed_33",
    "mixed_33_bad_last",
    "wide_1024x3",
    "wide_2048",
    "hash_blocks_32",
    "hash_blocks_64",
    "signatures_38",
    "signatures_38_bad_first",
    "signatures_38_bad_last",
    "creations_19_bad_first",
    "creations_19_bad_last",
    "creations_19_bad_destination",
];

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Accept,
    Module(ContractError),
    Signature,
    SignatureCount,
    Funding,
}

pub struct Case {
    pub fixture: Fixture,
    pub transaction: Transaction,
    preflight: Option<ContractError>,
    outcome: Outcome,
}

static CASE_DATA: LazyLock<BTreeMap<&str, Case>> =
    LazyLock::new(|| CASES.iter().map(|name| (*name, build_case(name))).collect());

pub fn case(name: &str) -> &'static Case {
    CASE_DATA.get(name).expect("registered adversarial case")
}

fn constant(bytes: usize) -> Fixture {
    assert!(bytes.is_power_of_two());
    let mut value = simplicity::Value::u8(0x55);
    for _ in 0..bytes.ilog2() {
        value = simplicity::Value::product(value.clone(), value);
    }
    let program = simplicity::types::Context::with_context(|ctx| {
        let node: Arc<ConstructNode> = Arc::const_word(&ctx, value.to_word().expect("word"));
        Arc::comp(&node, &Arc::unit(&ctx))
            .expect("discard constant")
            .finalize_types()
            .expect("closed types")
            .to_vec_without_witness()
    });
    encoded(program, vec![])
}

fn packed() -> Fixture {
    let mut fixture = constant(4096);
    fixture.inputs.clear();
    fixture.consumed.clear();
    let mut remaining = resources::MAX_TRANSACTION_REDEMPTION_BYTES;
    for exponent in (0..=12).rev() {
        let part = constant(1 << exponent);
        while part.inputs[0].program.len() <= remaining && fixture.inputs.len() < 32 {
            remaining -= part.inputs[0].program.len();
            let mut input = part.inputs[0].clone();
            input.outpoint = point(fixture.inputs.len() as u64);
            fixture.inputs.push(input);
            fixture.consumed.push(part.consumed[0].clone());
        }
    }
    fixture
}

// Unique constants prevent canonical sharing from collapsing the node count.
fn sequence(count: u32, balanced: bool) -> Fixture {
    let program = simplicity::types::Context::with_context(|ctx| {
        let mut nodes: Vec<Arc<ConstructNode>> = (0..count)
            .map(|index| {
                Arc::comp(
                    &Arc::const_word(&ctx, simplicity::Value::u32(index).to_word().expect("u32")),
                    &Arc::unit(&ctx),
                )
                .expect("discard constant")
            })
            .collect();
        if balanced {
            while nodes.len() > 1 {
                nodes = nodes
                    .chunks(2)
                    .map(|pair| {
                        if pair.len() == 1 {
                            pair[0].clone()
                        } else {
                            Arc::comp(&pair[0], &pair[1]).expect("unit composition")
                        }
                    })
                    .collect();
            }
        } else {
            let first = nodes.remove(0);
            nodes = vec![
                nodes
                    .into_iter()
                    .fold(first, |a, b| Arc::comp(&a, &b).expect("unit composition")),
            ];
        }
        nodes[0]
            .finalize_types()
            .expect("closed types")
            .to_vec_without_witness()
    });
    encoded(program, vec![])
}

fn hash_blocks(count: usize) -> Fixture {
    let program = fedimint_simplicity_client::compiler::compile(
        &format!("fn hash(block: (u256, u256), acc: u256) -> u256 {{ let (a, b): (u256, u256) = block; jet::sha_256_block(acc, a, b) }} fn main() {{ let hash: u256 = array_fold::<hash, {count}>(witness::DATA, jet::sha_256_iv()); }}"),
        arguments([]),
    ).expect("hash workload compiles");
    let block = Value::tuple([market::word([0; 32]), market::word([0; 32])]);
    let data = Value::array(vec![block.clone(); count], block.ty().clone());
    let satisfied = program
        .satisfy(witnesses([("DATA", data)]))
        .expect("hash workload satisfies");
    let (program, witness) = satisfied.redeem().to_vec_with_witness();
    encoded(program, witness)
}

fn signatures(count: usize, bad: Option<usize>) -> Fixture {
    let program = simplicity::types::Context::with_context(|ctx| {
        let mut bytes = [0; 128];
        bytes[..32].copy_from_slice(&key().x_only_public_key().0.serialize());
        bytes[64..].copy_from_slice(
            SECP256K1
                .sign_schnorr_no_aux_rand(&Message::from_digest([0; 32]), &key())
                .as_ref(),
        );
        let good: Arc<ConstructNode> = Arc::comp(
            &Arc::const_word(
                &ctx,
                simplicity::Value::from_byte_array(bytes)
                    .to_word()
                    .expect("word"),
            ),
            &Arc::jet(&ctx, &FedimintJet::Core(Core::Bip0340Verify)),
        )
        .expect("signature check");
        bytes[32] = 1; // Wrong message with an otherwise well-formed signature.
        let wrong: Arc<ConstructNode> = Arc::comp(
            &Arc::const_word(
                &ctx,
                simplicity::Value::from_byte_array(bytes)
                    .to_word()
                    .expect("word"),
            ),
            &Arc::jet(&ctx, &FedimintJet::Core(Core::Bip0340Verify)),
        )
        .expect("signature check");
        let mut nodes: Vec<_> = (0..count)
            .map(|i| {
                if bad == Some(i) {
                    wrong.clone()
                } else {
                    good.clone()
                }
            })
            .collect();
        while nodes.len() > 1 {
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    if pair.len() == 1 {
                        pair[0].clone()
                    } else {
                        Arc::comp(&pair[0], &pair[1]).expect("unit composition")
                    }
                })
                .collect();
        }
        nodes[0]
            .finalize_types()
            .expect("closed types")
            .to_vec_without_witness()
    });
    encoded(program, vec![])
}

fn mixed(bad: bool) -> Fixture {
    let mut fixture = packed();
    let signature = signatures(33, bad.then_some(32));
    let mut bytes = fixture
        .inputs
        .iter()
        .map(|input| input.program.len())
        .sum::<usize>();
    while bytes + signature.inputs[0].program.len() > resources::MAX_TRANSACTION_REDEMPTION_BYTES {
        bytes -= fixture
            .inputs
            .pop()
            .expect("packed constants")
            .program
            .len();
        fixture.consumed.pop();
    }
    let mut input = signature.inputs[0].clone();
    input.outpoint = point(fixture.inputs.len() as u64);
    fixture.inputs.push(input);
    fixture.consumed.push(signature.consumed[0].clone());
    fixture
}

fn build_case(name: &str) -> Case {
    let mut fixture = match name {
        "constants_256x32" | "constants_1024x15" | "constants_2048x7" | "constants_4096x3" => {
            let (size, count) = match name {
                "constants_256x32" => (256, 32),
                "constants_1024x15" => (1024, 15),
                "constants_2048x7" => (2048, 7),
                _ => (4096, 3),
            };
            let mut f = constant(size);
            duplicate(&mut f, count, false);
            f
        }
        "chain_256" => sequence(256, false),
        "chain_768" => sequence(768, false),
        "chain_768x2" | "balanced_768x2" => {
            let mut f = sequence(768, name.starts_with("balanced"));
            duplicate(&mut f, 2, false);
            f
        }
        "balanced_512" => sequence(512, true),
        "balanced_768" => sequence(768, true),
        "wide_1024x3" => {
            let mut f = encoded(shared_program(10, true), vec![]);
            duplicate(&mut f, 3, false);
            f
        }
        "wide_2048" => encoded(shared_program(11, true), vec![]),
        "hash_blocks_32" => hash_blocks(32),
        "hash_blocks_64" => hash_blocks(64),
        "signatures_38" => signatures(38, None),
        "signatures_38_bad_first" => signatures(38, Some(0)),
        "signatures_38_bad_last" => signatures(38, Some(37)),
        "mixed_33" => mixed(false),
        "mixed_33_bad_last" => mixed(true),
        name if name.starts_with("creations_") => creation_case(19),
        _ => packed(),
    };
    if name.starts_with("packed_bad_cmr") {
        let index = if name.ends_with("first") {
            0
        } else {
            fixture.consumed.len() - 1
        };
        fixture.consumed[index].cmr = compiled("fn main() {}").consumed[0].cmr;
    }
    // The funding-failure case has a valid successor consuming every supplied
    // msat, leaving the fees uncovered even after dummy sponsorship.
    if name == "packed_underfunded" {
        let mut output = fixture.consumed[0].clone();
        output.amount = Amount::from_msats(
            100_000_000 + fixture.consumed.iter().map(|o| o.amount.msats).sum::<u64>(),
        );
        fixture
            .transaction
            .outputs
            .push(DynOutput::from_typed(MODULE, output));
    }
    fixture.finish();
    let mut transaction = fixture.funded_transaction();
    let mut preflight = None;
    let outcome = match name {
        "packed_missing_first" | "packed_missing_last" | "packed_duplicate" => {
            let index = if name.ends_with("first") {
                0
            } else {
                fixture.inputs.len() - 1
            };
            let mut input = fixture.inputs[index].clone();
            input.outpoint = if name.ends_with("duplicate") {
                point(0)
            } else {
                point(9999)
            };
            transaction.inputs[index] = DynInput::from_typed(MODULE, input);
            Outcome::Module(ContractError::UnknownContract)
        }
        "packed_bad_cmr_first" | "packed_bad_cmr_last" => {
            Outcome::Module(ContractError::Commitment)
        }
        "packed_bad_output" => {
            let mut output = fixture.consumed[0].clone();
            output.version = 2;
            transaction
                .outputs
                .push(DynOutput::from_typed(MODULE, output));
            Outcome::Module(ContractError::Version)
        }
        "packed_trailing_witness_first" | "packed_trailing_witness_last" => {
            let index = if name.ends_with("first") {
                0
            } else {
                fixture.inputs.len() - 1
            };
            let mut input = fixture.inputs[index].clone();
            input.witness.push(0);
            // Make room for the deliberately invalid witness while remaining
            // within the aggregate byte cap. The final packed input is tiny.
            transaction.inputs[index] = DynInput::from_typed(MODULE, input);
            let last = fixture.inputs.len() - 1;
            transaction
                .inputs
                .remove(if index == last { last - 1 } else { last });
            preflight = Some(ContractError::Program);
            Outcome::Module(ContractError::Program)
        }
        "packed_bad_outer_signature" => Outcome::Signature,
        "packed_missing_outer_signature" => Outcome::SignatureCount,
        "packed_underfunded" => Outcome::Funding,
        "signatures_38_bad_first" | "signatures_38_bad_last" | "mixed_33_bad_last" => {
            Outcome::Module(ContractError::Rejected)
        }
        "creations_19_bad_first" | "creations_19_bad_last" | "creations_19_bad_destination" => {
            let mut output = transaction.outputs[1]
                .as_any()
                .downcast_ref::<ContractOutput>()
                .expect("actions")
                .clone();
            let Some(AssetExtension::Actions(actions)) = &mut output.extension else {
                panic!("actions")
            };
            let index = if name.ends_with("first") { 0 } else { 18 };
            if name.ends_with("destination") {
                actions.creations[index].authority_outputs[0] = 127;
            } else {
                actions.creations[index].signature =
                    SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest([0; 32]), &key());
            }
            transaction.outputs[1] = DynOutput::from_typed(MODULE, output);
            if name.ends_with("destination") {
                for i in 0..19 {
                    let creator = Keypair::from_secret_key(
                        SECP256K1,
                        &SecretKey::from_slice(&[i + 2; 32]).expect("creator"),
                    );
                    assets::sign_creation(&mut transaction, federation(), MODULE, &creator)
                        .expect("creation");
                }
                Outcome::Module(ContractError::Assets)
            } else {
                Outcome::Module(ContractError::CreationSignature)
            }
        }
        _ => Outcome::Accept,
    };
    let keys = vec![key(); transaction.inputs.len()];
    sign_transaction(&mut transaction, &keys).expect("outer signatures");
    if let TransactionSignature::NaiveMultisig(sigs) = &mut transaction.signatures {
        if name == "packed_missing_outer_signature" {
            sigs.pop();
        }
        if name == "packed_bad_outer_signature" {
            sigs[0] = SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest([0; 32]), &key());
        }
    }
    Case {
        fixture,
        transaction,
        preflight,
        outcome,
    }
}

fn classify(result: Result<(), TransactionError>) -> Outcome {
    match result {
        Ok(()) => Outcome::Accept,
        Err(TransactionError::InvalidSignature { .. }) => Outcome::Signature,
        Err(TransactionError::InvalidWitnessLength) => Outcome::SignatureCount,
        Err(TransactionError::UnbalancedTransaction { .. }) => Outcome::Funding,
        Err(error) => Outcome::Module(contract_error(error)),
    }
}

pub fn check_all() {
    let rt = executor();
    for (name, case) in CASE_DATA.iter() {
        assert_eq!(
            resources::check_transaction(&case.fixture.transaction),
            Ok(()),
            "{name}: unmutated workload fits both caps"
        );
        assert!(
            case.transaction.consensus_encode_to_vec().len() <= Transaction::MAX_TX_SIZE,
            "{name}: outer size"
        );
        let bytes: usize = case
            .transaction
            .inputs
            .iter()
            .filter_map(|i| i.as_any().downcast_ref::<ContractInput>())
            .map(|i| i.program.len() + i.witness.len())
            .sum();
        assert!(
            bytes <= resources::MAX_TRANSACTION_REDEMPTION_BYTES,
            "{name}: redemption size"
        );
        assert_eq!(
            resources::check_transaction(&case.transaction).err(),
            case.preflight,
            "{name}: preflight"
        );
        rt.block_on(async {
            let (db, modules) = case.fixture.core_database().await;
            for mode in [TxProcessingMode::Submission, TxProcessingMode::Consensus] {
                let before = snapshot(&db).await;
                let mut dbtx = db.begin_transaction_nc().await;
                let result = process_transaction_with_dbtx(
                    modules.clone(),
                    &mut dbtx.to_ref_nc(),
                    &case.transaction,
                    CoreConsensusVersion::new(2, 1),
                    mode,
                    TransactionConsensusContext {
                        federation_id: federation(),
                        session_index: 10,
                    },
                )
                .await;
                assert_eq!(classify(result), case.outcome, "{name}: core outcome");
                drop(dbtx);
                assert_eq!(snapshot(&db).await, before, "{name}: dropped writes");
            }
        });
    }
}

async fn snapshot(db: &Database) -> Vec<(Vec<u8>, Vec<u8>)> {
    db.begin_transaction_nc()
        .await
        .raw_find_by_prefix(&[])
        .await
        .expect("in-memory snapshot")
        .collect()
        .await
}

pub fn manifest() -> serde_json::Value {
    serde_json::Value::Array(CASE_DATA.iter().map(|(name, case)| {
        let inputs: Vec<_> = case.transaction.inputs.iter().filter_map(|i| i.as_any().downcast_ref::<ContractInput>()).collect();
        let bounds: Vec<_> = inputs.iter().map(|i| runtime::decode_program(i).ok().map(|p| p.bounds())).collect();
        serde_json::json!({
            "name": name, "transaction_sha256": case.transaction.tx_hash().to_string(),
            "transaction_bytes": case.transaction.consensus_encode_to_vec().len(),
            "redemption_bytes": inputs.iter().map(|i| i.program.len() + i.witness.len()).sum::<usize>(),
            "input_costs": bounds.iter().map(|b| b.map(|b| b.cost.to_string())).collect::<Vec<_>>(),
            "input_extra_cells": bounds.iter().map(|b| b.map(|b| b.extra_cells)).collect::<Vec<_>>(),
            "input_extra_frames": bounds.iter().map(|b| b.map(|b| b.extra_frames)).collect::<Vec<_>>(),
            "preflight": format!("{:?}", case.preflight), "outcome": format!("{:?}", case.outcome),
        })
    }).collect())
}

pub fn mutations() -> serde_json::Value {
    let mut results = vec![];
    for name in [
        "constants_4096x3",
        "chain_768",
        "balanced_768",
        "hash_blocks_64",
        "signatures_38",
    ] {
        let base = &case(name).transaction;
        let input = base.inputs[0]
            .as_any()
            .downcast_ref::<ContractInput>()
            .expect("contract");
        let stride = (input.program.len() * 8 / 128).max(1);
        for bit in (0..input.program.len() * 8).step_by(stride) {
            let mut input = input.clone();
            input.program[bit / 8] ^= 1 << (bit % 8);
            let mut transaction = base.clone();
            transaction.inputs[0] = DynInput::from_typed(MODULE, input);
            let start = Instant::now();
            let outcome = resources::check_transaction(&transaction);
            results.push(serde_json::json!({ "case": name, "bit": bit,
                "nanoseconds": start.elapsed().as_nanos(), "outcome": format!("{outcome:?}") }));
        }
    }
    serde_json::json!({"note": "One timing sample per deterministic bit mutation; ranking only, not benchmark medians", "mutations": results})
}
