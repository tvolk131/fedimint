use std::collections::BTreeMap;
use std::sync::{Arc, LazyLock};

use bitcoin::hashes::{Hash, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::core::{DynInput, DynOutput};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{AmountUnit, CoreConsensusVersion};
use fedimint_core::secp256k1::{Keypair, Message, SECP256K1, SecretKey};
use fedimint_core::transaction::{Transaction, TransactionError, TransactionSignature};
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_dummy_common::config::{DummyConfig, DummyConfigConsensus, DummyConfigPrivate};
use fedimint_dummy_common::{DummyInput, DummyOutput};
use fedimint_dummy_server::Dummy;
use fedimint_server::consensus::transaction::{TxProcessingMode, process_transaction_with_dbtx};
use fedimint_server_core::{
    DynServerModule, ModuleTransactionContext, ServerModule, ServerModuleRegistry,
    TransactionConsensusContext,
};
use fedimint_simplicity_client::compiler::{Value, ValueConstructible, arguments, witnesses};
use fedimint_simplicity_client::{
    ContractProgram, assets, market, placeholder_signature, sign_transaction,
};
use fedimint_simplicity_common::assets::{
    AssetActions, AssetAmount, AssetBundle, AssetExtension, AssetId, AssetRecord,
};
use fedimint_simplicity_common::jet::FedimintJet;
use fedimint_simplicity_common::runtime::{self, Environment, EnvironmentInput, EnvironmentOutput};
use fedimint_simplicity_common::{
    ContractError, ContractInput, ContractOutput, ContractOutputError, MAX_PROGRAM_BYTES,
    MAX_WITNESS_BYTES, output_fee, resources,
};
use fedimint_simplicity_server::Simplicity;
use fedimint_simplicity_server::db::{AssetKey, BlockVoteKey, ContractKey, StoredContract};
use simplicity::jet::Core;
use simplicity::node::CoreConstructible;
use simplicity::{BitWriter, ConstructNode, encode};

#[path = "adversarial.rs"]
pub mod adversarial;

pub const MODULE: u16 = 4;
const FUNDING_MODULE: u16 = 5;
pub const EXECUTION_CASES: &[&str] = &[
    "unit_v0",
    "unit_v1",
    "owner",
    "market_issue",
    "market_resolve",
    "bad_oracle",
    "cost_near_limit",
    "signature_cost_near_limit",
    "wide_value",
    "large_constant",
    "large_witness",
];
pub const DECODE_CASES: &[&str] = &[
    "unit_v0",
    "owner",
    "market_issue",
    "market_resolve",
    "cost_near_limit",
    "signature_cost_near_limit",
    "wide_value",
    "large_constant",
    "large_witness",
    "cost_over_limit",
    "type_over_limit",
    "truncated_word",
    "impossible_nodes",
    "oversize_program",
    "oversize_witness",
    "trailing_witness",
];
pub const TRANSACTION_CASES: &[&str] = &[
    "unit_v0",
    "unit_v1",
    "owner",
    "market_issue",
    "market_resolve",
    "bad_oracle",
    "inputs_8",
    "inputs_32",
    "context_32",
    "recovery_32",
    "assets_32",
    "foreign_outputs_128",
    "cost_near_limit",
    "signature_cost_near_limit",
    "cost_32",
    "signature_cost_32",
    "asset_failure",
    "late_bad_signature",
    "signature_budget",
    "signature_split_budget",
    "signature_budget_over",
    "constants_3",
    "constants_4",
    "creation_19",
    "creation_20",
];

pub fn federation() -> FederationId {
    FederationId(sha256::Hash::hash(b"simplicity-resource-benchmark-v1"))
}

fn key() -> Keypair {
    Keypair::from_secret_key(
        SECP256K1,
        &SecretKey::from_slice(&[1; 32]).expect("fixed secret"),
    )
}

fn point(index: u64) -> OutPoint {
    OutPoint {
        txid: TransactionId::from_raw_hash(sha256::Hash::hash(b"benchmark-utxos")),
        out_idx: index,
    }
}

pub fn executor() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("benchmark executor")
}

pub struct Fixture {
    pub transaction: Transaction,
    pub inputs: Vec<ContractInput>,
    pub environments: Vec<Environment>,
    consumed: Vec<ContractOutput>,
    records: BTreeMap<AssetId, AssetRecord>,
    decode_error: Option<ContractError>,
    execution_error: Option<ContractError>,
    validation_error: Option<ContractError>,
    preflight_error: Option<ContractError>,
}

static FIXTURES: LazyLock<BTreeMap<&str, Fixture>> = LazyLock::new(|| {
    DECODE_CASES
        .iter()
        .chain(EXECUTION_CASES)
        .chain(TRANSACTION_CASES)
        .map(|name| (*name, ()))
        .collect::<BTreeMap<_, _>>()
        .into_keys()
        .map(|name| (name, build(name)))
        .collect()
});

pub fn case(name: &str) -> &'static Fixture {
    FIXTURES.get(name).expect("registered benchmark fixture")
}

impl Fixture {
    pub fn signature_hash(&self) -> [u8; 32] {
        let hash = if self.consumed[0].version == 0 {
            fedimint_simplicity_common::signature_hash(federation(), MODULE, &self.transaction)
        } else {
            fedimint_simplicity_common::assets::signature_hash_v1(
                federation(),
                MODULE,
                &self.transaction,
            )
        };
        hash.expect("bounded fixture transaction")
    }

    pub async fn database(&self) -> Database {
        let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
        self.seed(&db).await;
        db
    }

    async fn seed(&self, db: &Database) {
        let mut dbtx = db.begin_transaction().await;
        for (input, output) in self.inputs.iter().zip(&self.consumed) {
            dbtx.insert_new_entry(
                &ContractKey(input.outpoint),
                &StoredContract {
                    output: output.clone(),
                    creation_session: 0,
                    creation_block_count: 0,
                },
            )
            .await;
        }
        for (id, record) in &self.records {
            dbtx.insert_new_entry(&AssetKey(*id), record).await;
        }
        dbtx.insert_new_entry(&BlockVoteKey(0.into()), &5u64).await;
        dbtx.commit_tx().await;
    }

    pub fn funded_transaction(&self) -> Transaction {
        let mut transaction = self.transaction.clone();
        transaction.inputs.push(DynInput::from_typed(
            FUNDING_MODULE,
            DummyInput {
                amount: Amount::from_sats(100_000),
                unit: AmountUnit::BITCOIN,
                pub_key: key().public_key(),
            },
        ));
        // Foreign funding is excluded from all inner Simplicity signatures.
        let keys = vec![key(); transaction.inputs.len()];
        sign_transaction(&mut transaction, &keys).expect("funded outer signatures");
        assert!(transaction.consensus_encode_to_vec().len() <= Transaction::MAX_TX_SIZE);
        transaction
    }

    pub async fn core_database(&self) -> (Database, ServerModuleRegistry) {
        let db = Database::new(
            MemDatabase::new(),
            ModuleDecoderRegistry::new([
                (
                    MODULE,
                    fedimint_simplicity_common::KIND,
                    Simplicity::decoder(),
                ),
                (
                    FUNDING_MODULE,
                    fedimint_dummy_common::KIND,
                    Dummy::decoder(),
                ),
            ]),
        );
        self.seed(&db.with_prefix_module_id(MODULE).0).await;
        let modules = ServerModuleRegistry::new([
            (
                MODULE,
                fedimint_simplicity_common::KIND,
                DynServerModule::from(
                    Simplicity::new_for_testing(vec![0.into()]).expect("one guardian"),
                ),
            ),
            (
                FUNDING_MODULE,
                fedimint_dummy_common::KIND,
                DynServerModule::from(Dummy::new(DummyConfig {
                    private: DummyConfigPrivate,
                    consensus: DummyConfigConsensus,
                })),
            ),
        ]);
        (db, modules)
    }

    fn finish(&mut self) {
        self.transaction.inputs = self
            .inputs
            .iter()
            .cloned()
            .map(|input| DynInput::from_typed(MODULE, input))
            .collect();
        sign_transaction(&mut self.transaction, &vec![key(); self.inputs.len()])
            .expect("outer signatures");
        // Every case, including adversarial cases, fits the actual outer limit.
        assert!(self.transaction.consensus_encode_to_vec().len() <= Transaction::MAX_TX_SIZE);
        let outputs: Arc<[_]> = self
            .transaction
            .outputs
            .iter()
            .map(|output| EnvironmentOutput {
                module_id: output.module_instance_id(),
                hash: output.consensus_hash_sha256().to_byte_array(),
                contract: (output.module_instance_id() == MODULE).then(|| {
                    output
                        .as_any()
                        .downcast_ref::<ContractOutput>()
                        .expect("own output")
                        .clone()
                }),
            })
            .collect();
        let actions: Arc<AssetActions> = outputs
            .iter()
            .filter_map(|output| output.contract.as_ref()?.actions())
            .next()
            .cloned()
            .unwrap_or_default()
            .into();
        let inputs: Arc<[_]> = self
            .inputs
            .iter()
            .zip(&self.consumed)
            .map(|(input, output)| EnvironmentInput {
                outpoint: input.outpoint,
                contract: output.clone(),
            })
            .collect();
        self.environments = self
            .consumed
            .iter()
            .enumerate()
            .map(|(index, current)| Environment {
                inputs: inputs.clone(),
                outputs: outputs.clone(),
                actions: actions.clone(),
                signature_hash: self.signature_hash(),
                session_index: 10,
                block_count: 5,
                current: current.clone(),
                creation_session: 0,
                creation_block_count: 0,
                input_index: index as u32,
                input_count: self.inputs.len() as u32,
            })
            .collect();
    }
}

fn empty(program: Vec<u8>, witness: Vec<u8>, cmr: [u8; 32]) -> Fixture {
    Fixture {
        transaction: Transaction {
            inputs: vec![],
            outputs: vec![],
            nonce: [0; 8],
            signatures: TransactionSignature::NaiveMultisig(vec![]),
        },
        inputs: vec![ContractInput {
            outpoint: point(0),
            claim_key: key().public_key(),
            program,
            witness,
        }],
        consumed: vec![ContractOutput {
            version: 1,
            amount: Amount::from_msats(1_000_000),
            cmr,
            state: [0; 32],
            recovery: vec![],
            extension: Some(AssetExtension::Bundle(AssetBundle::default())),
        }],
        environments: vec![],
        records: BTreeMap::new(),
        decode_error: None,
        execution_error: None,
        validation_error: None,
        preflight_error: None,
    }
}

fn compiled(source: &str) -> Fixture {
    let program = ContractProgram::compile(source, arguments([])).expect("fixture compiles");
    let input = program
        .input(point(0), key().public_key(), witnesses([]))
        .expect("fixture satisfies");
    empty(input.program, input.witness, program.cmr())
}

fn duplicate(fixture: &mut Fixture, count: usize, outputs: bool) {
    fixture.inputs = (0..count)
        .map(|index| {
            let mut input = fixture.inputs[0].clone();
            input.outpoint = point(index as u64);
            input
        })
        .collect();
    fixture.consumed = vec![fixture.consumed[0].clone(); count];
    if outputs {
        fixture.transaction.outputs = fixture
            .consumed
            .iter()
            .cloned()
            .map(|output| DynOutput::from_typed(MODULE, output))
            .collect();
    }
}

// A shared DAG: tiny encodings may describe substantial execution/type work.
fn shared_program(levels: usize, wide: bool) -> Vec<u8> {
    simplicity::types::Context::with_context(|ctx| {
        let mut node: Arc<ConstructNode> = if wide {
            Arc::jet(&ctx, &FedimintJet::Core(Core::Sha256Iv))
        } else {
            Arc::unit(&ctx)
        };
        let mut half = node.clone();
        for _ in 0..levels {
            half = node.clone();
            node = if wide {
                Arc::pair(&node, &node)
            } else {
                Arc::comp(&node, &node)
            }
            .expect("shared DAG has matching types");
        }
        if !wide {
            node = Arc::comp(&node, &half).expect("three halves of a power of two");
        }
        Arc::comp(&node, &Arc::unit(&ctx))
            .expect("discard result")
            .finalize_types()
            .expect("closed types")
            .to_vec_without_witness()
    })
}

fn encoded(program: Vec<u8>, witness: Vec<u8>) -> Fixture {
    let mut fixture = empty(program, witness, [0; 32]);
    match runtime::decode_program(&fixture.inputs[0]) {
        Ok(program) => fixture.consumed[0].cmr = program.cmr().to_byte_array(),
        Err(error) => {
            fixture.decode_error = Some(error.clone());
            fixture.execution_error = Some(error.clone());
            fixture.validation_error = Some(error);
        }
    }
    fixture
}

fn build(name: &str) -> Fixture {
    let mut fixture = match name {
        "owner" | "late_bad_signature" => owner(name == "late_bad_signature"),
        "creation_19" | "creation_20" => creation_case(if name == "creation_19" { 19 } else { 20 }),
        "market_issue" | "market_resolve" | "bad_oracle" => market_case(name),
        "cost_near_limit" | "cost_32" | "cost_over_limit" => {
            // 3 * 2^14 unit executions fit near the cost cap; doubling does not.
            let mut fixture = encoded(
                shared_program(if name == "cost_over_limit" { 16 } else { 15 }, false),
                vec![],
            );
            assert_eq!(
                fixture.decode_error,
                (name == "cost_over_limit").then_some(ContractError::Limit)
            );
            if name == "cost_32" {
                duplicate(&mut fixture, 32, false);
            }
            fixture
        }
        "signature_cost_near_limit"
        | "signature_cost_32"
        | "signature_budget"
        | "signature_budget_over"
        | "signature_split_budget" => {
            let program = simplicity::types::Context::with_context(|ctx| {
                let mut bytes = [0; 128];
                bytes[..32].copy_from_slice(&key().x_only_public_key().0.serialize());
                bytes[64..].copy_from_slice(
                    SECP256K1
                        .sign_schnorr_no_aux_rand(&Message::from_digest([0; 32]), &key())
                        .as_ref(),
                );
                let word = simplicity::Value::from_byte_array(bytes)
                    .to_word()
                    .expect("signature word");
                let mut node: Arc<ConstructNode> = Arc::comp(
                    &Arc::const_word(&ctx, word),
                    &Arc::jet(&ctx, &FedimintJet::Core(Core::Bip0340Verify)),
                )
                .expect("verify signature");
                let mut half = node.clone();
                let levels = match name {
                    "signature_split_budget" => 3,
                    "signature_budget" => 5,
                    "signature_budget_over" => 6,
                    _ => 7,
                };
                for _ in 0..levels {
                    half = node.clone();
                    node = Arc::comp(&node, &node).expect("repeat signature check");
                }
                if name.starts_with("signature_cost") {
                    node = Arc::comp(&node, &half).expect("192 signature checks");
                }
                node.finalize_types()
                    .expect("closed types")
                    .to_vec_without_witness()
            });
            let mut fixture = encoded(program, vec![]);
            assert_eq!(fixture.decode_error, None);
            if name == "signature_cost_32" {
                duplicate(&mut fixture, 32, false);
            } else if name == "signature_split_budget" {
                duplicate(&mut fixture, 4, false);
            }
            fixture
        }
        "wide_value" | "type_over_limit" => {
            let fixture = encoded(
                shared_program(if name == "wide_value" { 12 } else { 32 }, true),
                vec![],
            );
            assert_eq!(
                fixture.decode_error,
                (name == "type_over_limit").then_some(ContractError::Limit)
            );
            fixture
        }
        "large_constant" | "constants_3" | "constants_4" => {
            let program = simplicity::types::Context::with_context(|ctx| {
                let word = simplicity::Value::from_byte_array([0x55; 4096])
                    .to_word()
                    .expect("power of two word");
                let node: Arc<ConstructNode> = Arc::const_word(&ctx, word);
                Arc::comp(&node, &Arc::unit(&ctx))
                    .expect("discard word")
                    .finalize_types()
                    .expect("closed types")
                    .to_vec_without_witness()
            });
            let mut fixture = encoded(program, vec![]);
            assert_eq!(fixture.decode_error, None);
            if name != "large_constant" {
                duplicate(
                    &mut fixture,
                    if name == "constants_3" { 3 } else { 4 },
                    false,
                );
            }
            fixture
        }
        "large_witness" => {
            let program = fedimint_simplicity_client::compiler::compile(
                "fn hash(block: (u256, u256), acc: u256) -> u256 { let (a, b): (u256, u256) = block; jet::sha_256_block(acc, a, b) } fn main() { let hash: u256 = array_fold::<hash, 128>(witness::DATA, jet::sha_256_iv()); }", arguments([])
            ).expect("large witness compiles");
            let block = Value::tuple([market::word([0; 32]), market::word([0; 32])]);
            let data = Value::array(vec![block.clone(); 128], block.ty().clone());
            let satisfied = program
                .satisfy(witnesses([("DATA", data)]))
                .expect("large witness satisfies");
            let (program, witness) = satisfied.redeem().to_vec_with_witness();
            assert_eq!(witness.len(), MAX_WITNESS_BYTES);
            let fixture = encoded(program, witness);
            assert_eq!(
                fixture.decode_error, None,
                "large witness within cost limits"
            );
            fixture
        }
        "truncated_word" | "impossible_nodes" => {
            let mut bytes = Vec::new();
            let mut bits = BitWriter::new(&mut bytes);
            encode::encode_natural(
                if name == "impossible_nodes" {
                    1_000_000
                } else {
                    1
                },
                &mut bits,
            )
            .expect("vec writer");
            if name == "truncated_word" {
                bits.write_bits_be(0b10, 2).expect("vec writer");
                encode::encode_natural(32, &mut bits).expect("vec writer");
            }
            bits.flush_all().expect("vec writer");
            let fixture = encoded(bytes, vec![]);
            assert_eq!(fixture.decode_error, Some(ContractError::Program));
            fixture
        }
        _ => compiled("fn main() {}"),
    };
    match name {
        "unit_v0" => {
            fixture.consumed[0].version = 0;
            fixture.consumed[0].extension = None;
        }
        "inputs_8" => duplicate(&mut fixture, 8, false),
        "inputs_32" => duplicate(&mut fixture, 32, false),
        "context_32" | "recovery_32" | "assets_32" | "asset_failure" => {
            if name == "recovery_32" {
                fixture.consumed[0].recovery = vec![42; 1024];
            }
            if name == "assets_32" || name == "asset_failure" {
                let balances = (1..=32)
                    .map(|index| AssetAmount {
                        asset: AssetId([index; 32]),
                        quantity: 1,
                    })
                    .collect::<Vec<_>>();
                for value in &balances {
                    fixture.records.insert(value.asset, record(value.asset));
                }
                fixture.consumed[0].extension = Some(AssetExtension::Bundle(AssetBundle {
                    balances,
                    authorities: vec![],
                }));
            }
            duplicate(&mut fixture, 32, true);
            if name == "asset_failure" {
                fixture.transaction.outputs.pop();
                fixture.validation_error = Some(ContractError::Assets);
            }
        }
        "foreign_outputs_128" => {
            duplicate(&mut fixture, 32, false);
            fixture.transaction.outputs = (0..128)
                .map(|_| {
                    DynOutput::from_typed(
                        5,
                        DummyOutput {
                            amount: Amount::ZERO,
                            unit: AmountUnit::BITCOIN,
                        },
                    )
                })
                .collect();
        }
        "oversize_program" | "oversize_witness" | "trailing_witness" => {
            if name == "oversize_program" {
                fixture.inputs[0].program = vec![0; MAX_PROGRAM_BYTES + 1];
            } else {
                fixture.inputs[0].witness = vec![
                    0;
                    if name == "oversize_witness" {
                        MAX_WITNESS_BYTES + 1
                    } else {
                        1
                    }
                ];
            }
            let error = if name == "trailing_witness" {
                ContractError::Program
            } else {
                ContractError::Limit
            };
            fixture.decode_error = Some(error.clone());
            fixture.execution_error = Some(error.clone());
            fixture.validation_error = Some(error);
        }
        _ => {}
    }
    fixture.finish();
    fixture.preflight_error = match name {
        "cost_near_limit"
        | "cost_32"
        | "signature_cost_near_limit"
        | "signature_cost_32"
        | "signature_budget_over"
        | "wide_value"
        | "large_witness"
        | "constants_4"
        | "creation_20" => Some(ContractError::Limit),
        _ => fixture.decode_error.clone(),
    };
    fixture
}

fn creation_case(count: u8) -> Fixture {
    let mut fixture = compiled("fn main() {}");
    let mut creators = vec![];
    let mut creations = vec![];
    let mut ids = vec![];
    for index in 0..count {
        let creator = Keypair::from_secret_key(
            SECP256K1,
            &SecretKey::from_slice(&[index + 2; 32]).expect("fixed creator"),
        );
        let (creation, created) =
            assets::creation(federation(), MODULE, &creator, vec![0]).expect("creation batch");
        creators.push(creator);
        creations.push(creation);
        ids.extend(created);
    }
    ids.sort();
    let mut authority = fixture.consumed[0].clone();
    authority.amount = Amount::ZERO;
    authority.extension = Some(AssetExtension::Bundle(AssetBundle {
        balances: vec![],
        authorities: ids,
    }));
    fixture.transaction.outputs = vec![
        DynOutput::from_typed(MODULE, authority),
        DynOutput::from_typed(
            MODULE,
            assets::action_output(AssetActions {
                creations,
                ..Default::default()
            })
            .expect("creation action"),
        ),
    ];
    fixture.finish();
    for creator in creators {
        assets::sign_creation(&mut fixture.transaction, federation(), MODULE, &creator)
            .expect("creation authorization");
    }
    fixture
}

fn record(id: AssetId) -> AssetRecord {
    AssetRecord {
        creation_key: key().public_key(),
        ordinal: u32::from(id.0[0]),
        authority_outpoint: point(1000 + u64::from(id.0[0])),
        authority_cmr: [0; 32],
        authority_state: [0; 32],
    }
}

fn owner(late_failure: bool) -> Fixture {
    let program = market::owner_program(key().x_only_public_key().0).expect("owner compiles");
    let input = program
        .input(
            point(0),
            key().public_key(),
            witnesses([("SIGNATURE", placeholder_signature())]),
        )
        .expect("placeholder");
    let mut fixture = empty(input.program, input.witness, program.cmr());
    duplicate(&mut fixture, if late_failure { 32 } else { 1 }, true);
    fixture.finish();
    let signature = assets::signature_value(federation(), MODULE, &fixture.transaction, &key())
        .expect("owner signature");
    for (index, input) in fixture.inputs.iter_mut().enumerate() {
        *input = program
            .input(
                point(index as u64),
                key().public_key(),
                witnesses([(
                    "SIGNATURE",
                    if late_failure && index == 31 {
                        placeholder_signature()
                    } else {
                        signature.clone()
                    },
                )]),
            )
            .expect("owner input");
    }
    if late_failure {
        fixture.validation_error = Some(ContractError::Rejected);
    }
    fixture
}

fn market_case(name: &str) -> Fixture {
    let yes = AssetId([1; 32]);
    let no = AssetId([2; 32]);
    let terms = market::BinaryMarket {
        federation: federation(),
        module: MODULE,
        yes,
        no,
        event: [3; 32],
        rules: [4; 32],
        oracle: key().x_only_public_key().0,
        resolution_start: 5,
        deadline: 10,
    };
    let program = terms.program().expect("market compiles");
    let signature = SECP256K1.sign_schnorr_no_aux_rand(
        &Message::from_digest(
            terms
                .attestation_message(if name == "bad_oracle" { 2 } else { 1 })
                .expect("oracle message"),
        ),
        &key(),
    );
    let input = program
        .input(
            point(0),
            key().public_key(),
            witnesses([
                (
                    "ACTION",
                    Value::u8(if name == "market_issue" { 0 } else { 2 }),
                ),
                ("OUTCOME", Value::u8(1)),
                ("ORACLE_SIGNATURE", Value::byte_array(*signature.as_ref())),
            ]),
        )
        .expect("market input");
    let mut fixture = empty(input.program, input.witness, program.cmr());
    fixture.consumed[0].extension = Some(AssetExtension::Bundle(AssetBundle {
        balances: vec![],
        authorities: vec![yes, no],
    }));
    fixture
        .records
        .extend([(yes, record(yes)), (no, record(no))]);
    let mut successor = fixture.consumed[0].clone();
    if name == "market_issue" {
        successor.amount += Amount::from_msats(1000);
    } else {
        successor.state = market::state(1).expect("YES state");
    }
    fixture
        .transaction
        .outputs
        .push(DynOutput::from_typed(MODULE, successor));
    if name == "market_issue" {
        let balances = vec![
            AssetAmount {
                asset: yes,
                quantity: 1,
            },
            AssetAmount {
                asset: no,
                quantity: 1,
            },
        ];
        let holding = market::owner_program(key().x_only_public_key().0)
            .expect("owner compiles")
            .asset_output(
                Amount::ZERO,
                [0; 32],
                vec![],
                AssetBundle {
                    balances: balances.clone(),
                    authorities: vec![],
                },
            )
            .expect("holding");
        fixture
            .transaction
            .outputs
            .push(DynOutput::from_typed(MODULE, holding));
        fixture.transaction.outputs.push(DynOutput::from_typed(
            MODULE,
            assets::action_output(AssetActions {
                issuance: balances,
                ..Default::default()
            })
            .expect("actions"),
        ));
    }
    if name == "bad_oracle" {
        fixture.execution_error = Some(ContractError::Rejected);
        fixture.validation_error = Some(ContractError::Rejected);
    }
    fixture
}

pub fn check_all() {
    let rt = executor();
    let module = Simplicity::new_for_testing(vec![0.into()]).expect("one guardian");
    for (name, fixture) in FIXTURES.iter() {
        assert_eq!(
            resources::check_transaction(&fixture.transaction).err(),
            fixture.preflight_error,
            "{name}: resource preflight"
        );
        assert_eq!(
            runtime::decode_program(&fixture.inputs[0]).err(),
            fixture.decode_error,
            "{name}: decode"
        );
        for (index, (input, environment)) in
            fixture.inputs.iter().zip(&fixture.environments).enumerate()
        {
            let expected = if *name == "late_bad_signature" && index == 31 {
                Some(ContractError::Rejected)
            } else {
                fixture.execution_error.clone()
            };
            assert_eq!(
                runtime::execute(input, environment).err(),
                expected,
                "{name}: input {index} execution"
            );
        }
        rt.block_on(async {
            let db = fixture.database().await;
            let result =
                validate_module(&module, &mut db.begin_transaction_nc().await, fixture).await;
            let error = result.err().map(|error| match error {
                TransactionError::Input(error) => error
                    .as_any()
                    .downcast_ref::<ContractError>()
                    .expect("Simplicity error")
                    .clone(),
                TransactionError::Output(error) => error
                    .as_any()
                    .downcast_ref::<ContractOutputError>()
                    .expect("Simplicity output error")
                    .0
                    .clone(),
                error => panic!("{name}: unexpected error {error}"),
            });
            assert_eq!(
                error,
                fixture
                    .preflight_error
                    .clone()
                    .or_else(|| fixture.validation_error.clone()),
                "{name}: guardian validation"
            );
            let transaction = fixture.funded_transaction();
            let (db, modules) = fixture.core_database().await;
            let expected = fixture
                .preflight_error
                .clone()
                .or_else(|| fixture.validation_error.clone());
            let error = process_core(&db, &modules, &transaction)
                .await
                .err()
                .map(contract_error);
            assert_eq!(error, expected, "{name}: funded core submission");
        });
    }
}

pub fn manifest() -> serde_json::Value {
    serde_json::json!({
        "schema": 2,
        "allocation_profiler": cfg!(feature = "bench-alloc"),
        "max_transaction_bytes": Transaction::MAX_TX_SIZE,
        "max_redemption_bytes": resources::MAX_TRANSACTION_REDEMPTION_BYTES,
        "max_transaction_milliweight": resources::MAX_TRANSACTION_MILLIWEIGHT,
        "creation_signature_milliweight": resources::CREATION_SIGNATURE_MILLIWEIGHT,
        "fixtures": FIXTURES.iter().map(|(name, fixture)| {
            let program = runtime::decode_program(&fixture.inputs[0]).ok();
            let bounds = program.as_ref().map(|program| program.bounds());
            serde_json::json!({
                "name": name,
                "transaction_sha256": fixture.transaction.tx_hash().to_string(),
                "transaction_bytes": fixture.transaction.consensus_encode_to_vec().len(),
                "funded_transaction_sha256": fixture.funded_transaction().tx_hash().to_string(),
                "funded_transaction_bytes": fixture.funded_transaction().consensus_encode_to_vec().len(),
                "inputs": fixture.inputs.len(), "outputs": fixture.transaction.outputs.len(),
                "first_program_bytes": fixture.inputs[0].program.len(),
                "first_witness_bytes": fixture.inputs[0].witness.len(),
                "first_cost_milliweight": bounds.map(|bounds| bounds.cost.to_string().parse::<u32>().expect("cost display is integer")),
                "first_extra_cells": bounds.map(|bounds| bounds.extra_cells),
                "first_extra_frames": bounds.map(|bounds| bounds.extra_frames),
                "input_fee_msat": fixture.inputs.iter().map(runtime::input_fee).collect::<Result<Vec<_>, _>>().ok().map(|fees| fees.iter().map(|fee| fee.msats).sum::<u64>()),
                "output_fee_msat": fixture.transaction.outputs.iter().filter_map(|output| output.as_any().downcast_ref::<ContractOutput>()).map(|output| output_fee(output).msats).sum::<u64>(),
                "decode_error": fixture.decode_error.as_ref().map(ToString::to_string),
                "validation_error": fixture.preflight_error.as_ref().or(fixture.validation_error.as_ref()).map(ToString::to_string),
                "preflight_error": fixture.preflight_error.as_ref().map(ToString::to_string),
            })
        }).collect::<Vec<_>>()
    })
}

pub async fn process_core(
    db: &Database,
    modules: &ServerModuleRegistry,
    transaction: &Transaction,
) -> Result<(), TransactionError> {
    // Each iteration starts from the same snapshot and drops all changes. This
    // includes MemDatabase snapshot creation and processing, but no commit/I/O.
    let mut dbtx = db.begin_transaction_nc().await;
    process_transaction_with_dbtx(
        modules.clone(),
        &mut dbtx.to_ref_nc(),
        transaction,
        CoreConsensusVersion::new(2, 1),
        TxProcessingMode::Submission,
        TransactionConsensusContext {
            federation_id: federation(),
            session_index: 10,
        },
    )
    .await
}

fn contract_error(error: TransactionError) -> ContractError {
    match error {
        TransactionError::Input(error) => error
            .as_any()
            .downcast_ref::<ContractError>()
            .expect("Simplicity input error")
            .clone(),
        TransactionError::Output(error) => error
            .as_any()
            .downcast_ref::<ContractOutputError>()
            .expect("Simplicity output error")
            .0
            .clone(),
        error => panic!("unexpected core error: {error}"),
    }
}

/// All production module phases, excluding foreign funding/signatures and
/// writes.
pub async fn validate_module(
    module: &Simplicity,
    dbtx: &mut fedimint_core::db::DatabaseTransaction<'_>,
    fixture: &Fixture,
) -> Result<fedimint_server_core::ModuleTransactionValidation, TransactionError> {
    let mut context = ModuleTransactionContext {
        transaction: &fixture.transaction,
        consensus: TransactionConsensusContext {
            federation_id: federation(),
            session_index: 10,
        },
        module_instance_id: MODULE,
        preparation: None,
        validation: None,
    };
    <Simplicity as ServerModule>::verify_transaction(&context)?;
    let resolved = module.prepare_transaction(dbtx, &context).await?;
    let prepared = <Simplicity as ServerModule>::prepare_kind_transaction(
        &context,
        BTreeMap::from([(MODULE, resolved)]),
    )?;
    context.preparation = Some(&prepared);
    module.validate_transaction(dbtx, &context).await
}
