//! Opt-in large-history module recovery probe. The transport is simulated;
//! transaction validation, RocksDB, quorum querying and wallet replay are real.
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use fedimint_core::module::CommonModuleInit;
use fedimint_derive_secret::DerivableSecret;
use fedimint_simplicity_client::descriptor::{BuiltinTemplates, ContractDescriptor, WalletKeys};
use fedimint_simplicity_client::receipt::{ReceiptContext, SenderReceipt};
use fedimint_simplicity_client::wallet::{SessionHistory, WalletContract, WalletStore};
use serde::{Deserialize, Serialize};

use super::*;

#[path = "scale_api.rs"]
mod api;

#[derive(Serialize, Deserialize)]
struct ExpectedHistory {
    txid: TransactionId,
    encoded_hash: [u8; 32],
    session: u64,
    consumed: Vec<OutPoint>,
    received: Vec<OutPoint>,
    sent: Option<SenderReceipt>,
}

#[derive(Default, Serialize, Deserialize)]
struct Expected {
    accepted: u64,
    contracts: Vec<(OutPoint, WalletContract)>,
    history: Vec<ExpectedHistory>,
}

pub fn run(spec: &str) {
    if cfg!(feature = "bench-alloc") {
        panic!("use the normal allocator");
    }
    let parts: Vec<_> = spec.split(',').collect();
    let [count, stride] = parts.as_slice() else {
        panic!("expected operations,owned_every");
    };
    let count: u32 = count.parse().expect("operations");
    let stride: u32 = stride.parse().expect("owned_every");
    assert!((100..=1_000_000).contains(&count));
    assert!((1..=1000).contains(&stride) && count.is_multiple_of(stride * 4));
    let directory = tempfile::tempdir().expect("scale directory");
    runtime().block_on(generate(directory.path(), count, stride));
    // Fresh processes separate recovery RSS from generation, and ensure the
    // interrupted wallet reopens RocksDB after an abrupt process exit.
    for phase in ["clean", "interrupt", "resume"] {
        let result = Command::new(std::env::current_exe().expect("benchmark executable"))
            .env_remove("FM_SIMPLICITY_BENCH_SCALE")
            .env("FM_SIMPLICITY_BENCH_RECOVER", directory.path())
            .env("FM_SIMPLICITY_BENCH_RECOVER_PHASE", phase)
            .output()
            .expect("recovery process");
        assert_eq!(
            result.status.code(),
            Some(if phase == "interrupt" { 77 } else { 0 }),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        print!("{}", String::from_utf8(result.stdout).expect("JSON output"));
    }
}

pub fn worker(path: &Path, phase: &str) {
    runtime().block_on(recover(path, phase));
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("scale runtime")
}
fn root(seed: u8) -> DerivableSecret {
    // Fixed stand-in for the mnemonic-derived module root. No original wallet
    // database, external backup or saved descriptor is read during recovery.
    DerivableSecret::new_root(&[seed; 32], b"simplicity-scale")
}
fn decoders() -> ModuleDecoderRegistry {
    ModuleDecoderRegistry::from_iter([
        (
            MODULE,
            fedimint_simplicity_common::KIND,
            fedimint_simplicity_common::SimplicityCommonInit::decoder(),
        ),
        (
            FUNDING_MODULE,
            fedimint_dummy_common::KIND,
            fedimint_dummy_common::DummyCommonInit::decoder(),
        ),
    ])
}
async fn database(path: &Path) -> Database {
    Database::new(
        fedimint_rocksdb::RocksDb::build(path)
            .open()
            .await
            .expect("RocksDB"),
        decoders(),
    )
}

async fn generate(path: &Path, count: u32, stride: u32) {
    let fixture = build("unit_v1");
    let (db, modules) = fixture
        .core_database_on(database(&path.join("guardian")).await)
        .await;
    let module_db = db.with_prefix_module_id(MODULE).0;
    let mut clean = module_db.begin_transaction().await;
    clean
        .remove_entry(&ContractKey(fixture.inputs[0].outpoint))
        .await;
    clean.commit_tx().await;
    let own = WalletKeys::new(&root(1), federation(), MODULE);
    let foreign = WalletKeys::new(&root(2), federation(), MODULE);
    let foreign_descriptor = ContractDescriptor::owner([2; 32]);
    let foreign_program = foreign
        .program(&foreign_descriptor, &BuiltinTemplates)
        .expect("foreign program")
        .1;
    let mut expected = Expected::default();
    let mut history = vec![];
    let begin = Instant::now();
    for index in 0..count {
        let owned = index.is_multiple_of(stride);
        let kind = if owned { (index / stride) % 4 } else { 4 };
        let descriptor = if kind == 2 || !owned {
            foreign_descriptor.clone()
        } else {
            ContractDescriptor {
                application_data: index.to_be_bytes().to_vec(),
                ..ContractDescriptor::owner(index.consensus_hash_sha256().to_byte_array())
            }
        };
        let keys = if kind == 2 || !owned { &foreign } else { &own };
        let program = if kind == 2 || !owned {
            foreign_program.clone()
        } else {
            keys.program(&descriptor, &BuiltinTemplates)
                .expect("owner program")
                .1
        };
        let mut annotation_descriptor = descriptor.clone();
        if !owned && index.is_multiple_of(4) {
            annotation_descriptor.application_data = vec![42; 800];
        }
        let mut bundle = AssetBundle::default();
        let mut creator = None;
        let mut actions = AssetActions::default();
        if kind == 3 {
            let key = own.signing_key(&descriptor);
            let (creation, mut ids) =
                assets::creation(federation(), MODULE, &key, vec![0, 0]).expect("assets");
            ids.sort();
            bundle.authorities = ids;
            actions.creations.push(creation);
            creator = Some(key);
        }
        let output = program
            .asset_output(
                Amount::from_sats(1),
                index.consensus_hash_sha256().to_byte_array(),
                keys.encrypt(&annotation_descriptor).expect("annotation"),
                bundle.clone(),
            )
            .expect("output");
        let mut outputs = vec![DynOutput::from_typed(MODULE, output.clone())];
        let sent = (kind == 2).then(|| SenderReceipt {
            context: Some(ReceiptContext {
                application: "scale".to_owned(),
                version: 1,
                data: index.to_be_bytes().to_vec(),
            }),
        });
        if kind == 2 || kind == 3 {
            let mut action = assets::action_output(actions).expect("action");
            if let Some(receipt) = &sent {
                action.recovery = receipt_placeholder(receipt);
            }
            outputs.push(DynOutput::from_typed(MODULE, action));
        }
        let mut tx = funded(vec![], outputs, 0, index);
        if let Some(creator) = creator {
            assets::sign_creation(&mut tx, federation(), MODULE, &creator)
                .expect("creation signature");
        }
        if let Some(receipt) = &sent {
            attach_receipt(&mut tx, receipt);
        }
        sign_transaction(&mut tx, &[key()]).expect("outer signature");
        let point = OutPoint {
            txid: tx.tx_hash(),
            out_idx: 0,
        };
        let recognized = owned && kind != 2;
        if owned {
            expected.history.push(ExpectedHistory {
                txid: point.txid,
                encoded_hash: tx.consensus_hash_sha256().to_byte_array(),
                session: expected.accepted / 100,
                consumed: vec![],
                received: if recognized { vec![point] } else { vec![] },
                sent,
            });
        }
        if recognized {
            expected.contracts.push((
                point,
                WalletContract {
                    output,
                    descriptor: descriptor.clone(),
                    creation_session: expected.accepted / 100,
                    spent_by: None,
                },
            ));
        }
        storage::commit(&db, &modules, tx, &mut history, &mut expected.accepted).await;
        if kind == 1 || kind == 3 {
            let outputs = if kind == 3 {
                let amounts: Vec<_> = bundle
                    .authorities
                    .iter()
                    .enumerate()
                    .map(|(i, id)| AssetAmount {
                        asset: *id,
                        quantity: 7 + i as u64,
                    })
                    .collect();
                bundle.balances = amounts.clone();
                vec![
                    DynOutput::from_typed(
                        MODULE,
                        program
                            .asset_output(
                                Amount::from_sats(1),
                                [0; 32],
                                own.encrypt(&descriptor).expect("successor annotation"),
                                bundle,
                            )
                            .expect("successor"),
                    ),
                    DynOutput::from_typed(
                        MODULE,
                        assets::action_output(AssetActions {
                            issuance: amounts,
                            ..Default::default()
                        })
                        .expect("issue"),
                    ),
                ]
            } else {
                vec![DynOutput::from_typed(
                    FUNDING_MODULE,
                    DummyOutput {
                        amount: Amount::from_sats(1),
                        unit: AmountUnit::BITCOIN,
                    },
                )]
            };
            let tx = spend(
                point,
                &expected.contracts.last().expect("owned contract").1,
                outputs,
                index,
            );
            let id = tx.tx_hash();
            expected
                .contracts
                .last_mut()
                .expect("owned contract")
                .1
                .spent_by = Some(id);
            let received = if kind == 3 {
                let point = OutPoint {
                    txid: id,
                    out_idx: 0,
                };
                expected.contracts.push((
                    point,
                    WalletContract {
                        output: tx.outputs[0]
                            .as_any()
                            .downcast_ref::<ContractOutput>()
                            .expect("successor")
                            .clone(),
                        descriptor: descriptor.clone(),
                        creation_session: expected.accepted / 100,
                        spent_by: None,
                    },
                ));
                vec![point]
            } else {
                vec![]
            };
            expected.history.push(ExpectedHistory {
                txid: id,
                encoded_hash: tx.consensus_hash_sha256().to_byte_array(),
                session: expected.accepted / 100,
                consumed: vec![point],
                received,
                sent: None,
            });
            storage::commit(&db, &modules, tx, &mut history, &mut expected.accepted).await;
        }
        if index > 0 && index.is_multiple_of(100_000) {
            eprintln!("generated {index}/{count} operations");
        }
    }
    if !history.is_empty() {
        storage::save_history(&db, &mut history, (expected.accepted - 1) / 100).await;
    }
    let generation_seconds = Instant::now().duration_since(begin).as_secs_f64();
    std::fs::write(
        path.join("expected.json"),
        serde_json::to_vec(&expected).expect("expectations"),
    )
    .expect("write oracle");
    let records = storage::summarize(&db, false).await;
    let checkpoint = path.join("guardian-checkpoint");
    db.checkpoint(&checkpoint).expect("guardian checkpoint");
    println!(
        "{}",
        serde_json::json!({"phase":"generate", "operations":count, "owned_every":stride, "accepted_transactions":expected.accepted, "owned_contracts":expected.contracts.len(), "owned_history":expected.history.len(), "seconds":generation_seconds, "database_records_count_and_bytes":records, "checkpoint_bytes":storage::directory_size(&checkpoint).0})
    );
}

fn funded(
    inputs: Vec<DynInput>,
    outputs: Vec<DynOutput>,
    input_msats: u64,
    index: u32,
) -> Transaction {
    let fee: u64 = inputs
        .iter()
        .map(|i| {
            runtime::input_fee(i.as_any().downcast_ref::<ContractInput>().expect("input"))
                .expect("fee")
                .msats
        })
        .sum::<u64>()
        + outputs
            .iter()
            .filter_map(|o| o.as_any().downcast_ref::<ContractOutput>())
            .map(|o| output_fee(o).msats)
            .sum::<u64>();
    let out: u64 = outputs
        .iter()
        .map(|o| {
            o.as_any()
                .downcast_ref::<ContractOutput>()
                .map(|o| o.amount.msats)
                .or_else(|| {
                    o.as_any()
                        .downcast_ref::<DummyOutput>()
                        .map(|o| o.amount.msats)
                })
                .expect("output amount")
        })
        .sum();
    storage::transaction(
        inputs,
        outputs,
        (out + fee).checked_sub(input_msats).expect("funding"),
        index,
    )
}
fn spend(
    point: OutPoint,
    contract: &WalletContract,
    outputs: Vec<DynOutput>,
    index: u32,
) -> Transaction {
    let keys = WalletKeys::new(&root(1), federation(), MODULE);
    let owner = keys.signing_key(&contract.descriptor);
    let program = keys
        .program(&contract.descriptor, &BuiltinTemplates)
        .expect("recovered program")
        .1;
    let input = program
        .input(
            point,
            owner.public_key(),
            witnesses([("SIGNATURE", placeholder_signature())]),
        )
        .expect("input");
    let mut tx = funded(
        vec![DynInput::from_typed(MODULE, input)],
        outputs,
        contract.output.amount.msats,
        index,
    );
    let signature =
        assets::signature_value(federation(), MODULE, &tx, &owner).expect("policy signature");
    tx.inputs[0] = DynInput::from_typed(
        MODULE,
        program
            .input(
                point,
                owner.public_key(),
                witnesses([("SIGNATURE", signature)]),
            )
            .expect("signed input"),
    );
    sign_transaction(&mut tx, &[owner, key()]).expect("outer signature");
    tx
}

// Synthetic receipt construction uses the public commitment and the pinned v1
// envelope/KDF. Replay must recognize and check the exact application context;
// the network tests separately exercise the production submission finalizer.
fn receipt_placeholder(receipt: &SenderReceipt) -> Vec<u8> {
    let mut bytes = b"FMR1".to_vec();
    bytes.resize(
        32 + ([0u8; 32], 1u16, receipt).consensus_encode_to_vec().len(),
        0,
    );
    bytes
}
fn attach_receipt(tx: &mut Transaction, receipt: &SenderReceipt) {
    let secret = root(1)
        .tweak(
            &(
                "fedimint/simplicity/wallet/v1".to_owned(),
                federation(),
                MODULE,
            )
                .consensus_encode_to_vec(),
        )
        .tweak(b"sender receipts");
    let plaintext = (
        fedimint_simplicity_client::receipt::commitment(federation(), MODULE, tx),
        1u16,
        receipt,
    )
        .consensus_encode_to_vec();
    let mut output = tx.outputs[1]
        .as_any()
        .downcast_ref::<ContractOutput>()
        .expect("receipt output")
        .clone();
    let mut bytes = b"FMR1".to_vec();
    bytes.extend(
        fedimint_aead::encrypt(
            plaintext,
            &fedimint_aead::LessSafeKey::new(secret.to_chacha20_poly1305_key()),
        )
        .expect("encrypt receipt"),
    );
    assert_eq!(bytes.len(), output.recovery.len());
    output.recovery = bytes;
    tx.outputs[1] = DynOutput::from_typed(MODULE, output);
}

async fn recover(path: &Path, phase: &str) {
    use std::sync::atomic::Ordering;
    // Only the oracle verifier below reads expected.json. The recovery itself
    // obtains its boundary and history from the simulated guardian API.
    let guardian = database(&path.join("guardian")).await;
    let api = api::HistoryApi::new(guardian.clone()).await;
    let stats = api.stats.clone();
    let global = api.into_global();
    let version = if std::env::var_os("FM_SIMPLICITY_BENCH_LEGACY_HISTORY").is_some() {
        fedimint_core::module::ApiVersion::new(0, 0)
    } else {
        fedimint_api_client::api::VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2
    };
    let history_api = SessionHistory::new(
        global,
        decoders(),
        version,
        Some(
            storage::history_keys()
                .into_iter()
                .map(|(peer, key)| (peer, key.public_key()))
                .collect(),
        ),
    );
    let wallet_path = path.join(if phase == "clean" {
        "wallet-clean"
    } else {
        "wallet-resume"
    });
    let begin = Instant::now();
    let wallet_db = database(&wallet_path).await;
    let wallet = WalletStore::open(
        wallet_db.clone(),
        &root(1),
        federation(),
        MODULE,
        Arc::new(BuiltinTemplates),
    )
    .await
    .expect("wallet");
    let start = wallet.next_session().await;
    assert_eq!(start > 0, phase == "resume");
    assert_eq!(wallet.is_recovering().await, phase == "resume");
    wallet.sync(&history_api, |done, total| {
        if phase == "interrupt" && done > 0 && done == total / 2 {
            println!("{}", serde_json::json!({"phase":phase,"seconds":Instant::now().duration_since(begin).as_secs_f64(), "next_session":done, "target":total,"response_json_bytes":stats.bytes.load(Ordering::Relaxed),"peak_rss_bytes":peak_rss()}));
            // Abrupt process termination: no wallet/API/database destructor runs.
            std::process::exit(77);
        }
    }).await.expect("mnemonic recovery");
    let seconds = Instant::now().duration_since(begin).as_secs_f64();
    let recovery_rss = peak_rss();
    let response_json_bytes = stats.bytes.load(Ordering::Relaxed);
    let requests = stats.requests.load(Ordering::Relaxed);
    assert!(!wallet.is_recovering().await);
    assert_eq!(stats.min_index.load(Ordering::Relaxed), start);
    let enumerate = Instant::now();
    let contracts = wallet.contracts().await;
    let history = wallet.history().await;
    let enumeration_seconds = Instant::now().duration_since(enumerate).as_secs_f64();
    let enumeration_rss = peak_rss();
    let expected: Expected =
        serde_json::from_slice(&std::fs::read(path.join("expected.json")).expect("oracle file"))
            .expect("oracle");
    let actual: BTreeMap<_, _> = contracts.iter().cloned().collect();
    let expected_contracts: BTreeMap<_, _> = expected.contracts.into_iter().collect();
    assert_eq!(actual, expected_contracts);
    assert_eq!(history.len(), expected.history.len());
    for (actual, expected) in history.iter().zip(&expected.history) {
        assert_eq!(actual.transaction.tx_hash(), expected.txid);
        assert_eq!(
            actual.transaction.consensus_hash_sha256().to_byte_array(),
            expected.encoded_hash,
            "complete transaction encoding, including witness and signature bytes"
        );
        assert_eq!(actual.session, expected.session);
        assert_eq!(actual.consumed, expected.consumed);
        assert_eq!(actual.received, expected.received);
        assert_eq!(actual.sent, expected.sent);
    }
    // A second sync cannot duplicate history or holdings.
    wallet
        .sync(&history_api, |_, _| {})
        .await
        .expect("idempotent sync");
    assert_eq!(wallet.history().await, history);
    assert_eq!(wallet.contracts().await, contracts);
    let modules = core_modules();
    let mut checked = [false; 2];
    for (point, contract) in &contracts {
        if contract.spent_by.is_some() {
            continue;
        }
        let bundle = contract.output.bundle().expect("bundle");
        let index = usize::from(!bundle.authorities.is_empty());
        if checked[index] {
            continue;
        }
        let mut outputs = vec![DynOutput::from_typed(
            FUNDING_MODULE,
            DummyOutput {
                amount: contract.output.amount,
                unit: AmountUnit::BITCOIN,
            },
        )];
        if !bundle.balances.is_empty() {
            outputs.push(DynOutput::from_typed(
                MODULE,
                assets::action_output(AssetActions {
                    burns: bundle.balances.clone(),
                    ..Default::default()
                })
                .expect("burn"),
            ));
        }
        let tx = spend(*point, contract, outputs, u32::MAX);
        assert!(process_core(&guardian, &modules, &tx).await.is_ok());
        checked[index] = true;
    }
    assert_eq!(
        checked,
        [true, true],
        "recovered native and asset authority spends"
    );
    let checkpoint = path.join(format!("{phase}-checkpoint"));
    wallet_db
        .checkpoint(&checkpoint)
        .expect("wallet checkpoint");
    println!(
        "{}",
        serde_json::json!({"phase":phase,"seconds":seconds,"start_session":start,"end_session":wallet.next_session().await,"owned_contracts":contracts.len(),"owned_history":history.len(),"response_json_bytes":response_json_bytes,"requests":requests,"peak_rss_bytes":recovery_rss,"enumeration_seconds":enumeration_seconds,"enumeration_peak_rss_bytes":enumeration_rss,"wallet_checkpoint_bytes":storage::directory_size(&checkpoint).0})
    );
}

#[cfg(unix)]
fn peak_rss() -> u64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    let peak = unsafe { usage.assume_init() }.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        peak
    } else {
        peak * 1024
    }
}

#[cfg(not(unix))]
fn peak_rss() -> u64 {
    panic!("RSS measurements require a Unix host");
}
