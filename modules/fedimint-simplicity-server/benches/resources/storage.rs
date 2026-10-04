//! Persistent record sizing using real validation, synthetic funding and signed
//! 100-transaction history batches. Does not run networking or Aleph consensus.
use std::io::Write;
use std::path::Path;

use fedimint_core::db::IDatabaseTransactionOpsCore;
use fedimint_core::session_outcome::{
    AcceptedItem, ConsensusItem, SessionOutcome, SignedSessionOutcome,
};
use fedimint_server::consensus::db::{AcceptedTransactionKey, SignedSessionOutcomeKey};
use futures::StreamExt;

use super::*;

pub fn run(spec: &str) {
    let parts: Vec<_> = spec.split(',').collect();
    let [scenario, count] = parts.as_slice() else {
        panic!("expected bare|live|receipt|assets1|assets32|churn,count");
    };
    assert!(["bare", "live", "receipt", "assets1", "assets32", "churn"].contains(scenario));
    let count: u32 = count.parse().expect("count");
    assert!((1..=1_000_000).contains(&count));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("storage runtime");
    rt.block_on(measure(scenario, count));
}

async fn measure(scenario: &str, count: u32) {
    let directory = tempfile::tempdir().expect("storage directory");
    let db = Database::new(
        fedimint_rocksdb::RocksDb::build(directory.path().join("db"))
            .open()
            .await
            .expect("RocksDB"),
        ModuleDecoderRegistry::default(),
    );
    let fixture = build("unit_v1");
    let (db, modules) = fixture.core_database_on(db).await;
    let module_db = db.with_prefix_module_id(MODULE).0;
    let mut clean = module_db.begin_transaction().await;
    clean
        .remove_entry(&ContractKey(fixture.inputs[0].outpoint))
        .await;
    clean.commit_tx().await;
    let mut history = vec![];
    let mut accepted = 0u64;
    let mut fees_msat = 0u64;
    let mut samples = vec![];
    for index in 0..count {
        let mut output = fixture.environments[0].current.clone();
        output.amount = Amount::ZERO;
        let mut outputs = vec![];
        let mut creator = None;
        if scenario.starts_with("assets") {
            let mut secret = [0; 32];
            secret[28..].copy_from_slice(&(index + 2).to_be_bytes());
            let key = Keypair::from_secret_key(
                SECP256K1,
                &SecretKey::from_slice(&secret).expect("creator"),
            );
            let assets_count = if scenario == "assets32" { 32 } else { 1 };
            let (creation, mut ids) =
                assets::creation(federation(), MODULE, &key, vec![0; assets_count])
                    .expect("creation");
            ids.sort();
            output.extension = Some(AssetExtension::Bundle(AssetBundle {
                balances: vec![],
                authorities: ids,
            }));
            outputs.push(DynOutput::from_typed(MODULE, output));
            outputs.push(DynOutput::from_typed(
                MODULE,
                assets::action_output(AssetActions {
                    creations: vec![creation],
                    ..Default::default()
                })
                .expect("actions"),
            ));
            creator = Some(key);
        } else {
            if scenario == "receipt" {
                output = assets::action_output(AssetActions::default()).expect("receipt action");
            }
            // Incompressible stand-in for encrypted annotations, unique per
            // record. No secrets or plaintext recovery descriptors.
            if scenario != "bare" {
                output.recovery = (0..32u32)
                    .flat_map(|block| (index, block).consensus_hash_sha256().to_byte_array())
                    .collect();
            }
            outputs.push(DynOutput::from_typed(MODULE, output));
        }
        let fee: u64 = outputs
            .iter()
            .map(|o| {
                output_fee(
                    o.as_any()
                        .downcast_ref::<ContractOutput>()
                        .expect("contract"),
                )
                .msats
            })
            .sum();
        let mut tx = transaction(vec![], outputs, fee, index);
        if let Some(creator) = creator {
            assets::sign_creation(&mut tx, federation(), MODULE, &creator)
                .expect("authorize creation");
        }
        sign_transaction(&mut tx, &[key()]).expect("outer signature");
        let point = OutPoint {
            txid: tx.tx_hash(),
            out_idx: 0,
        };
        if index.is_multiple_of(count.div_ceil(1024)) {
            let asset = tx.outputs[0]
                .as_any()
                .downcast_ref::<ContractOutput>()
                .and_then(ContractOutput::bundle)
                .and_then(|b| b.authorities.first())
                .copied();
            samples.push((point, asset));
        }
        commit(&db, &modules, tx, &mut history, &mut accepted).await;
        fees_msat += fee;
        if scenario == "churn" {
            let mut input = fixture.inputs[0].clone();
            input.outpoint = point;
            let fee = runtime::input_fee(&input).expect("unit fee").msats;
            let mut tx = transaction(
                vec![DynInput::from_typed(MODULE, input)],
                vec![],
                fee,
                index,
            );
            sign_transaction(&mut tx, &[key(), key()]).expect("spend signatures");
            commit(&db, &modules, tx, &mut history, &mut accepted).await;
            fees_msat += fee;
        }
    }
    if !history.is_empty() {
        save_history(&db, &mut history, (accepted - 1) / 100).await;
    }
    let records = summarize(&module_db, true).await;
    let record_count = |class| records.get(class).map_or(0, |(count, _)| *count);
    let expected_live = if ["receipt", "churn"].contains(&scenario) {
        0
    } else {
        count as usize
    };
    assert_eq!(record_count("live_contracts"), expected_live);
    let expected_namespaces = if scenario.starts_with("assets") {
        count as usize
    } else {
        0
    };
    assert_eq!(record_count("namespaces"), expected_namespaces);
    assert_eq!(
        record_count("asset_origins"),
        expected_namespaces * if scenario == "assets32" { 32 } else { 1 }
    );
    let database_records = summarize(&db, false).await;
    assert_eq!(database_records["accepted_index"].0 as u64, accepted);
    assert_eq!(
        database_records["signed_history"].0 as u64,
        accepted.div_ceil(100)
    );
    let logical_bytes: usize = database_records.values().map(|(_, bytes)| bytes).sum();
    let mut valid_spend = transaction(
        vec![DynInput::from_typed(
            MODULE,
            ContractInput {
                outpoint: samples[0].0,
                ..fixture.inputs[0].clone()
            },
        )],
        vec![],
        runtime::input_fee(&fixture.inputs[0]).expect("fee").msats,
        count,
    );
    sign_transaction(&mut valid_spend, &[key(), key()]).expect("spend signatures");
    let probes = probe(
        &db,
        &modules,
        &samples,
        &valid_spend,
        !["receipt", "churn"].contains(&scenario),
    )
    .await;
    let checkpoint = directory.path().join("checkpoint");
    db.checkpoint(&checkpoint).expect("flushed checkpoint");
    let (checkpoint_bytes, sst_bytes) = directory_size(&checkpoint);
    println!(
        "{}",
        serde_json::json!({"scenario": scenario, "operations": count, "probes": probes, "accepted_transactions": accepted, "module_fees_msat": fees_msat, "module_records_count_and_bytes": records, "database_logical_bytes": logical_bytes, "database_records_count_and_bytes": database_records, "checkpoint_bytes": checkpoint_bytes, "checkpoint_sst_bytes": sst_bytes})
    );
}

pub(super) fn transaction(
    mut inputs: Vec<DynInput>,
    outputs: Vec<DynOutput>,
    fee: u64,
    index: u32,
) -> Transaction {
    inputs.push(DynInput::from_typed(
        FUNDING_MODULE,
        DummyInput {
            amount: Amount::from_msats(fee),
            unit: AmountUnit::BITCOIN,
            pub_key: key().public_key(),
        },
    ));
    Transaction {
        inputs,
        outputs,
        nonce: u64::from(index).to_le_bytes(),
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    }
}

pub(super) async fn commit(
    db: &Database,
    modules: &ServerModuleRegistry,
    tx: Transaction,
    history: &mut Vec<AcceptedItem>,
    accepted: &mut u64,
) {
    let mut dbtx = db.begin_transaction().await;
    process_transaction_with_dbtx(
        modules.clone(),
        &mut dbtx.to_ref_nc(),
        &tx,
        CoreConsensusVersion::new(2, 1),
        TxProcessingMode::Consensus,
        TransactionConsensusContext {
            federation_id: federation(),
            session_index: *accepted / 100,
        },
    )
    .await
    .expect("funded storage workload");
    dbtx.insert_new_entry(
        &AcceptedTransactionKey(tx.tx_hash()),
        &tx.outputs
            .iter()
            .map(DynOutput::module_instance_id)
            .collect::<Vec<_>>(),
    )
    .await;
    dbtx.commit_tx().await;
    history.push(AcceptedItem {
        item: ConsensusItem::Transaction(tx),
        peer: 0.into(),
    });
    *accepted += 1;
    if history.len() == 100 {
        save_history(db, history, (*accepted - 1) / 100).await;
    }
}

pub(super) async fn save_history(db: &Database, history: &mut Vec<AcceptedItem>, index: u64) {
    let keys: BTreeMap<fedimint_core::PeerId, _> = (0..4u8)
        .map(|peer| {
            (
                u16::from(peer).into(),
                Keypair::from_secret_key(
                    SECP256K1,
                    &SecretKey::from_slice(&[peer + 10; 32]).expect("history signer"),
                ),
            )
        })
        .collect();
    let public: BTreeMap<_, _> = keys
        .iter()
        .map(|(peer, key)| (*peer, key.public_key()))
        .collect();
    let session_outcome = SessionOutcome {
        items: std::mem::take(history),
    };
    let mut engine = sha256::Hash::engine();
    engine
        .write_all(public.consensus_hash_sha256().as_ref())
        .expect("hash");
    engine
        .write_all(&session_outcome.header(index))
        .expect("hash");
    let message = Message::from_digest(sha256::Hash::from_engine(engine).to_byte_array());
    let signed = SignedSessionOutcome {
        session_outcome,
        signatures: keys
            .iter()
            .take(3)
            .map(|(peer, key)| (*peer, SECP256K1.sign_schnorr_no_aux_rand(&message, key)))
            .collect(),
    };
    assert!(signed.verify(&public, index));
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_new_entry(&SignedSessionOutcomeKey(index), &signed)
        .await;
    dbtx.commit_tx().await;
}

pub(super) async fn summarize(
    db: &Database,
    module: bool,
) -> BTreeMap<&'static str, (usize, usize)> {
    let mut dbtx = db.begin_transaction_nc().await;
    let mut rows = dbtx.raw_find_by_prefix(&[]).await.expect("record scan");
    let mut records = BTreeMap::<&str, (usize, usize)>::new();
    while let Some((key, value)) = rows.next().await {
        let class = if module {
            match key[0] {
                1 => "live_contracts",
                3 => "namespaces",
                4 => "asset_origins",
                _ => "other",
            }
        } else if key[0] == fedimint_server::db::DbKeyPrefix::SignedSessionOutcome as u8 {
            "signed_history"
        } else if key[0] == fedimint_server::db::DbKeyPrefix::AcceptedTransaction as u8 {
            "accepted_index"
        } else {
            "module_and_other"
        };
        let entry = records.entry(class).or_default();
        entry.0 += 1;
        entry.1 += key.len() + value.len();
    }
    records
}

pub(super) fn latency(mut seconds: Vec<f64>) -> serde_json::Value {
    seconds.sort_by(f64::total_cmp);
    serde_json::json!({"samples": seconds.len(), "p50_ms": seconds[(seconds.len() * 50).div_ceil(100) - 1] * 1000.0, "p95_ms": seconds[(seconds.len() * 95).div_ceil(100) - 1] * 1000.0})
}

pub(super) async fn probe(
    db: &Database,
    modules: &ServerModuleRegistry,
    samples: &[(OutPoint, Option<AssetId>)],
    spend: &Transaction,
    exists: bool,
) -> serde_json::Value {
    use std::time::Instant;
    let module = db.with_prefix_module_id(MODULE).0;
    let mut found = vec![];
    let mut absent = vec![];
    let mut origins = vec![];
    for (point, asset) in samples {
        let begin = Instant::now();
        let value = module
            .begin_transaction_nc()
            .await
            .get_value(&ContractKey(*point))
            .await;
        found.push(Instant::now().duration_since(begin).as_secs_f64());
        assert_eq!(value.is_some(), exists);
        let missing = OutPoint {
            txid: TransactionId::from_raw_hash((point, "missing").consensus_hash_sha256()),
            out_idx: 0,
        };
        let begin = Instant::now();
        let value = module
            .begin_transaction_nc()
            .await
            .get_value(&ContractKey(missing))
            .await;
        absent.push(Instant::now().duration_since(begin).as_secs_f64());
        assert!(value.is_none());
        if let Some(asset) = asset {
            let begin = Instant::now();
            let value = module
                .begin_transaction_nc()
                .await
                .get_value(&AssetKey(*asset))
                .await;
            origins.push(Instant::now().duration_since(begin).as_secs_f64());
            assert!(value.is_some());
        }
    }
    let mut validation = vec![];
    for _ in 0..100 {
        let begin = Instant::now();
        let result = process_core(db, modules, spend).await;
        validation.push(Instant::now().duration_since(begin).as_secs_f64());
        if exists {
            assert!(result.is_ok(), "{result:?}");
        } else {
            assert_eq!(
                contract_error(result.expect_err("spent or action")),
                ContractError::UnknownContract
            );
        }
    }
    serde_json::json!({"contract": latency(found), "missing_contract": latency(absent), "asset": (!origins.is_empty()).then(|| latency(origins)), "core_spend": latency(validation)})
}

pub(super) fn directory_size(path: &Path) -> (u64, u64) {
    let mut result = (0, 0);
    for entry in std::fs::read_dir(path).expect("checkpoint directory") {
        let entry = entry.expect("checkpoint entry");
        if entry.file_type().expect("type").is_file() {
            let size = entry.metadata().expect("size").len();
            result.0 += size;
            if entry.path().extension().is_some_and(|ext| ext == "sst") {
                result.1 += size;
            }
        }
    }
    result
}
