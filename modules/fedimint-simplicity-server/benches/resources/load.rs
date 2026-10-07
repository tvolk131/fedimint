//! Opt-in closed-loop load probe. Each invocation measures one fresh process.
use std::collections::BTreeMap;
use std::sync::Barrier;
use std::time::Instant;

use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::transaction::Transaction;
use fedimint_mintv2_common::config::MintConfig;
use fedimint_mintv2_common::{Denomination, MintInput, MintOutput, Note, nonce_message};
use fedimint_mintv2_server::{Mint, MintInit};
use fedimint_server_core::{
    ConfigGenModuleArgs, DynServerModule, ServerModuleInit, ServerModuleRegistry,
};

use super::fixtures::{self, process_core};

pub fn run(spec: &str) {
    if cfg!(feature = "bench-alloc") {
        panic!("load timings require the normal allocator");
    }
    let parts: Vec<_> = spec.split(',').collect();
    let [name, workers, iterations, backend] = parts.as_slice() else {
        panic!("expected workload,workers,iterations,mem|rocks");
    };
    let workers: usize = workers.parse().expect("workers");
    let iterations: usize = iterations.parse().expect("iterations");
    assert!((1..=16).contains(&workers) && (10..=2000).contains(&iterations));
    // Construct only this workload, keeping unrelated fixture corpora out of
    // the process memory measurement and setup time.
    let (fixture, heavy) = match *name {
        "owner" | "mint" => {
            let fixture = fixtures::build("owner");
            let transaction = fixture.funded_transaction();
            (fixture, transaction)
        }
        "mixed" => {
            let case = fixtures::adversarial::build_case("constants_packed");
            (case.fixture, case.transaction)
        }
        "constants_packed" | "mixed_33_bad_last" | "context_asset_missing" | "chain_768x2" => {
            let case = fixtures::adversarial::build_case(name);
            (case.fixture, case.transaction)
        }
        _ => panic!("unknown load workload"),
    };
    // A multithread runtime permits the RocksDB wrapper's block_in_place. Each
    // scoped caller thread drives one validation at a time using this runtime.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("load runtime");
    let directory = tempfile::tempdir().expect("load database directory");
    let (db, mut modules) = rt.block_on(async {
        match *backend {
            "mem" => fixture.core_database().await,
            "rocks" => {
                fixture
                    .core_database_on(Database::new(
                        fedimint_rocksdb::RocksDb::build(directory.path().join("db"))
                            .open()
                            .await
                            .expect("RocksDB"),
                        ModuleDecoderRegistry::default(),
                    ))
                    .await
            }
            _ => panic!("unknown database backend"),
        }
    });
    let mint = rt.block_on(mint_control(&db, &mut modules));
    let expected_heavy = rt.block_on(process_core(&db, &modules, &heavy));
    if *name == "mixed_33_bad_last" {
        assert_eq!(
            fixtures::contract_error(expected_heavy.clone().expect_err("late failure")),
            fedimint_simplicity_common::ContractError::Rejected
        );
    } else {
        assert!(expected_heavy.is_ok());
    }
    assert!(rt.block_on(process_core(&db, &modules, &mint)).is_ok());
    let ready = Barrier::new(workers + 1);
    let start = Barrier::new(workers + 1);
    let (elapsed, cpu_seconds, before_rss, after_rss, samples) = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|worker| {
                let (db, modules, heavy, mint, rt, ready, start, expected) = (
                    &db,
                    &modules,
                    &heavy,
                    &mint,
                    &rt,
                    &ready,
                    &start,
                    &expected_heavy,
                );
                scope.spawn(move || {
                    let mut samples = Vec::with_capacity(iterations);
                    ready.wait();
                    start.wait();
                    for iteration in 0..iterations {
                        let is_mint =
                            *name == "mint" || (*name == "mixed" && (worker + iteration) % 2 == 0);
                        let tx = if is_mint { mint } else { heavy };
                        let begin = Instant::now();
                        let result = rt.block_on(process_core(db, modules, tx));
                        let seconds = Instant::now().duration_since(begin).as_secs_f64();
                        assert_eq!(result, if is_mint { Ok(()) } else { expected.clone() });
                        samples.push((is_mint, seconds));
                    }
                    samples
                })
            })
            .collect();
        ready.wait();
        let before = usage();
        let begin = Instant::now();
        start.wait();
        let samples: Vec<_> = handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("load worker"))
            .collect();
        let elapsed = Instant::now().duration_since(begin).as_secs_f64();
        let after = usage();
        (elapsed, after.0 - before.0, before.1, after.1, samples)
    });
    let classes: Vec<_> = [false, true].into_iter().filter_map(|mint| {
        let mut times: Vec<_> = samples.iter().filter_map(|(class, time)| (*class == mint).then_some(*time)).collect();
        if times.is_empty() { return None; }
        times.sort_by(f64::total_cmp);
        let percentile = |percent: usize| times[(times.len() * percent).div_ceil(100).saturating_sub(1)] * 1000.0;
        Some(serde_json::json!({"class": if mint { "mint" } else { "simplicity" }, "samples": times.len(), "p50_ms": percentile(50), "p95_ms": percentile(95), "p99_ms": percentile(99)}))
    }).collect();
    println!(
        "{}",
        serde_json::json!({"workload": name, "workers": workers, "iterations_per_worker": iterations, "backend": backend, "elapsed_seconds": elapsed, "validations_per_second": samples.len() as f64 / elapsed, "cpu_seconds": cpu_seconds, "setup_peak_rss_bytes": before_rss, "peak_rss_bytes": after_rss, "latencies": classes})
    );
}

async fn mint_control(db: &Database, modules: &mut ServerModuleRegistry) -> Transaction {
    use fedimint_core::core::{DynInput, DynOutput};
    use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
    use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey};
    use fedimint_core::transaction::TransactionSignature;
    use fedimint_simplicity_client::sign_transaction;

    const MINT: u16 = 6;
    let cfg: MintConfig = MintInit
        .trusted_dealer_gen(
            &[0.into()],
            &ConfigGenModuleArgs {
                network: bitcoin::Network::Regtest,
                disable_base_fees: true,
            },
        )
        .remove(&0.into())
        .expect("mint config")
        .to_typed()
        .expect("typed config");
    let owner = Keypair::from_secret_key(
        SECP256K1,
        &SecretKey::from_slice(&[3; 32]).expect("fixed key"),
    );
    let denomination = Denomination(20);
    // The synthetic signed note represents one previously issued note. Keep
    // Mint's persisted liability counter consistent with that starting state.
    let mint_db = db.with_prefix_module_id(MINT).0;
    let mut dbtx = mint_db.begin_transaction().await;
    dbtx.insert_new_entry(
        &fedimint_mintv2_server::db::IssuanceCounterKey(denomination),
        &1,
    )
    .await;
    dbtx.commit_tx().await;
    let blind = tbs::BlindingKey::random();
    let message = tbs::blind_message(nonce_message(owner.public_key()), blind);
    let share = tbs::sign_message(message, cfg.private.tbs_sks[&denomination]);
    let signature = tbs::unblind_signature(
        blind,
        tbs::aggregate_signature_shares(&BTreeMap::from([(0, share)])),
    );
    modules.register_module(
        MINT,
        fedimint_mintv2_common::KIND,
        DynServerModule::from(Mint::new(cfg, db.with_prefix_module_id(MINT).0)),
    );
    let mut tx = Transaction {
        inputs: vec![DynInput::from_typed(
            MINT,
            MintInput::new_v0(Note {
                denomination,
                nonce: owner.public_key(),
                signature,
            }),
        )],
        outputs: vec![DynOutput::from_typed(
            MINT,
            MintOutput::new_v0(denomination, message, [0; 16]),
        )],
        nonce: [0; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    };
    sign_transaction(&mut tx, &[owner]).expect("mint signature");
    tx
}

#[cfg(unix)]
fn usage() -> (f64, u64) {
    let mut result = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: getrusage initializes the entire valid rusage output on success.
    let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, result.as_mut_ptr()) };
    assert_eq!(status, 0);
    let result = unsafe { result.assume_init() };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1_000_000.0;
    let rss_unit = if cfg!(target_os = "macos") { 1 } else { 1024 };
    (
        seconds(result.ru_utime) + seconds(result.ru_stime),
        result.ru_maxrss as u64 * rss_unit,
    )
}

#[cfg(not(unix))]
fn usage() -> (f64, u64) {
    panic!("load resource counters currently require Unix")
}
