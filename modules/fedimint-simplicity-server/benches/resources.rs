//! Opt-in validation and storage measurements. See resources/README.md.
#[path = "resources/fixtures.rs"]
mod fixtures;
#[path = "resources/load.rs"]
mod load;

use std::hint::black_box;

use fedimint_core::db::DatabaseTransaction;
use fedimint_simplicity_common::{resources, runtime};
use fedimint_simplicity_server::Simplicity;
use fixtures::{DECODE_CASES, EXECUTION_CASES, TRANSACTION_CASES, case};
use simplicity::BitMachine;

#[cfg(feature = "bench-alloc")]
#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    if let Ok(spec) = std::env::var("FM_SIMPLICITY_BENCH_STORAGE") {
        fixtures::storage::run(&spec);
        return;
    }
    if let Ok(spec) = std::env::var("FM_SIMPLICITY_BENCH_LOAD") {
        load::run(&spec);
        return;
    }
    // Compilation, signatures, fixture checks, DB seeding and manifest output
    // are outside measurement. --test also checks all fixture expectations.
    fixtures::check_all();
    fixtures::adversarial::check_all();
    if std::env::var_os("FM_SIMPLICITY_BENCH_MUTATIONS").is_some() {
        println!("{}", fixtures::adversarial::mutations());
        return;
    }
    if std::env::var_os("FM_SIMPLICITY_BENCH_MANIFEST").is_some() {
        let mut manifest = fixtures::manifest();
        manifest["adversarial"] = fixtures::adversarial::manifest();
        println!("{manifest}");
        return;
    }
    divan::main();
}

#[divan::bench(args = fixtures::adversarial::CASES)]
fn adversarial_preflight(bencher: divan::Bencher, name: &str) {
    let case = fixtures::adversarial::case(name);
    bencher.bench(|| {
        black_box(fixtures::adversarial::check_preflight(black_box(
            &case.transaction,
        )))
    });
}

#[divan::bench(args = fixtures::adversarial::CASES)]
fn retained_decode(bencher: divan::Bencher, name: &str) {
    let case = fixtures::adversarial::case(name);
    bencher.bench(|| {
        let programs: Vec<_> = case
            .fixture
            .inputs
            .iter()
            .map(|input| runtime::decode_program(black_box(input)).expect("valid baseline"))
            .collect();
        drop(black_box(programs));
    });
}

#[divan::bench(args = fixtures::adversarial::CASES)]
fn adversarial_core(bencher: divan::Bencher, name: &str) {
    let case = fixtures::adversarial::case(name);
    let rt = fixtures::executor();
    let (db, modules) = rt.block_on(case.fixture.core_database());
    bencher.bench_local(|| {
        black_box(rt.block_on(fixtures::process_core(
            &db,
            &modules,
            black_box(&case.transaction),
        )))
    });
}

#[divan::bench(args = DECODE_CASES)]
fn decode(bencher: divan::Bencher, name: &str) {
    let fixture = case(name);
    bencher.bench(|| {
        drop(black_box(runtime::decode_program(black_box(
            &fixture.inputs[0],
        ))))
    });
}

#[divan::bench(args = EXECUTION_CASES)]
fn vm_cached(bencher: divan::Bencher, name: &str) {
    let fixture = case(name);
    let program = runtime::decode_program(&fixture.inputs[0]).expect("checked fixture");
    bencher.bench(|| {
        let mut machine = BitMachine::for_program(black_box(&program)).expect("checked bounds");
        drop(black_box(
            machine.exec(&program, black_box(&fixture.environments[0])),
        ));
    });
}

#[divan::bench(args = EXECUTION_CASES)]
fn runtime_execute(bencher: divan::Bencher, name: &str) {
    let fixture = case(name);
    bencher.bench(|| {
        let _ = black_box(runtime::execute(
            black_box(&fixture.inputs[0]),
            black_box(&fixture.environments[0]),
        ));
    });
}

#[divan::bench(args = TRANSACTION_CASES)]
fn intent_hash(bencher: divan::Bencher, name: &str) {
    let fixture = case(name);
    bencher.bench(|| black_box(fixture.signature_hash()));
}

#[divan::bench(args = TRANSACTION_CASES)]
fn environment_clone(bencher: divan::Bencher, name: &str) {
    let fixture = case(name);
    // Isolates one environment's cloning cost; it does not include DB reads,
    // output hashing or asset checks. The real validation hook below does.
    bencher.bench(|| drop(black_box(black_box(&fixture.environments[0]).clone())));
}

#[divan::bench(args = TRANSACTION_CASES)]
fn guardian_validation(bencher: divan::Bencher, name: &str) {
    let fixture = case(name);
    let rt = fixtures::executor();
    let db = rt.block_on(fixture.database());
    let module = Simplicity::new_for_testing(vec![0.into()]).expect("one guardian");
    let mut dbtx = rt.block_on(db.begin_transaction_nc());
    // Use the production module hook, with a warm read-only DB transaction.
    rt.block_on(validate(&module, &mut dbtx, fixture));
    bencher.bench_local(|| rt.block_on(validate(&module, &mut dbtx, fixture)));
}

#[divan::bench(args = TRANSACTION_CASES)]
fn transaction_preflight(bencher: divan::Bencher, name: &str) {
    let fixture = case(name);
    bencher.bench(|| {
        black_box(resources::check_transaction(black_box(
            &fixture.transaction,
        )))
    });
}

#[divan::bench(args = TRANSACTION_CASES)]
fn core_submission(bencher: divan::Bencher, name: &str) {
    let fixture = case(name);
    let rt = fixtures::executor();
    let transaction = fixture.funded_transaction();
    let (db, modules) = rt.block_on(fixture.core_database());
    bencher.bench_local(|| {
        black_box(rt.block_on(fixtures::process_core(
            &db,
            &modules,
            black_box(&transaction),
        )))
    });
}

async fn validate(
    module: &Simplicity,
    dbtx: &mut DatabaseTransaction<'_>,
    fixture: &fixtures::Fixture,
) {
    drop(black_box(
        fixtures::validate_module(module, dbtx, fixture).await,
    ));
}
