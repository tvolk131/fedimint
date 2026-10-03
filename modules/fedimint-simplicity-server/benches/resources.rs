//! Reproducible, warm, single-threaded resource measurements. See
//! resources/README.md.
#[path = "resources/fixtures.rs"]
mod fixtures;

use std::hint::black_box;

use fedimint_core::db::DatabaseTransaction;
use fedimint_server_core::{ModuleTransactionContext, ServerModule, TransactionConsensusContext};
use fedimint_simplicity_common::runtime;
use fedimint_simplicity_server::Simplicity;
use fixtures::{DECODE_CASES, EXECUTION_CASES, TRANSACTION_CASES, case};
use simplicity::BitMachine;

#[cfg(feature = "bench-alloc")]
#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    // Compilation, signatures, fixture checks, DB seeding and manifest output
    // are outside measurement. --test also checks all fixture expectations.
    fixtures::check_all();
    if std::env::var_os("FM_SIMPLICITY_BENCH_MANIFEST").is_some() {
        println!("{}", fixtures::manifest());
        return;
    }
    divan::main();
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

async fn validate(
    module: &Simplicity,
    dbtx: &mut DatabaseTransaction<'_>,
    fixture: &fixtures::Fixture,
) {
    drop(black_box(
        module
            .validate_transaction(
                dbtx,
                &ModuleTransactionContext {
                    transaction: black_box(&fixture.transaction),
                    consensus: TransactionConsensusContext {
                        federation_id: fixtures::federation(),
                        session_index: 10,
                    },
                    module_instance_id: fixtures::MODULE,
                    validation: None,
                },
            )
            .await,
    ));
}
