//! Cost of one generator run, for comparing circuit designs. Run with
//! `cargo test --release -p fedimint-mpc --test measure -- --ignored
//! --nocapture`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use mpc::direct;
use mpc::engine::{Params, Transport};
use mpc::memory::{MemoryTransport, mesh};

/// Counts rounds and bytes sent.
struct Counting {
    inner: MemoryTransport,
    rounds: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
}

impl Transport for Counting {
    async fn exchange(&mut self, round: u64, outgoing: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        self.rounds.fetch_max(round + 1, Ordering::Relaxed);
        self.bytes.fetch_add(
            outgoing.iter().map(|m| m.len() as u64).sum(),
            Ordering::Relaxed,
        );

        self.inner.exchange(round, outgoing).await
    }
}

async fn measure(parties: usize, degree: usize, batch: usize) {
    let params = Params::new(parties, degree).expect("valid");
    let circuit = Arc::new(direct::circuit(params, batch).expect("valid"));
    let rounds = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let start = fedimint_core::time::now();

    let tasks: Vec<_> = mesh(parties)
        .into_iter()
        .map(|inner| {
            let party = inner.party();
            let circuit = circuit.clone();
            let mut transport = Counting {
                inner,
                rounds: rounds.clone(),
                bytes: bytes.clone(),
            };

            fedimint_core::runtime::spawn("mpc party", async move {
                direct::generate(
                    &mut transport,
                    params,
                    party,
                    batch,
                    &circuit,
                    &[u8::try_from(party).expect("small"); 32],
                    b"measure",
                )
                .await
                .expect("honest run succeeds")
            })
        })
        .collect();

    for task in tasks {
        task.await.expect("task completes");
    }

    let and_gates = circuit.schedule().and_count;
    let triples = and_gates + circuit.input_count();

    println!(
        "committee {parties} (degree {degree}), batch {batch}: {and_gates} ANDs, {} input bits, \
         {triples} triples, {} rounds, {:.1} MB sent, {:.2} s",
        circuit.input_count(),
        rounds.load(Ordering::Relaxed),
        bytes.load(Ordering::Relaxed) as f64 / 1e6,
        fedimint_core::time::now()
            .duration_since(start)
            .unwrap_or_default()
            .as_secs_f64(),
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement, not a check"]
async fn generator_cost() {
    for (parties, degree) in [(3, 1), (5, 2), (7, 3)] {
        measure(parties, degree, 4).await;
    }
}
