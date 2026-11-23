//! Scaling benchmark for federations (`N = 4, 10, 16, 22, 31` guardians,
//! corresponding to MPC committees `m = 3, 7, 11, 15, 21`), plus worst-case
//! `reconstruct()` timing via Berlekamp–Welch decoding.
//!
//! Run with:
//! `cargo test --release -p fedimint-mpc --test measure -- --ignored --nocapture`

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::Result;
use mpc::direct::{self, Share, reconstruct};
use mpc::engine::{Params, Transport};
use mpc::field::{F, evaluate, point};
use mpc::memory::{MemoryTransport, mesh};
use sha2::{Digest as _, Sha256};

struct Counting {
    inner: MemoryTransport,
    rounds: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    max_msg: Arc<AtomicU64>,
}

impl Transport for Counting {
    async fn exchange(&mut self, round: u64, outgoing: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        self.rounds.fetch_max(round + 1, Ordering::Relaxed);
        let mut total = 0u64;
        let mut peak = 0u64;
        for m in &outgoing {
            let len = m.len() as u64;
            total += len;
            peak = peak.max(len);
        }
        self.bytes.fetch_add(total, Ordering::Relaxed);
        self.max_msg.fetch_max(peak, Ordering::Relaxed);

        self.inner.exchange(round, outgoing).await
    }
}

struct Stats {
    fed_size: usize,
    parties: usize,
    degree: usize,
    batch: usize,
    rounds: u64,
    total_bytes: u64,
    max_msg_bytes: u64,
    local_secs: f64,
}

async fn measure(fed_size: usize, parties: usize, degree: usize, batch: usize) -> Stats {
    let params = Params::new(parties, degree).expect("valid");
    let circuit = Arc::new(direct::circuit(params, batch).expect("valid"));

    let rounds = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let max_msg = Arc::new(AtomicU64::new(0));
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
                max_msg: max_msg.clone(),
            };

            fedimint_core::runtime::spawn("mpc party", async move {
                direct::generate(
                    &mut transport,
                    params,
                    party,
                    batch,
                    &circuit,
                    &[u8::try_from(party).expect("small"); 32],
                    b"measure-scale",
                )
                .await
                .expect("honest run succeeds")
            })
        })
        .collect();

    let mut first_hashes = None;
    for task in tasks {
        let out = task.await.expect("task completes");
        assert_eq!(out.len(), batch);
        let hashes: Vec<[u8; 32]> = out.iter().map(|g| g.payment_hash).collect();
        if let Some(prev) = &first_hashes {
            assert_eq!(prev, &hashes, "all parties agree on hashes");
        } else {
            first_hashes = Some(hashes);
        }
    }

    let local_secs = fedimint_core::time::now()
        .duration_since(start)
        .unwrap_or_default()
        .as_secs_f64();

    Stats {
        fed_size,
        parties,
        degree,
        batch,
        rounds: rounds.load(Ordering::Relaxed),
        total_bytes: bytes.load(Ordering::Relaxed),
        max_msg_bytes: max_msg.load(Ordering::Relaxed),
        local_secs,
    }
}

fn print_stats(s: &Stats) {
    let total_mb = s.total_bytes as f64 / 1e6;
    let per_member_mb = total_mb / s.parties as f64;
    let kb_per_hash_total = (s.total_bytes as f64 / s.batch as f64) / 1e3;
    let kb_per_hash_member = kb_per_hash_total / s.parties as f64;
    let max_msg_mb = s.max_msg_bytes as f64 / 1e6;
    let tx_secs_100m = per_member_mb / 12.5;
    let wan_50ms = s.local_secs + (s.rounds as f64 * 0.050) + tx_secs_100m;
    let wan_150ms = s.local_secs + (s.rounds as f64 * 0.150) + tx_secs_100m;

    println!(
        "N={:2} (m={:2}, f={:2}) | b={:3} | rds={:4} | \
         total={:7.2} MB ({:6.1} MB/m) | {:7.1} KB/h ({:5.1} KB/h/m) | maxMsg={:5.2} MB | \
         cpuAll={:6.2}s | WAN50={:6.1}s ({:5.2}/s) | WAN150={:6.1}s ({:5.2}/s)",
        s.fed_size,
        s.parties,
        s.degree,
        s.batch,
        s.rounds,
        total_mb,
        per_member_mb,
        kb_per_hash_total,
        kb_per_hash_member,
        max_msg_mb,
        s.local_secs,
        wan_50ms,
        s.batch as f64 / wan_50ms,
        wan_150ms,
        s.batch as f64 / wan_150ms,
    );
}

fn bench_reconstruct(fed_size: usize, f: usize, share_count: usize, corrupt: usize) -> Duration {
    let preimage: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(19).wrapping_add(7));
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    let threshold = f + 1;

    let polys: Vec<Vec<F>> = (0..32)
        .map(|b| {
            let mut coeffs = Vec::with_capacity(threshold);
            coeffs.push(F(preimage[b]));
            for d in 1..threshold {
                coeffs.push(F(((b * 13 + d * 29 + 3) % 251 + 1) as u8));
            }
            coeffs
        })
        .collect();

    let shares: Vec<Share> = (0..share_count)
        .map(|party| {
            let x = point(party + 1);
            let mut val: [u8; 32] = std::array::from_fn(|b| evaluate(&polys[b], x).0);
            if party < corrupt {
                val[0] ^= 0xff;
            }
            Share::new(party, val)
        })
        .collect();

    let start = fedimint_core::time::now();
    let rec = reconstruct(&payment_hash, threshold, &shares).expect("reconstructs");
    let elapsed = fedimint_core::time::now()
        .duration_since(start)
        .unwrap_or_default();
    assert_eq!(rec.preimage, preimage);
    assert_eq!(rec.rejected.len(), corrupt);
    println!(
        "reconstruct N={fed_size:2} (f={f:2}) shares={share_count:2} corrupt={corrupt:2} => {:.3} ms",
        elapsed.as_secs_f64() * 1e3
    );
    elapsed
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "measurement, not a check"]
async fn generator_cost() {
    println!("=== Federation Scaling (batch=64) ===");
    let feds = [
        (4, 3, 1),
        (10, 7, 3),
        (16, 11, 5),
        (22, 15, 7),
        (31, 21, 10),
    ];
    for (fed_size, m, f) in feds {
        let s = measure(fed_size, m, f, 64).await;
        print_stats(&s);
    }

    println!("\n=== Large Batch (batch=256) at N=22 (m=15) & N=31 (m=21) ===");
    for (fed_size, m, f) in [(22, 15, 7), (31, 21, 10)] {
        let s = measure(fed_size, m, f, 256).await;
        print_stats(&s);
    }

    println!("\n=== Worst-Case Share Reconstruction (all f malicious at lowest indices) ===");
    for (fed_size, f) in [(16, 5), (19, 6), (22, 7)] {
        bench_reconstruct(fed_size, f, 2 * f + 1, f);
        bench_reconstruct(fed_size, f, 3 * f + 1, f);
    }
    bench_reconstruct(31, 10, 21, 5);
    bench_reconstruct(31, 10, 31, 10);
}
