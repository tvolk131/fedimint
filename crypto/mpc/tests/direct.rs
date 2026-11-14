//! End-to-end runs of the preimage generator over the in-memory transport.

use anyhow::Result;
use fedimint_mpc::circuit::Circuit;
use fedimint_mpc::direct::{self, Generated, Share, reconstruct};
use fedimint_mpc::engine::{Params, Transport};
use fedimint_mpc::memory::{MemoryTransport, mesh};
use sha2::{Digest as _, Sha256};

/// Wraps a transport, counting rounds and optionally corrupting one message.
struct Tamper {
    inner: MemoryTransport,
    /// Flip a bit in what this party sends `recipient` in `round`.
    target: Option<(u64, usize)>,
    rounds: u64,
}

impl Transport for Tamper {
    async fn exchange(&mut self, round: u64, mut outgoing: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        if let Some((target_round, recipient)) = self.target
            && target_round == round
            && let Some(byte) = outgoing[recipient].first_mut()
        {
            *byte ^= 2;
        }

        self.rounds = round + 1;

        self.inner.exchange(round, outgoing).await
    }
}

struct Outcome {
    results: Vec<Result<Vec<Generated>>>,
    rounds: u64,
}

fn seed(party: usize, salt: u8) -> [u8; 32] {
    let mut seed = [salt; 32];

    seed[0] = u8::try_from(party).expect("small");

    seed
}

/// Run every party; party 0 tampers with `target` if given.
async fn run(params: Params, batch: usize, salt: u8, target: Option<(u64, usize)>) -> Outcome {
    let circuit = std::sync::Arc::new(direct::circuit(params, batch).expect("valid circuit"));

    let tasks: Vec<_> = mesh(params.parties())
        .into_iter()
        .map(|inner| {
            let party = inner.party();
            let circuit: std::sync::Arc<Circuit> = circuit.clone();

            let mut transport = Tamper {
                inner,
                target: target.filter(|_| party == 0),
                rounds: 0,
            };

            fedimint_core::runtime::spawn("mpc party", async move {
                let result = direct::generate(
                    &mut transport,
                    params,
                    party,
                    batch,
                    &circuit,
                    &seed(party, salt),
                    b"test run",
                )
                .await;

                (result, transport.rounds)
            })
        })
        .collect();

    let mut results = vec![];
    let mut rounds = 0;

    for task in tasks {
        let (result, party_rounds) = task.await.expect("task completes");

        results.push(result);
        rounds = rounds.max(party_rounds);
    }

    Outcome { results, rounds }
}

fn copy(share: &Share) -> Share {
    Share::new(share.party(), *share.value())
}

/// Every combination of `k` items from `0..n`.
fn subsets(n: usize, k: usize) -> Vec<Vec<usize>> {
    (0u32..1 << n)
        .filter(|mask| mask.count_ones() as usize == k)
        .map(|mask| (0..n).filter(|i| mask & (1 << i) != 0).collect())
        .collect()
}

fn check_generation(params: Params, batch: usize, outcome: &Outcome) {
    let generated: Vec<&Vec<Generated>> = outcome
        .results
        .iter()
        .map(|r| r.as_ref().expect("honest run succeeds"))
        .collect();

    let threshold = params.degree() + 1;

    for item in 0..batch {
        let hash = generated[0][item].payment_hash;

        assert!(generated.iter().all(|g| g[item].payment_hash == hash));

        let shares: Vec<Share> = generated.iter().map(|g| copy(&g[item].share)).collect();

        let preimage = reconstruct(&hash, threshold, &shares)
            .expect("all shares recover")
            .preimage;

        assert_eq!(Sha256::digest(preimage).as_slice(), hash);

        // Any `threshold` shares suffice, and fewer do not.
        for subset in subsets(params.parties(), threshold) {
            let chosen: Vec<Share> = subset.iter().map(|&i| copy(&shares[i])).collect();

            assert_eq!(
                reconstruct(&hash, threshold, &chosen)
                    .expect("threshold shares recover")
                    .preimage,
                preimage
            );
        }

        for subset in subsets(params.parties(), threshold - 1) {
            let chosen: Vec<Share> = subset.iter().map(|&i| copy(&shares[i])).collect();

            assert!(reconstruct(&hash, threshold, &chosen).is_err());
        }
    }

    // Items in one batch are independent.
    if batch > 1 {
        assert_ne!(generated[0][0].payment_hash, generated[0][1].payment_hash);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn smallest_committee_generates_recoverable_preimages() {
    let params = Params::new(3, 1).expect("valid");

    check_generation(params, 2, &run(params, 2, 1, None).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn larger_committee_generates_recoverable_preimages() {
    let params = Params::new(5, 2).expect("valid");

    check_generation(params, 1, &run(params, 1, 2, None).await);
}

#[test]
fn committees_need_an_honest_majority() {
    assert!(Params::new(2, 1).is_err());
    assert!(Params::new(4, 2).is_err());
    assert!(Params::new(3, 0).is_err());
    assert!(Params::new(17, 1).is_err());
    assert!(Params::new(7, 3).is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn runs_are_a_function_of_the_seeds() {
    let params = Params::new(3, 1).expect("valid");

    let first = run(params, 1, 3, None).await;
    let second = run(params, 1, 3, None).await;
    let other = run(params, 1, 4, None).await;

    let hash = |outcome: &Outcome, party: usize| {
        outcome.results[party].as_ref().expect("succeeds")[0].payment_hash
    };

    for party in 0..3 {
        assert_eq!(hash(&first, party), hash(&second, party));
        assert_eq!(
            first.results[party].as_ref().expect("succeeds")[0]
                .share
                .value(),
            second.results[party].as_ref().expect("succeeds")[0]
                .share
                .value()
        );
    }

    assert_ne!(hash(&first, 0), hash(&other, 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_shares_cannot_change_the_recovered_preimage() {
    let params = Params::new(5, 2).expect("valid");
    let outcome = run(params, 1, 5, None).await;

    let generated: Vec<_> = outcome
        .results
        .iter()
        .map(|r| &r.as_ref().expect("succeeds")[0])
        .collect();

    let hash = generated[0].payment_hash;

    // Two of five shares are wrong; three correct ones remain.
    let shares: Vec<Share> = generated
        .iter()
        .map(|g| {
            let mut value = *g.share.value();

            if g.share.party() % 2 == 1 {
                value[7] ^= 1;
            }

            Share::new(g.share.party(), value)
        })
        .collect();

    let recovered = reconstruct(&hash, 3, &shares).expect("three correct shares recover");

    assert_eq!(Sha256::digest(recovered.preimage).as_slice(), hash);
    assert_eq!(recovered.rejected, vec![1, 3]);

    // With three wrong shares, nothing hashing to the payment hash is found.
    let mut worse: Vec<Share> = shares.iter().map(copy).collect();
    let mut value = *worse[0].value();

    value[0] ^= 1;
    worse[0] = Share::new(0, value);

    assert!(reconstruct(&hash, 3, &worse).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_corrupted_message_aborts_the_recipient() {
    let params = Params::new(3, 1).expect("valid");
    let honest = run(params, 1, 6, None).await;

    let honest_hash = honest.results[1].as_ref().expect("succeeds")[0].payment_hash;

    // Configuration, preprocessing, the challenge, input sharing, gates and
    // the output opening.
    let last = honest.rounds - 1;
    let rounds = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, last / 2, last - 1, last];

    for round in rounds {
        let outcome = run(params, 1, 6, Some((round, 1))).await;

        assert!(
            outcome.results[1].is_err(),
            "party 1 accepted a corrupted message in round {round}"
        );

        // A party that did finish holds the honest result.
        for result in outcome.results.iter().flatten() {
            assert_eq!(result[0].payment_hash, honest_hash);
        }
    }
}
