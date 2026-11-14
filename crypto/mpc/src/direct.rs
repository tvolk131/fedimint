//! Generating payment hashes with threshold-shared preimages, and recovering a
//! preimage from shares.
//!
//! A run publishes `SHA256(r)` for each preimage `r` and gives each party one
//! Shamir share of `r` with threshold `degree + 1`. There is no per-share
//! commitment: any `threshold` shares determine one candidate `r`, and the
//! hash decides whether it is right, so wrong shares can delay recovery but
//! not change its result.

use anyhow::{Result, bail, ensure};
use rand::{RngCore as _, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::MAX_PARTIES;
use crate::circuit::{self, Circuit, bytes, slots};
use crate::engine::{self, Params, Transport};
use crate::field::{F, inverse, point};

/// One party's share of a preimage.
pub struct Share {
    party: usize,
    value: [u8; 32],
}

impl Share {
    pub fn new(party: usize, value: [u8; 32]) -> Self {
        Self { party, value }
    }

    pub fn party(&self) -> usize {
        self.party
    }

    pub fn value(&self) -> &[u8; 32] {
        &self.value
    }
}

impl Drop for Share {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Share")
            .field("party", &self.party)
            .finish_non_exhaustive()
    }
}

/// A generated payment hash and this party's share of its preimage.
#[derive(Debug)]
pub struct Generated {
    pub payment_hash: [u8; 32],
    pub share: Share,
}

/// The circuit a run of `batch` preimages evaluates.
pub fn circuit(params: Params, batch: usize) -> Result<Circuit> {
    circuit::direct(params.parties(), batch, params.degree() + 1)
}

/// This party's circuit inputs, derived from its seed so a replay can
/// recompute them.
fn inputs(seed: &[u8; 32], circuit: &Circuit) -> Zeroizing<Vec<bool>> {
    let mut rng_seed = Sha256::new();

    rng_seed.update(b"fedimint/mpc/direct-inputs/v1");
    rng_seed.update(seed);

    let mut rng = ChaCha20Rng::from_seed(rng_seed.finalize().into());
    let mut bytes = Zeroizing::new(vec![0u8; circuit.inputs_per_party / 8]);

    rng.fill_bytes(&mut bytes);

    Zeroizing::new(circuit::bits(&bytes))
}

/// Run the generator as `party` and return each payment hash with this
/// party's share of its preimage.
///
/// `circuit` must come from [`circuit`] with the same `params` and `batch`.
/// `seed` must be fresh, secret and used once; `context` must be unique to
/// the run and the same for every party.
pub async fn generate<T: Transport>(
    transport: &mut T,
    params: Params,
    party: usize,
    batch: usize,
    circuit: &Circuit,
    seed: &[u8; 32],
    context: &[u8],
) -> Result<Vec<Generated>> {
    let inputs = inputs(seed, circuit);

    let outputs = Zeroizing::new(
        engine::run(transport, params, party, circuit, &inputs, seed, context).await?,
    );

    let slots = slots(params.degree() + 1);
    let row_len = 256 * (1 + params.parties());

    ensure!(
        outputs.len() == batch * row_len && inputs.len() == batch * slots * 256,
        "Outputs do not match the batch"
    );

    let mut generated = Vec::with_capacity(batch);

    for item in 0..batch {
        let row = &outputs[item * row_len..(item + 1) * row_len];

        // The digest wires come least significant bit first.
        let mut digest = row[..256].to_vec();

        digest.reverse();

        let offset = 256 * (1 + party);
        let mask = &inputs[(item * slots + slots - 1) * 256..(item * slots + slots) * 256];

        let mut share_bits = Zeroizing::new(
            row[offset..offset + 256]
                .iter()
                .zip(mask)
                .map(|(&a, &b)| a ^ b)
                .collect::<Vec<_>>(),
        );

        let mut value = bytes(&share_bits);

        share_bits.zeroize();

        generated.push(Generated {
            payment_hash: bytes(&digest).try_into().expect("256 bits"),
            share: Share::new(party, value.as_slice().try_into().expect("256 bits")),
        });

        value.zeroize();
    }

    Ok(generated)
}

/// A preimage recovered from shares.
#[derive(Debug, Eq, PartialEq)]
pub struct Recovered {
    pub preimage: [u8; 32],
    /// Parties whose share is not on the recovered polynomial.
    pub rejected: Vec<usize>,
}

fn words(value: &[u8; 32]) -> [F; 4] {
    std::array::from_fn(|w| {
        F(u64::from_be_bytes(
            value[w * 8..w * 8 + 8].try_into().expect("eight bytes"),
        ))
    })
}

/// Inverses of every difference between two evaluation points. Points are
/// at most `MAX_PARTIES`, so differences (XOR in a binary field) are below 32.
fn inverse_table() -> [F; 32] {
    std::array::from_fn(|k| if k == 0 { F(0) } else { inverse(point(k)) })
}

/// Evaluate, at `target`, the polynomial through `shares`.
fn interpolate(shares: &[&Share], target: usize, inverses: &[F; 32]) -> [u8; 32] {
    let mut acc = [F(0); 4];

    for share in shares {
        let i = share.party + 1;

        let weight = shares
            .iter()
            .map(|other| other.party + 1)
            .filter(|&j| j != i)
            .fold(F(1), |w, j| w * point(target ^ j) * inverses[i ^ j]);

        for (a, word) in acc.iter_mut().zip(words(&share.value)) {
            *a += word * weight;
        }
    }

    let mut out = [0u8; 32];

    for (chunk, word) in out.chunks_mut(8).zip(acc) {
        chunk.copy_from_slice(&word.0.to_be_bytes());
    }

    out
}

/// Recover the preimage of `payment_hash` from shares of which at least
/// `threshold` are correct. Tries share subsets of size `threshold` until one
/// yields a value with the right hash; with at most `MAX_PARTIES` shares that
/// is at most 12,870 attempts.
pub fn reconstruct(
    payment_hash: &[u8; 32],
    threshold: usize,
    shares: &[Share],
) -> Result<Recovered> {
    ensure!(threshold >= 1, "The threshold must be positive");
    ensure!(shares.len() >= threshold, "Not enough shares");

    let mut seen = [false; MAX_PARTIES];

    for share in shares {
        ensure!(
            share.party < MAX_PARTIES && !seen[share.party],
            "Shares must come from distinct parties"
        );

        seen[share.party] = true;
    }

    let inverses = inverse_table();
    let mut choice: Vec<usize> = (0..threshold).collect();

    loop {
        let subset: Vec<&Share> = choice.iter().map(|&i| &shares[i]).collect();
        let mut candidate = interpolate(&subset, 0, &inverses);

        if Sha256::digest(candidate).as_slice() == payment_hash {
            let rejected = shares
                .iter()
                .enumerate()
                .filter(|(i, share)| {
                    !choice.contains(i)
                        && interpolate(&subset, share.party + 1, &inverses) != share.value
                })
                .map(|(_, share)| share.party)
                .collect();

            return Ok(Recovered {
                preimage: candidate,
                rejected,
            });
        }

        candidate.zeroize();

        // Advance to the next combination in lexicographic order.
        let Some(i) = (0..threshold)
            .rev()
            .find(|&i| choice[i] != i + shares.len() - threshold)
        else {
            bail!("No subset of the shares matches the payment hash");
        };

        choice[i] += 1;

        for j in i + 1..threshold {
            choice[j] = choice[j - 1] + 1;
        }
    }
}
