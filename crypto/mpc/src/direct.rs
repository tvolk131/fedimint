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
use crate::circuit::{self, Circuit, bytes};
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
    circuit::direct(params.parties(), batch)
}

/// This party's circuit inputs, derived from its seed so a replay can
/// recompute them.
fn inputs(seed: &[u8; 32], circuit: &Circuit) -> Zeroizing<Vec<bool>> {
    let mut rng_seed = Sha256::new();

    rng_seed.update(b"fedimint/mpc/direct-inputs/v1");
    rng_seed.update(seed);

    let mut rng = ChaCha20Rng::from_seed(rng_seed.finalize().into());
    let mut bytes = Zeroizing::new(vec![0u8; circuit.total_inputs_per_party() / 8]);

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

    let output = engine::run(transport, params, party, circuit, &inputs, seed, context).await?;

    ensure!(
        output.public.len() == batch * 256 && output.shares.len() == batch,
        "Outputs do not match the batch"
    );

    Ok(output
        .public
        .as_chunks::<256>()
        .0
        .iter()
        .zip(&output.shares)
        .map(|(digest, share)| Generated {
            payment_hash: bytes(digest).try_into().expect("256 bits"),
            share: Share::new(party, *share),
        })
        .collect())
}

/// Maximum combinations tested during subset-search fallback in
/// [`reconstruct`]. Covers all `C(15, 8) = 6,435` combinations for `f = 7`
/// (`N <= 24`) while preventing exponential consensus CPU exhaustion.
pub const MAX_SUBSET_TRIALS: usize = 8_192;

/// A preimage recovered from shares.
#[derive(Eq, PartialEq)]
pub struct Recovered {
    pub preimage: [u8; 32],
    /// Parties whose share is not on the recovered polynomial.
    pub rejected: Vec<usize>,
}

impl Drop for Recovered {
    fn drop(&mut self) {
        self.preimage.zeroize();
    }
}

impl std::fmt::Debug for Recovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recovered")
            .field("rejected", &self.rejected)
            .finish_non_exhaustive()
    }
}

/// Inverses of every difference between two evaluation points. Points are
/// at most `MAX_PARTIES` (32), so pairwise XOR differences stay below 64.
fn inverse_table() -> [F; 64] {
    std::array::from_fn(|k| if k == 0 { F(0) } else { inverse(point(k)) })
}

/// Evaluate, at `target`, the polynomial through `shares` byte-by-byte over
/// `GF(2^8)`.
fn interpolate(shares: &[&Share], target: usize, inverses: &[F; 64]) -> [u8; 32] {
    let mut acc = [F(0); 32];

    for share in shares {
        let i = share.party + 1;

        let weight = shares
            .iter()
            .map(|other| other.party + 1)
            .filter(|&j| j != i)
            .fold(F(1), |w, j| w * point(target ^ j) * inverses[i ^ j]);

        for (a, &byte) in acc.iter_mut().zip(&share.value) {
            *a += F(byte) * weight;
        }
    }

    std::array::from_fn(|i| acc[i].0)
}

/// Decode one byte column with Berlekamp–Welch over `GF(2^8)`, correcting up
/// to `e = (n - threshold) / 2` arbitrary corrupted shares in `O(n^3)` time.
/// Returns the degree-`< threshold` polynomial coefficients (constant term
/// first) if decoding succeeds.
fn berlekamp_welch_byte(xs: &[F], ys: &[F], threshold: usize) -> Option<Vec<F>> {
    let n = xs.len();
    let e = (n - threshold) / 2;
    let q_len = threshold + e;
    let cols = q_len + e; // unknowns: q_0..q_{q_len-1}, e_0..e_{e-1}

    // Build augmented matrix `[A | rhs]` of size `n × (cols + 1)`.
    let mut mat = vec![vec![F(0); cols + 1]; n];
    for (i, row_vec) in mat.iter_mut().enumerate() {
        let x = xs[i];
        let y = ys[i];
        let mut xpow = F(1);
        for cell in row_vec.iter_mut().take(q_len) {
            *cell = xpow;
            xpow *= x;
        }
        let mut xpow_e = F(1);
        for cell in row_vec.iter_mut().skip(q_len).take(e) {
            *cell = y * xpow_e;
            xpow_e *= x;
        }
        row_vec[cols] = y * xpow_e;
    }

    // Gaussian elimination to reduced row-echelon form.
    let mut pivot_cols = Vec::with_capacity(cols);
    let mut row = 0;
    for col in 0..cols {
        let Some(piv) = (row..n).find(|&r| mat[r][col] != F(0)) else {
            continue;
        };
        mat.swap(row, piv);
        let inv = inverse(mat[row][col]);
        for cell in &mut mat[row][col..=cols] {
            *cell *= inv;
        }
        for r in 0..n {
            if r != row && mat[r][col] != F(0) {
                let factor = mat[r][col];
                for c in col..=cols {
                    let sub = factor * mat[row][c];
                    mat[r][c] += sub;
                }
            }
        }
        pivot_cols.push((row, col));
        row += 1;
        if row == n {
            break;
        }
    }

    // Check consistency on zero rows.
    let zeroize_mat = |m: &mut [Vec<F>]| {
        for r in m {
            for cell in r {
                cell.0.zeroize();
            }
        }
    };

    if mat[row..n].iter().any(|r| r[cols] != F(0)) {
        zeroize_mat(&mut mat);
        return None;
    }

    // Extract one solution (setting any free variables to 0).
    let mut sol = vec![F(0); cols];
    for &(r, col) in &pivot_cols {
        sol[col] = mat[r][cols];
    }
    zeroize_mat(&mut mat);

    let mut q = sol[..q_len].to_vec();
    let mut err = Vec::with_capacity(e + 1);
    err.extend_from_slice(&sol[q_len..]);
    err.push(F(1)); // monic x^e term
    for cell in &mut sol {
        cell.0.zeroize();
    }

    // Exact polynomial division `Q(x) / E(x)` (lowest degree first).
    let mut p = vec![F(0); threshold];
    for deg in (e..q_len).rev() {
        let coef = q[deg];
        p[deg - e] = coef;
        if coef != F(0) {
            for j in 0..=e {
                q[deg - e + j] += coef * err[j];
            }
        }
    }

    // Remainder must vanish identically.
    let ok = q[..e].iter().all(|&r| r == F(0));
    for cell in &mut q {
        cell.0.zeroize();
    }
    for cell in &mut err {
        cell.0.zeroize();
    }

    if !ok {
        for cell in &mut p {
            cell.0.zeroize();
        }
        return None;
    }

    Some(p)
}

/// Try polynomial-time Berlekamp–Welch decoding across all 32 bytes.
/// Succeeds immediately whenever at most `(shares.len() - threshold) / 2`
/// shares are corrupted (including ALL `f` malicious shares when `3f + 1`
/// shares are present).
fn try_berlekamp_welch(
    payment_hash: &[u8; 32],
    threshold: usize,
    shares: &[Share],
) -> Option<Recovered> {
    let xs: Vec<F> = shares.iter().map(|s| point(s.party + 1)).collect();
    let mut polys: Vec<Vec<F>> = Vec::with_capacity(32);
    let mut candidate = [0u8; 32];

    let zeroize_polys = |ps: &mut [Vec<F>]| {
        for poly in ps {
            for cell in poly {
                cell.0.zeroize();
            }
        }
    };

    for byte_idx in 0..32 {
        let mut ys: Vec<F> = shares.iter().map(|s| F(s.value[byte_idx])).collect();
        let poly = berlekamp_welch_byte(&xs, &ys, threshold);
        for y in &mut ys {
            y.0.zeroize();
        }
        let Some(poly) = poly else {
            candidate.zeroize();
            zeroize_polys(&mut polys);
            return None;
        };
        candidate[byte_idx] = poly[0].0;
        polys.push(poly);
    }

    if Sha256::digest(candidate).as_slice() != payment_hash {
        candidate.zeroize();
        zeroize_polys(&mut polys);
        return None;
    }

    let mut rejected = Vec::new();
    for (idx, share) in shares.iter().enumerate() {
        let x = xs[idx];
        let valid = polys
            .iter()
            .enumerate()
            .all(|(b, poly)| crate::field::evaluate(poly, x).0 == share.value[b]);
        if !valid {
            rejected.push(share.party);
        }
    }

    zeroize_polys(&mut polys);

    Some(Recovered {
        preimage: candidate,
        rejected,
    })
}

fn validate_shares(threshold: usize, shares: &[Share]) -> Result<()> {
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

    Ok(())
}

/// Recover the preimage of `payment_hash` in `O(threshold^2 + shares.len() * threshold)`
/// time using a caller-supplied `threshold`-sized subset of party indices.
///
/// Fails immediately if the supplied subset does not interpolate to a preimage
/// matching `payment_hash`, and otherwise identifies every share in `shares`
/// that does not lie on the recovered degree-`< threshold` polynomial.
pub fn reconstruct_with_subset(
    payment_hash: &[u8; 32],
    threshold: usize,
    shares: &[Share],
    subset_parties: &[usize],
) -> Result<Recovered> {
    validate_shares(threshold, shares)?;
    ensure!(
        subset_parties.len() == threshold,
        "Subset length must equal threshold"
    );

    let mut chosen_mask = [false; MAX_PARTIES];
    let mut subset: Vec<&Share> = Vec::with_capacity(threshold);

    for &party in subset_parties {
        ensure!(
            party < MAX_PARTIES && !chosen_mask[party],
            "Subset parties must be distinct"
        );
        chosen_mask[party] = true;

        let Some(share) = shares.iter().find(|s| s.party == party) else {
            bail!("Subset references a party not present in shares");
        };
        subset.push(share);
    }

    let inverses = inverse_table();
    let mut candidate = interpolate(&subset, 0, &inverses);

    if Sha256::digest(candidate).as_slice() != payment_hash {
        candidate.zeroize();
        bail!("Supplied subset does not match the payment hash");
    }

    let rejected = shares
        .iter()
        .filter(|share| {
            !chosen_mask[share.party]
                && interpolate(&subset, share.party + 1, &inverses) != share.value
        })
        .map(|share| share.party)
        .collect();

    Ok(Recovered {
        preimage: candidate,
        rejected,
    })
}

/// Recover the preimage of `payment_hash` from shares of which at least
/// `threshold` are correct.
///
/// Runs polynomial-time Berlekamp–Welch decoding first (handling up to
/// `(shares.len() - threshold) / 2` corrupted shares in microseconds—covering
/// all `f` Byzantine shares when `3f + 1` shares are given, and up to `f / 2`
/// when `2f + 1` are given), then falls back to bounded subset search (at most
/// [`MAX_SUBSET_TRIALS`] combinations) if more errors are present.
pub fn reconstruct(
    payment_hash: &[u8; 32],
    threshold: usize,
    shares: &[Share],
) -> Result<Recovered> {
    validate_shares(threshold, shares)?;

    if let Some(recovered) = try_berlekamp_welch(payment_hash, threshold, shares) {
        return Ok(recovered);
    }

    let inverses = inverse_table();
    let mut choice: Vec<usize> = (0..threshold).collect();
    let mut trials: usize = 0;

    loop {
        trials += 1;
        ensure!(
            trials <= MAX_SUBSET_TRIALS,
            "Subset search exceeded {MAX_SUBSET_TRIALS} trials; supply a witness subset"
        );

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
