//! Honest-majority MPC with abort over Boolean circuits using small-field
//! `GF(2^8)` Damgård–Nielsen (DN07) multiplication and a 128-bit `GF((2^8)^16)`
//! recursive inner-product verification (BBCGI19).
//!
//! Wires are degree-`degree` Shamir sharings over `GF(2^8)` holding 0 or 1;
//! party `i` holds the evaluation at `i + 1`. With `parties >= 2 * degree + 1`
//! and at most `degree` malicious parties:
//!
//! - Privacy: any `degree` shares are independent of the secret.
//! - Double-random sharings `([r]_t, [r]_{2t})` are generated in 1 round using
//!   pairwise PRG seed expansion and Vandermonde extraction (`n * t / (t + 1)`
//!   bytes total per AND gate).
//! - Consistency: all degree-`t` sharings (`[r]_t` and inputs) are checked
//!   together via a single random linear combination lifted into `GF((2^8)^16)`
//!   with 128-bit soundness and zero leakage.
//! - Online multiplication: DN07 broadcasts 1 byte per AND gate per peer
//!   (`d = x * y + r_{2t}`, `z = d + r_t`), 1 round per depth layer.
//! - Malicious verification: BEFORE opening any public output or dealing any
//!   secret share, all AND multiplications and input bit-checks (`w*(w+1)=0`)
//!   are verified together over `GF((2^8)^16)` using a 4-way BBCGI19 inner-
//!   product proof (`O(log_4 M)` rounds, ~1 KB total) plus a transcript digest
//!   over all online `d` messages, achieving 128-bit field soundness.
//! - Secret outputs: each 256-bit secret `v` becomes 32 `GF(2^8)` byte sharings
//!   and is dealt privately as degree-`degree` Shamir shares over `GF(2^8)`.
//!
//! Every message a party sends is a deterministic function of its seed and the
//! messages it received before, so a party that reveals its seed after an
//! abort can be replayed to check what it sent.

use std::future::Future;

use anyhow::{Context as _, Result, ensure};
use rand::{RngCore as _, SeedableRng as _};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize as _, Zeroizing};

use crate::circuit::{Circuit, Gate};
use crate::field::{F, Gf128, evaluate, evaluate_ext, point, weights};
use crate::{MAX_PARTIES, MAX_TRIPLES};

/// Who runs a computation and how much corruption it tolerates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Params {
    parties: usize,
    degree: usize,
}

impl Params {
    /// `parties` parties of which at most `degree` may be malicious.
    pub fn new(parties: usize, degree: usize) -> Result<Self> {
        ensure!(degree >= 1, "The degree must be at least one");
        ensure!(
            parties > 2 * degree,
            "An honest majority needs at least 2 * degree + 1 parties"
        );
        ensure!(parties <= MAX_PARTIES, "Too many parties");

        Ok(Self { parties, degree })
    }

    pub fn parties(self) -> usize {
        self.parties
    }

    pub fn degree(self) -> usize {
        self.degree
    }
}

/// Lockstep message delivery between the parties of one run.
pub trait Transport: Send {
    /// Send `outgoing[p]` to every other party `p` and return what each party
    /// sent this party in round `round`. The entry for this party itself is
    /// ignored in both directions.
    ///
    /// Rounds start at zero and increase by one; implementations must bind
    /// each message to its run, sender, recipient and round.
    fn exchange(
        &mut self,
        round: u64,
        outgoing: Vec<Vec<u8>>,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>>> + Send;
}

/// Base-field elements wiped when dropped.
struct Secrets(Vec<F>);

impl Drop for Secrets {
    fn drop(&mut self) {
        for f in &mut self.0 {
            f.0.zeroize();
        }
    }
}

/// Extension-field elements wiped when dropped.
struct ExtSecrets(Vec<Gf128>);

impl Drop for ExtSecrets {
    fn drop(&mut self) {
        for f in &mut self.0 {
            f.zeroize();
        }
    }
}

struct Engine<'t, T> {
    transport: &'t mut T,
    params: Params,
    party: usize,
    round: u64,
    rng: ChaCha20Rng,
    /// Pairwise PRG streams for seed-expanded Shamir sharing (indexed by peer).
    send_rngs: Vec<Option<ChaCha20Rng>>,
    recv_rngs: Vec<Option<ChaCha20Rng>>,
    /// `interp_t[target]` evaluates at `target` the degree-`t` polynomial
    /// through the first `degree + 1` parties (`1..=degree + 1`).
    interp_t: Vec<Vec<F>>,
    /// `interp_2t[target]` evaluates at `target` the degree-`2t` polynomial
    /// through the first `2 * degree + 1` parties (`1..=2 * degree + 1`).
    interp_2t: Vec<Vec<F>>,
    /// Running digest of every online DN07 opening message received, folded
    /// into the final verification coin to rule out selective equivocation.
    online_transcript: Sha256,
}

impl<T: Transport> Engine<'_, T> {
    fn parties(&self) -> usize {
        self.params.parties
    }

    fn degree(&self) -> usize {
        self.params.degree
    }

    async fn exchange(&mut self, mut outgoing: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>> {
        let round = self.round;
        self.round += 1;

        let own = std::mem::take(&mut outgoing[self.party]);

        let mut incoming = self.transport.exchange(round, outgoing).await?;

        ensure!(
            incoming.len() == self.parties(),
            "Transport returned the wrong number of messages"
        );

        incoming[self.party] = own;

        Ok(incoming)
    }

    async fn broadcast(&mut self, payload: Vec<u8>) -> Result<Vec<Vec<u8>>> {
        self.exchange(vec![payload; self.parties()]).await
    }

    /// Broadcast, then echo a digest of everything received and abort unless
    /// every party saw the same messages.
    async fn consistent_broadcast(&mut self, payload: Vec<u8>) -> Result<Vec<Vec<u8>>> {
        let values = self.broadcast(payload).await?;

        let mut hash = Sha256::new();
        hash.update(b"fedimint/mpc/echo/v2");
        hash.update(self.round.to_le_bytes());

        for value in &values {
            hash.update((value.len() as u64).to_le_bytes());
            hash.update(value);
        }

        let digest = hash.finalize().to_vec();
        let echoes = self.broadcast(digest.clone()).await?;

        ensure!(
            echoes.iter().all(|echo| *echo == digest),
            "A party broadcast inconsistent messages"
        );

        Ok(values)
    }

    /// Exchange pairwise 32-byte PRG seeds derived deterministically from this
    /// party's run seed.
    async fn init_prg_seeds(&mut self, context: &[u8]) -> Result<()> {
        let n = self.parties();
        let mut outgoing = Vec::with_capacity(n);

        for dst in 0..n {
            if dst == self.party {
                outgoing.push(Vec::new());
            } else {
                let mut seed = Zeroizing::new([0u8; 32]);
                self.rng.fill_bytes(seed.as_mut());
                self.send_rngs[dst] = Some(derive_prg(context, self.party, dst, &seed));
                outgoing.push(seed.to_vec());
            }
        }

        let incoming = Zeroizing::new(self.exchange(outgoing).await?);

        for (src, data) in incoming.iter().enumerate() {
            if src == self.party {
                continue;
            }
            ensure!(data.len() == 32, "A peer sent a malformed PRG seed");
            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(data);
            self.recv_rngs[src] = Some(derive_prg(context, src, self.party, &seed));
        }

        Ok(())
    }

    /// Cyclic peer offset `(peer - dealer) mod n`.
    fn peer_offset(&self, dealer: usize, peer: usize) -> usize {
        (peer + self.parties() - dealer) % self.parties()
    }

    /// Number of other peers that receive explicit bytes for a degree-`d`
    /// seed-expanded sharing (the remaining `d` peers derive shares from PRG).
    fn sent_count(&self, d: usize) -> usize {
        self.parties() - 1 - d
    }

    /// Generate `count` double-random sharings `([r]_t, [r]_{2t})` over
    /// `GF(2^8)` using seed-expanded Shamir sharing + Vandermonde extraction.
    /// Costs 1 round and `n * t / (t + 1)` bytes total per pair when `n = 2t + 1`.
    async fn gen_double_random(&mut self, count: usize) -> Result<(Secrets, Secrets)> {
        if count == 0 {
            return Ok((Secrets(Vec::new()), Secrets(Vec::new())));
        }

        let n = self.parties();
        let t = self.degree();
        let k = n - t;
        let blocks = count.div_ceil(k);

        let sent_t = self.sent_count(t);
        let sent_2t = self.sent_count(2 * t);

        // Precompute interpolation weights from `{0} U prg_peers` for `self.party`
        // as dealer.
        let prg_t_peers: Vec<usize> = (sent_t + 1..n).map(|o| (self.party + o) % n).collect();
        let sent_t_peers: Vec<usize> = (1..=sent_t).map(|o| (self.party + o) % n).collect();
        let mut base_t = Vec::with_capacity(t + 1);
        base_t.push(0usize);
        for &p in &prg_t_peers {
            base_t.push(p + 1);
        }
        let w_t_own = weights(&base_t, self.party + 1);
        let w_t_sent: Vec<Vec<F>> = sent_t_peers
            .iter()
            .map(|&dst| weights(&base_t, dst + 1))
            .collect();

        let prg_2t_peers: Vec<usize> = (sent_2t + 1..n).map(|o| (self.party + o) % n).collect();
        let sent_2t_peers: Vec<usize> = (1..=sent_2t).map(|o| (self.party + o) % n).collect();
        let mut base_2t = Vec::with_capacity(2 * t + 1);
        base_2t.push(0usize);
        for &p in &prg_2t_peers {
            base_2t.push(p + 1);
        }
        let w_2t_own = weights(&base_2t, self.party + 1);
        let w_2t_sent: Vec<Vec<F>> = sent_2t_peers
            .iter()
            .map(|&dst| weights(&base_2t, dst + 1))
            .collect();

        // Draw our own random secrets `s[0..blocks]`.
        let mut secrets = Zeroizing::new(vec![0u8; blocks]);
        self.rng.fill_bytes(secrets.as_mut());

        // Draw PRG shares in canonical order: first `prg_t_peers`, then `prg_2t_peers`.
        let mut prg_t_bufs: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(prg_t_peers.len());
        for &peer in &prg_t_peers {
            let mut buf = Zeroizing::new(vec![0u8; blocks]);
            self.send_rngs[peer]
                .as_mut()
                .expect("PRG initialized")
                .fill_bytes(buf.as_mut());
            prg_t_bufs.push(buf);
        }

        let mut prg_2t_bufs: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(prg_2t_peers.len());
        for &peer in &prg_2t_peers {
            let mut buf = Zeroizing::new(vec![0u8; blocks]);
            self.send_rngs[peer]
                .as_mut()
                .expect("PRG initialized")
                .fill_bytes(buf.as_mut());
            prg_2t_bufs.push(buf);
        }

        // Compute own shares and outgoing explicit shares.
        let mut own_t = Secrets(vec![F(0); blocks]);
        let mut own_2t = Secrets(vec![F(0); blocks]);
        let mut outgoing: Vec<Vec<u8>> = (0..n)
            .map(|dst| {
                let off = self.peer_offset(self.party, dst);
                let mut cap = 0;
                if (1..=sent_t).contains(&off) {
                    cap += blocks;
                }
                if (1..=sent_2t).contains(&off) {
                    cap += blocks;
                }
                Vec::with_capacity(cap)
            })
            .collect();

        for b in 0..blocks {
            let s = F(secrets[b]);
            // Degree-t share for self.
            let mut val = s * w_t_own[0];
            for (idx, buf) in prg_t_bufs.iter().enumerate() {
                val += F(buf[b]) * w_t_own[idx + 1];
            }
            own_t.0[b] = val;

            // Degree-2t share for self.
            let mut val2 = s * w_2t_own[0];
            for (idx, buf) in prg_2t_bufs.iter().enumerate() {
                val2 += F(buf[b]) * w_2t_own[idx + 1];
            }
            own_2t.0[b] = val2;
        }

        for (i, &dst) in sent_t_peers.iter().enumerate() {
            let w = &w_t_sent[i];
            let out = &mut outgoing[dst];
            for b in 0..blocks {
                let mut val = F(secrets[b]) * w[0];
                for (idx, buf) in prg_t_bufs.iter().enumerate() {
                    val += F(buf[b]) * w[idx + 1];
                }
                out.push(val.0);
            }
        }

        for (i, &dst) in sent_2t_peers.iter().enumerate() {
            let w = &w_2t_sent[i];
            let out = &mut outgoing[dst];
            for b in 0..blocks {
                let mut val = F(secrets[b]) * w[0];
                for (idx, buf) in prg_2t_bufs.iter().enumerate() {
                    val += F(buf[b]) * w[idx + 1];
                }
                out.push(val.0);
            }
        }

        drop(prg_t_bufs);
        drop(prg_2t_bufs);
        drop(secrets);

        let incoming = Zeroizing::new(self.exchange(outgoing).await?);

        // Assemble per-dealer shares received by `self.party`.
        let mut dealt_t: Vec<Secrets> = Vec::with_capacity(n);
        let mut dealt_2t: Vec<Secrets> = Vec::with_capacity(n);

        for dealer in 0..n {
            if dealer == self.party {
                dealt_t.push(Secrets(std::mem::take(&mut own_t.0)));
                dealt_2t.push(Secrets(std::mem::take(&mut own_2t.0)));
                continue;
            }

            let off = self.peer_offset(dealer, self.party);
            let is_sent_t = off <= sent_t;
            let is_sent_2t = off <= sent_2t;
            let expected_len = usize::from(is_sent_t) * blocks + usize::from(is_sent_2t) * blocks;
            let data = &incoming[dealer];
            ensure!(
                data.len() == expected_len,
                "A dealer sent the wrong number of double-random shares"
            );

            let mut cursor = 0;
            let st = if is_sent_t {
                let slice = &data[cursor..cursor + blocks];
                cursor += blocks;
                Secrets(slice.iter().map(|&b| F(b)).collect())
            } else {
                let mut buf = Zeroizing::new(vec![0u8; blocks]);
                self.recv_rngs[dealer]
                    .as_mut()
                    .expect("PRG initialized")
                    .fill_bytes(buf.as_mut());
                Secrets(buf.iter().map(|&b| F(b)).collect())
            };

            let s2t = if is_sent_2t {
                let slice = &data[cursor..cursor + blocks];
                Secrets(slice.iter().map(|&b| F(b)).collect())
            } else {
                let mut buf = Zeroizing::new(vec![0u8; blocks]);
                self.recv_rngs[dealer]
                    .as_mut()
                    .expect("PRG initialized")
                    .fill_bytes(buf.as_mut());
                Secrets(buf.iter().map(|&b| F(b)).collect())
            };

            dealt_t.push(st);
            dealt_2t.push(s2t);
        }

        // Vandermonde extraction: `V[r][d] = (d + 1)^r` for `r in 0..k`, `d in 0..n`.
        let mut vandermonde = vec![vec![F(1); n]; k];
        for r in 1..k {
            for d in 0..n {
                vandermonde[r][d] = vandermonde[r - 1][d] * point(d + 1);
            }
        }

        let mut out_t = Secrets(Vec::with_capacity(count));
        let mut out_2t = Secrets(Vec::with_capacity(count));

        'outer: for b in 0..blocks {
            for row in &vandermonde {
                let mut acc_t = F(0);
                let mut acc_2t = F(0);
                for d in 0..n {
                    let v = row[d];
                    acc_t += v * dealt_t[d].0[b];
                    acc_2t += v * dealt_2t[d].0[b];
                }
                out_t.0.push(acc_t);
                out_2t.0.push(acc_2t);
                if out_t.0.len() == count {
                    break 'outer;
                }
            }
        }

        Ok((out_t, out_2t))
    }

    /// Deal degree-`t` sharings of `values` over `GF(2^8)` using seed-expanded
    /// Shamir sharing (`n - 1 - t` bytes per value per dealer).
    async fn share_base(&mut self, values: &[F]) -> Result<Vec<Secrets>> {
        let n = self.parties();
        let t = self.degree();
        let len = values.len();
        let sent_t = self.sent_count(t);

        let prg_t_peers: Vec<usize> = (sent_t + 1..n).map(|o| (self.party + o) % n).collect();
        let sent_t_peers: Vec<usize> = (1..=sent_t).map(|o| (self.party + o) % n).collect();

        let mut base_t = Vec::with_capacity(t + 1);
        base_t.push(0usize);
        for &p in &prg_t_peers {
            base_t.push(p + 1);
        }
        let w_own = weights(&base_t, self.party + 1);
        let w_sent: Vec<Vec<F>> = sent_t_peers
            .iter()
            .map(|&dst| weights(&base_t, dst + 1))
            .collect();

        let mut prg_bufs: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(prg_t_peers.len());
        for &peer in &prg_t_peers {
            let mut buf = Zeroizing::new(vec![0u8; len]);
            self.send_rngs[peer]
                .as_mut()
                .expect("PRG initialized")
                .fill_bytes(buf.as_mut());
            prg_bufs.push(buf);
        }

        let mut own = Secrets(vec![F(0); len]);
        for i in 0..len {
            let mut val = values[i] * w_own[0];
            for (idx, buf) in prg_bufs.iter().enumerate() {
                val += F(buf[i]) * w_own[idx + 1];
            }
            own.0[i] = val;
        }

        let mut outgoing = vec![Vec::new(); n];
        for (pi, &dst) in sent_t_peers.iter().enumerate() {
            let w = &w_sent[pi];
            let mut out = Vec::with_capacity(len);
            for i in 0..len {
                let mut val = values[i] * w[0];
                for (idx, buf) in prg_bufs.iter().enumerate() {
                    val += F(buf[i]) * w[idx + 1];
                }
                out.push(val.0);
            }
            outgoing[dst] = out;
        }
        drop(prg_bufs);

        let incoming = Zeroizing::new(self.exchange(outgoing).await?);

        let mut rows = Vec::with_capacity(n);
        for dealer in 0..n {
            if dealer == self.party {
                rows.push(Secrets(std::mem::take(&mut own.0)));
                continue;
            }
            let off = self.peer_offset(dealer, self.party);
            if off <= sent_t {
                ensure!(
                    incoming[dealer].len() == len,
                    "A dealer sent the wrong number of input shares"
                );
                rows.push(Secrets(incoming[dealer].iter().map(|&b| F(b)).collect()));
            } else {
                ensure!(
                    incoming[dealer].is_empty(),
                    "Unexpected payload from PRG peer"
                );
                let mut buf = Zeroizing::new(vec![0u8; len]);
                self.recv_rngs[dealer]
                    .as_mut()
                    .expect("PRG initialized")
                    .fill_bytes(buf.as_mut());
                rows.push(Secrets(buf.iter().map(|&b| F(b)).collect()));
            }
        }

        Ok(rows)
    }

    /// Generate `count` random degree-`t` sharings over `GF(2^8)`.
    async fn random_base(&mut self, count: usize) -> Result<Secrets> {
        let mut raw = Zeroizing::new(vec![0u8; count]);
        self.rng.fill_bytes(raw.as_mut());
        let own = Secrets(raw.iter().map(|&b| F(b)).collect());
        let rows = self.share_base(&own.0).await?;

        let mut sum = Secrets(vec![F(0); count]);
        for row in &rows {
            for (acc, &v) in sum.0.iter_mut().zip(&row.0) {
                *acc += v;
            }
        }
        Ok(sum)
    }

    /// Deal degree-`t` sharings of `values` over `Gf128`.
    async fn share_ext(&mut self, values: &[Gf128]) -> Result<Vec<ExtSecrets>> {
        let n = self.parties();
        let t = self.degree();
        let mut outgoing = vec![Vec::with_capacity(16 * values.len()); n];
        let mut coeffs = ExtSecrets(vec![Gf128::ZERO; t + 1]);

        for &v in values {
            coeffs.0[0] = v;
            for c in &mut coeffs.0[1..] {
                *c = self.random_gf128();
            }
            for (p, data) in outgoing.iter_mut().enumerate() {
                data.extend_from_slice(&evaluate_ext(&coeffs.0, point(p + 1)).to_bytes());
            }
        }

        let incoming = Zeroizing::new(self.exchange(outgoing).await?);

        incoming
            .iter()
            .map(|data| {
                ensure!(
                    data.len() == 16 * values.len(),
                    "A dealer sent the wrong number of extension shares"
                );
                Ok(ExtSecrets(decode_ext(data)))
            })
            .collect()
    }

    /// Generate `count` random degree-`t` sharings over `Gf128`.
    async fn random_ext(&mut self, count: usize) -> Result<ExtSecrets> {
        let own = ExtSecrets((0..count).map(|_| self.random_gf128()).collect());
        let rows = self.share_ext(&own.0).await?;
        let mut sum = ExtSecrets(vec![Gf128::ZERO; count]);
        for row in &rows {
            for (acc, &v) in sum.0.iter_mut().zip(&row.0) {
                *acc += v;
            }
        }
        Ok(sum)
    }

    /// Generate `count` double-random sharings `([r]_t, [r]_{2t})` over `Gf128`
    /// in 1 round (used only for the tiny `O(log M)` verification proof).
    async fn gen_double_random_ext(&mut self, count: usize) -> Result<(ExtSecrets, ExtSecrets)> {
        let n = self.parties();
        let t = self.degree();
        let mut outgoing = vec![Vec::with_capacity(32 * count); n];
        let mut coeffs_t = ExtSecrets(vec![Gf128::ZERO; t + 1]);
        let mut coeffs_2t = ExtSecrets(vec![Gf128::ZERO; 2 * t + 1]);

        for _ in 0..count {
            let s = self.random_gf128();
            coeffs_t.0[0] = s;
            for c in &mut coeffs_t.0[1..] {
                *c = self.random_gf128();
            }
            coeffs_2t.0[0] = s;
            for c in &mut coeffs_2t.0[1..] {
                *c = self.random_gf128();
            }
            for (p, data) in outgoing.iter_mut().enumerate() {
                let x = point(p + 1);
                data.extend_from_slice(&evaluate_ext(&coeffs_t.0, x).to_bytes());
                data.extend_from_slice(&evaluate_ext(&coeffs_2t.0, x).to_bytes());
            }
        }

        let incoming = Zeroizing::new(self.exchange(outgoing).await?);
        let mut sum_t = ExtSecrets(vec![Gf128::ZERO; count]);
        let mut sum_2t = ExtSecrets(vec![Gf128::ZERO; count]);

        for data in incoming.iter() {
            ensure!(
                data.len() == 32 * count,
                "A dealer sent the wrong number of extension double shares"
            );
            for (i, chunk) in data.as_chunks::<32>().0.iter().enumerate() {
                let a: [u8; 16] = chunk[..16].try_into().expect("16 bytes");
                let b: [u8; 16] = chunk[16..].try_into().expect("16 bytes");
                sum_t.0[i] += Gf128::from_bytes(a);
                sum_2t.0[i] += Gf128::from_bytes(b);
            }
        }

        Ok((sum_t, sum_2t))
    }

    fn random_gf128(&mut self) -> Gf128 {
        let mut bytes = Zeroizing::new([0u8; 16]);
        self.rng.fill_bytes(bytes.as_mut());
        Gf128::from_bytes(*bytes)
    }

    /// Coin a 128-bit challenge over `Gf128` that no party can predict before
    /// committing.
    async fn coin_128(&mut self, context: &[u8]) -> Result<Gf128> {
        let mut nonce = Zeroizing::new([0u8; 32]);
        self.rng.fill_bytes(nonce.as_mut());

        let commitment = coin_commitment(self.party, context, nonce.as_ref());
        let commitments = self.consistent_broadcast(commitment.to_vec()).await?;
        let reveals = self.broadcast(nonce.to_vec()).await?;

        let mut mixed = Zeroizing::new([0u8; 32]);
        for (p, reveal) in reveals.iter().enumerate() {
            ensure!(
                reveal.len() == 32 && coin_commitment(p, context, reveal) == *commitments[p],
                "A party revealed a nonce that does not match its commitment"
            );
            for (m, &r) in mixed.iter_mut().zip(reveal) {
                *m ^= r;
            }
        }

        let mut hash = Sha256::new();
        hash.update(b"fedimint/mpc/coin128-output/v2");
        hash.update(context);
        hash.update(mixed.as_ref());

        let digest = hash.finalize();
        Ok(Gf128::from_bytes(
            digest[..16].try_into().expect("16 bytes"),
        ))
    }

    /// Coin a 128-bit challenge outside `excluded` (e.g. `{0, 1, 2, 3}`).
    async fn coin_128_excluding(&mut self, context: &[u8], excluded: &[Gf128]) -> Result<Gf128> {
        let mut c = self.coin_128(context).await?;
        let mut counter = 0u64;
        while excluded.contains(&c) {
            counter += 1;
            let mut h = Sha256::new();
            h.update(b"fedimint/mpc/coin128-rehash/v2");
            h.update(c.to_bytes());
            h.update(counter.to_le_bytes());
            let d = h.finalize();
            c = Gf128::from_bytes(d[..16].try_into().expect("16 bytes"));
        }
        Ok(c)
    }

    /// Open base-field degree-`t` sharings and verify all `n` shares lie on one
    /// degree-`t` polynomial.
    async fn open_base(&mut self, shares: &[F]) -> Result<Vec<F>> {
        let payload: Vec<u8> = shares.iter().map(|f| f.0).collect();
        let incoming = self.broadcast(payload).await?;
        self.reconstruct_base(&incoming, shares.len())
    }

    fn reconstruct_base(&self, incoming: &[Vec<u8>], count: usize) -> Result<Vec<F>> {
        for data in incoming {
            ensure!(
                data.len() == count,
                "A party opened the wrong number of base shares"
            );
        }

        let base = self.degree() + 1;
        let mut values = Vec::with_capacity(count);

        for i in 0..count {
            for (p, row) in incoming.iter().enumerate().skip(base) {
                let expected = self.interp_t[p + 1]
                    .iter()
                    .zip(&incoming[..base])
                    .fold(F(0), |acc, (&w, r)| acc + w * F(r[i]));
                ensure!(
                    expected == F(row[i]),
                    "Opened base shares are not on one polynomial"
                );
            }

            let val = self.interp_t[0]
                .iter()
                .zip(&incoming[..base])
                .fold(F(0), |acc, (&w, r)| acc + w * F(r[i]));
            values.push(val);
        }

        Ok(values)
    }

    /// Reconstruct degree-`2t` values in `GF(2^8)` from `incoming` (used in DN07
    /// online multiplication).
    ///
    /// Deliberately interpolates from the first `2t + 1` shares without an
    /// online consistency check on extra shares when `n > 2t + 1`: checking
    /// extra shares before `verify_triples` would allow a malicious king who
    /// equivocated in a previous layer to trigger a selective abort correlated
    /// with a secret wire. Any error in `r_2t` or shares is caught with over
    /// 100-bit soundness by `verify_triples` + `online_digest` before any
    /// public output or secret share is opened.
    fn reconstruct_2t_base(&self, incoming: &[Vec<u8>], count: usize) -> Result<Vec<F>> {
        for data in incoming {
            ensure!(
                data.len() == count,
                "A party sent the wrong number of DN07 values"
            );
        }

        let w0 = &self.interp_2t[0];
        let mut values = vec![F(0); count];

        for (j, &w) in w0.iter().enumerate() {
            for (val, &b) in values.iter_mut().zip(&incoming[j]) {
                *val += w * F(b);
            }
        }

        Ok(values)
    }

    /// Open extension-field degree-`t` sharings and verify all `n` shares lie on
    /// one degree-`t` polynomial over `Gf128`.
    async fn open_ext(&mut self, shares: &[Gf128]) -> Result<Vec<Gf128>> {
        let incoming = self.broadcast(encode_ext(shares)).await?;
        self.reconstruct_ext(&incoming, shares.len())
    }

    fn reconstruct_ext(&self, incoming: &[Vec<u8>], count: usize) -> Result<Vec<Gf128>> {
        let rows: Vec<Vec<Gf128>> = incoming
            .iter()
            .map(|data| {
                ensure!(
                    data.len() == 16 * count,
                    "A party opened the wrong number of extension shares"
                );
                Ok(decode_ext(data))
            })
            .collect::<Result<_>>()?;

        let base = self.degree() + 1;
        let mut values = Vec::with_capacity(count);

        for i in 0..count {
            for (p, row) in rows.iter().enumerate().skip(base) {
                let expected = self.interp_t[p + 1]
                    .iter()
                    .zip(&rows[..base])
                    .fold(Gf128::ZERO, |acc, (&w, r)| acc + r[i].scale(w));
                ensure!(
                    expected == row[i],
                    "Opened extension shares are not on one polynomial"
                );
            }

            let val = self.interp_t[0]
                .iter()
                .zip(&rows[..base])
                .fold(Gf128::ZERO, |acc, (&w, r)| acc + r[i].scale(w));
            values.push(val);
        }

        Ok(values)
    }

    /// Reshare degree-`2t` values over `Gf128` down to degree-`t` using
    /// pre-generated extension-field double-random pairs (DN07 over `Gf128`).
    async fn reshare_ext(
        &mut self,
        values_2t: &[Gf128],
        rt: &[Gf128],
        r2t: &[Gf128],
    ) -> Result<ExtSecrets> {
        let count = values_2t.len();
        ensure!(rt.len() == count && r2t.len() == count);

        let masked: Vec<Gf128> = values_2t.iter().zip(r2t).map(|(&v, &r)| v + r).collect();
        let incoming = self.broadcast(encode_ext(&masked)).await?;

        let rows: Vec<Vec<Gf128>> = incoming
            .iter()
            .map(|data| {
                ensure!(
                    data.len() == 16 * count,
                    "A party sent the wrong number of extension reshare values"
                );
                Ok(decode_ext(data))
            })
            .collect::<Result<_>>()?;

        let base = 2 * self.degree() + 1;
        let mut out = ExtSecrets(Vec::with_capacity(count));

        for i in 0..count {
            let d = self.interp_2t[0]
                .iter()
                .zip(&rows[..base])
                .fold(Gf128::ZERO, |acc, (&w, r)| acc + r[i].scale(w));
            out.0.push(d + rt[i]);
        }

        Ok(out)
    }

    /// Verify in 1 batched 128-bit check that all given base-field and
    /// extension-field shares lie on valid degree-`t` polynomials, with zero
    /// leakage (blinded by a fresh random `Gf128` degree-`t` sharing).
    async fn check_degree_t(
        &mut self,
        base_slices: &[&[F]],
        ext_slices: &[&[Gf128]],
        context: &[u8],
    ) -> Result<()> {
        let mask = self.random_ext(1).await?;
        let chi = self.coin_128(context).await?;

        let mut acc = mask.0[0];
        let mut power = chi;

        for slice in base_slices {
            for &v in *slice {
                acc += power.scale(v);
                power *= chi;
            }
        }
        for slice in ext_slices {
            for &v in *slice {
                acc += power * v;
                power *= chi;
            }
        }

        let _ = self.open_ext(&[acc]).await?;
        Ok(())
    }

    /// Online DN07 multiplication of `x` and `y` over `GF(2^8)` using
    /// load-balanced parallel kings (`2` rounds, `O(m)` total traffic, `O(1)`
    /// egress and interpolation CPU per guardian).
    async fn multiply_dn07(&mut self, x: &[F], y: &[F], rt: &[F], r2t: &[F]) -> Result<Vec<F>> {
        let count = x.len();
        ensure!(y.len() == count && rt.len() == count && r2t.len() == count);

        let masked: Vec<u8> = (0..count).map(|i| (x[i] * y[i] + r2t[i]).0).collect();

        let n = self.parties();
        let slice_range = |k: usize| (k * count / n)..((k + 1) * count / n);

        // Round 1 (scatter): send slice `k` to king `k`.
        let outgoing: Vec<Vec<u8>> = (0..n).map(|k| masked[slice_range(k)].to_vec()).collect();
        let incoming = self.exchange(outgoing).await?;

        // Each party `k = self.party` reconstructs only its `1 / n` slice
        // (`O(1)` work per AND gate independent of committee size `n`).
        let my_len = slice_range(self.party).len();
        let my_opened = self.reconstruct_2t_base(&incoming, my_len)?;
        let my_bytes: Vec<u8> = my_opened.into_iter().map(|f| f.0).collect();

        // Round 2 (gather): every king broadcasts its reconstructed slice.
        let gathered = self.broadcast(my_bytes).await?;

        let mut opened = Vec::with_capacity(count);
        for (k, slice) in gathered.iter().enumerate() {
            let expected = slice_range(k).len();
            ensure!(
                slice.len() == expected,
                "A king broadcast the wrong number of reconstructed values"
            );
            self.online_transcript.update(slice);
            opened.extend(slice.iter().map(|&b| F(b)));
        }

        Ok((0..count).map(|i| opened[i] + rt[i]).collect())
    }

    /// Verify all `M` multiplication triples `(x_k, y_k, z_k)` over `GF(2^8)`
    /// via a 4-way BBCGI19 recursive inner-product proof over `Gf128` (128-bit
    /// field soundness, zero leakage).
    async fn verify_triples(
        &mut self,
        log_x: &[F],
        log_y: &[F],
        log_z: &[F],
        context: &[u8],
    ) -> Result<()> {
        let m_total = log_x.len();
        ensure!(log_y.len() == m_total && log_z.len() == m_total);
        if m_total == 0 {
            return Ok(());
        }

        // Count 4-way folding steps down to length 1.
        let mut folds = 0usize;
        let mut cur_len = m_total;
        while cur_len > 1 {
            cur_len = cur_len.div_ceil(4);
            folds += 1;
        }

        // Pre-generate all extension-field randomness for the proof:
        // 6 double-sharings per 4-way fold + 2 for the base case, plus 2
        // blinding sharings `(u, v)` for the zero-knowledge base case.
        let ext_pairs = 6 * folds + 2;
        let (ext_rt, ext_r2t) = self.gen_double_random_ext(ext_pairs).await?;
        let uv = self.random_ext(2).await?;
        let mut ext_cursor = 0usize;

        // Bind the online DN07 transcript digest into verification context.
        let online_digest = self.online_transcript.clone().finalize();
        let mut vctx = context.to_vec();
        vctx.extend_from_slice(b"fedimint/mpc/verify/v2");
        vctx.extend_from_slice(&online_digest);

        // Verify all extension-field degree-`t` sharings used in the proof.
        let mut dctx = vctx.clone();
        dctx.extend_from_slice(b"/ext-deg");
        self.check_degree_t(&[], &[&ext_rt.0, &uv.0], &dctx).await?;

        // Coin the batching challenge `alpha` over `Gf128`.
        let mut actx = vctx.clone();
        actx.extend_from_slice(b"/alpha");
        let alpha = self.coin_128(&actx).await?;

        let excluded_0123 = [
            Gf128::embed(F(0)),
            Gf128::embed(F(1)),
            Gf128::embed(F(2)),
            Gf128::embed(F(3)),
        ];

        // Precompute base-field Lagrange weights from `{0, 1, 2, 3}` to `{4, 5, 6}`.
        let w4_to: [[F; 4]; 3] = std::array::from_fn(|idx| {
            let w = weights(&[0, 1, 2, 3], idx + 4);
            [w[0], w[1], w[2], w[3]]
        });

        let mut claim = Gf128::ZERO;
        let mut pow = alpha;
        for &z in log_z {
            claim += pow.scale(z);
            pow *= alpha;
        }

        let (mut a, mut b) = if m_total == 1 {
            (
                ExtSecrets(vec![alpha.scale(log_x[0])]),
                ExtSecrets(vec![Gf128::embed(log_y[0])]),
            )
        } else {
            // Pass 1: stream directly from 1-byte `GF(2^8)` logs into `ceil(M/4)`
            // `Gf128` elements without ever allocating an `M`-element `Vec<Gf128>`.
            let groups = m_total.div_ceil(4);
            let mut h_2t = [Gf128::ZERO; 7];
            let mut alpha_pow = alpha;

            for g in 0..groups {
                let mut fx = [Gf128::ZERO; 4];
                let mut gy = [F(0); 4];
                for j in 0..4 {
                    let idx = 4 * g + j;
                    if idx < m_total {
                        fx[j] = alpha_pow.scale(log_x[idx]);
                        gy[j] = log_y[idx];
                        alpha_pow *= alpha;
                    }
                }

                // Points 0, 1, 2 (point 3 is derived from `claim + h0 + h1 + h2`).
                h_2t[0] += fx[0].scale(gy[0]);
                h_2t[1] += fx[1].scale(gy[1]);
                h_2t[2] += fx[2].scale(gy[2]);

                // Points 4, 5, 6: `gy` stays in `GF(2^8)` so `fx * gy` uses `.scale()`.
                for t_idx in 0..3 {
                    let w = &w4_to[t_idx];
                    let ft = fx[0].scale(w[0])
                        + fx[1].scale(w[1])
                        + fx[2].scale(w[2])
                        + fx[3].scale(w[3]);
                    let gt = gy[0] * w[0] + gy[1] * w[1] + gy[2] * w[2] + gy[3] * w[3];
                    h_2t[t_idx + 4] += ft.scale(gt);
                }
            }

            let h_send = [h_2t[0], h_2t[1], h_2t[2], h_2t[4], h_2t[5], h_2t[6]];
            let h_t_six = self
                .reshare_ext(
                    &h_send,
                    &ext_rt.0[ext_cursor..ext_cursor + 6],
                    &ext_r2t.0[ext_cursor..ext_cursor + 6],
                )
                .await?;
            ext_cursor += 6;

            let h_t = [
                h_t_six.0[0],
                h_t_six.0[1],
                h_t_six.0[2],
                claim + h_t_six.0[0] + h_t_six.0[1] + h_t_six.0[2],
                h_t_six.0[3],
                h_t_six.0[4],
                h_t_six.0[5],
            ];

            let mut rctx = vctx.clone();
            rctx.extend_from_slice(b"/fold/");
            rctx.extend_from_slice(&0u64.to_le_bytes());
            let r = self.coin_128_excluding(&rctx, &excluded_0123).await?;

            let basis4 = Gf128::lagrange_basis(&[0, 1, 2, 3], r);
            let basis7 = Gf128::lagrange_basis(&[0, 1, 2, 3, 4, 5, 6], r);

            claim = h_t
                .iter()
                .zip(&basis7)
                .fold(Gf128::ZERO, |acc, (&h, &w)| acc + h * w);

            let mut next_a = ExtSecrets(Vec::with_capacity(groups));
            let mut next_b = ExtSecrets(Vec::with_capacity(groups));
            let mut alpha_pow = alpha;

            for g in 0..groups {
                let mut fa = Gf128::ZERO;
                let mut gb = Gf128::ZERO;
                for (j, &w) in basis4.iter().enumerate() {
                    let idx = 4 * g + j;
                    if idx < m_total {
                        fa += (alpha_pow * w).scale(log_x[idx]);
                        gb += w.scale(log_y[idx]);
                        alpha_pow *= alpha;
                    }
                }
                next_a.0.push(fa);
                next_b.0.push(gb);
            }

            (next_a, next_b)
        };

        // Subsequent 4-way folding passes over `Gf128`.
        let mut fold_idx = 1u64;
        while a.0.len() > 1 {
            let cur_len = a.0.len();
            let groups = cur_len.div_ceil(4);
            let mut h_2t = [Gf128::ZERO; 7];

            for g in 0..groups {
                let mut fx = [Gf128::ZERO; 4];
                let mut gy = [Gf128::ZERO; 4];
                for j in 0..4 {
                    let idx = 4 * g + j;
                    if idx < cur_len {
                        fx[j] = a.0[idx];
                        gy[j] = b.0[idx];
                    }
                }

                h_2t[0] += fx[0] * gy[0];
                h_2t[1] += fx[1] * gy[1];
                h_2t[2] += fx[2] * gy[2];

                for t_idx in 0..3 {
                    let w = &w4_to[t_idx];
                    let ft = fx[0].scale(w[0])
                        + fx[1].scale(w[1])
                        + fx[2].scale(w[2])
                        + fx[3].scale(w[3]);
                    let gt = gy[0].scale(w[0])
                        + gy[1].scale(w[1])
                        + gy[2].scale(w[2])
                        + gy[3].scale(w[3]);
                    h_2t[t_idx + 4] += ft * gt;
                }
            }

            let h_send = [h_2t[0], h_2t[1], h_2t[2], h_2t[4], h_2t[5], h_2t[6]];
            let h_t_six = self
                .reshare_ext(
                    &h_send,
                    &ext_rt.0[ext_cursor..ext_cursor + 6],
                    &ext_r2t.0[ext_cursor..ext_cursor + 6],
                )
                .await?;
            ext_cursor += 6;

            let h_t = [
                h_t_six.0[0],
                h_t_six.0[1],
                h_t_six.0[2],
                claim + h_t_six.0[0] + h_t_six.0[1] + h_t_six.0[2],
                h_t_six.0[3],
                h_t_six.0[4],
                h_t_six.0[5],
            ];

            let mut rctx = vctx.clone();
            rctx.extend_from_slice(b"/fold/");
            rctx.extend_from_slice(&fold_idx.to_le_bytes());
            fold_idx += 1;
            let r = self.coin_128_excluding(&rctx, &excluded_0123).await?;

            let basis4 = Gf128::lagrange_basis(&[0, 1, 2, 3], r);
            let basis7 = Gf128::lagrange_basis(&[0, 1, 2, 3, 4, 5, 6], r);

            claim = h_t
                .iter()
                .zip(&basis7)
                .fold(Gf128::ZERO, |acc, (&h, &w)| acc + h * w);

            let mut next_a = ExtSecrets(Vec::with_capacity(groups));
            let mut next_b = ExtSecrets(Vec::with_capacity(groups));
            for g in 0..groups {
                let mut fa = Gf128::ZERO;
                let mut gb = Gf128::ZERO;
                for (j, &w) in basis4.iter().enumerate() {
                    let idx = 4 * g + j;
                    if idx < cur_len {
                        fa += a.0[idx] * w;
                        gb += b.0[idx] * w;
                    }
                }
                next_a.0.push(fa);
                next_b.0.push(gb);
            }
            a = next_a;
            b = next_b;
        }

        // Zero-knowledge base case: prove `a[0] * b[0] == claim` using fresh
        // random masks `(u, v)`.
        let (a0, b0) = (a.0[0], b.0[0]);
        let (u, v) = (uv.0[0], uv.0[1]);

        let f2 = a0 + (a0 + u).scale(F(2));
        let g2 = b0 + (b0 + v).scale(F(2));
        let h_base = self
            .reshare_ext(
                &[u * v, f2 * g2],
                &ext_rt.0[ext_cursor..ext_cursor + 2],
                &ext_r2t.0[ext_cursor..ext_cursor + 2],
            )
            .await?;
        ext_cursor += 2;
        ensure!(ext_cursor == ext_pairs, "Unused verification pairs");

        let mut bctx = vctx;
        bctx.extend_from_slice(b"/base");
        let r = self.coin_128_excluding(&bctx, &[Gf128::ZERO]).await?;

        let f_r = a0 + r * (a0 + u);
        let g_r = b0 + r * (b0 + v);
        let basis3 = Gf128::lagrange_basis(&[0, 1, 2], r);
        let h_r = claim * basis3[0] + h_base.0[0] * basis3[1] + h_base.0[1] * basis3[2];

        let opened = self.open_ext(&[f_r, g_r, h_r]).await?;
        ensure!(
            opened[0] * opened[1] == opened[2],
            "Verification of circuit multiplications failed"
        );

        Ok(())
    }

    /// Give every party a `GF(2^8)` Shamir share of each 256-bit secret in
    /// `bits` (sharings of bits, most significant first), and return this
    /// party's `[u8; 32]` shares.
    async fn deal_secrets(&mut self, bits: &[F], context: &[u8]) -> Result<Vec<[u8; 32]>> {
        let degree = self.degree();
        let byte_count = bits.len() / 8;

        // Pack 8 bit sharings linearly into one `GF(2^8)` byte sharing.
        let values = Secrets(
            bits.as_chunks::<8>()
                .0
                .iter()
                .map(|byte_bits| {
                    byte_bits
                        .iter()
                        .enumerate()
                        .fold(F(0), |acc, (b, &bit)| acc + bit * F(1u8 << (7 - b)))
                })
                .collect(),
        );

        let coefficients = self.random_base(byte_count * degree).await?;

        // Check that all random higher-degree coefficients are valid degree-`t`
        // sharings before sending recipient shares.
        let mut sctx = context.to_vec();
        sctx.extend_from_slice(b"fedimint/mpc/deal-deg/v2");
        self.check_degree_t(&[&coefficients.0], &[], &sctx).await?;

        let outgoing: Vec<Vec<u8>> = (0..self.parties())
            .map(|recipient| {
                let x = point(recipient + 1);
                let mut buf = Vec::with_capacity(byte_count);
                for w in 0..byte_count {
                    let higher = &coefficients.0[w * degree..(w + 1) * degree];
                    buf.push((values.0[w] + evaluate(higher, x) * x).0);
                }
                buf
            })
            .collect();

        let incoming = Zeroizing::new(self.exchange(outgoing).await?);
        let own = Secrets(self.reconstruct_base(&incoming, byte_count)?);

        let shares = own
            .0
            .as_chunks::<32>()
            .0
            .iter()
            .map(|chunk| std::array::from_fn(|i| chunk[i].0))
            .collect();

        Ok(shares)
    }
}

fn derive_prg(context: &[u8], sender: usize, recipient: usize, seed: &[u8; 32]) -> ChaCha20Rng {
    let mut hash = Sha256::new();
    hash.update(b"fedimint/mpc/prg-share/v2");
    hash.update(context);
    hash.update((sender as u64).to_le_bytes());
    hash.update((recipient as u64).to_le_bytes());
    hash.update(seed);
    ChaCha20Rng::from_seed(hash.finalize().into())
}

fn coin_commitment(party: usize, context: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"fedimint/mpc/coin128/v2");
    hash.update((party as u64).to_le_bytes());
    hash.update(context);
    hash.update(nonce);
    hash.finalize().into()
}

fn encode_ext(fields: &[Gf128]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.len() * 16);
    for f in fields {
        out.extend_from_slice(&f.to_bytes());
    }
    out
}

fn decode_ext(bytes: &[u8]) -> Vec<Gf128> {
    bytes
        .as_chunks::<16>()
        .0
        .iter()
        .map(|c| Gf128::from_bytes(*c))
        .collect()
}

/// What a run gives this party.
pub struct Output {
    /// The public outputs, in circuit order.
    pub public: Vec<bool>,
    /// This party's `GF(2^8)` Shamir share of each secret output, in circuit
    /// order, 32 bytes each, at evaluation point `party + 1`.
    pub shares: Vec<[u8; 32]>,
}

impl Drop for Output {
    fn drop(&mut self) {
        for share in &mut self.shares {
            share.zeroize();
        }
    }
}

/// Evaluate `circuit` jointly and return its outputs.
///
/// `context` must be unique to the run and the same for every party; it binds
/// the challenges. All of this party's randomness comes from `seed`, which
/// must be fresh, secret and used once.
pub async fn run<T: Transport>(
    transport: &mut T,
    params: Params,
    party: usize,
    circuit: &Circuit,
    inputs: &[bool],
    seed: &[u8; 32],
    context: &[u8],
) -> Result<Output> {
    circuit.validate()?;

    let lanes = circuit.lanes;

    ensure!(party < params.parties, "Party index out of range");
    ensure!(
        circuit.parties == params.parties && inputs.len() == circuit.total_inputs_per_party(),
        "Circuit does not match the parties or inputs"
    );

    let schedule = circuit.schedule();
    let input_count = circuit.input_count();
    let and_total = schedule
        .and_count
        .checked_mul(lanes)
        .context("AND gate count overflow")?;
    let triple_count = schedule
        .and_count
        .checked_add(input_count)
        .and_then(|per_lane| per_lane.checked_mul(lanes))
        .context("Triple count overflow")?;

    ensure!(
        triple_count <= MAX_TRIPLES,
        "The run needs too many triples"
    );

    let mut rng_seed = Sha256::new();
    rng_seed.update(b"fedimint/mpc/engine-rng/v2");
    rng_seed.update(seed);

    let points_t: Vec<usize> = (1..=params.degree + 1).collect();
    let points_2t: Vec<usize> = (1..=2 * params.degree + 1).collect();

    let mut engine = Engine {
        transport,
        params,
        party,
        round: 0,
        rng: ChaCha20Rng::from_seed(rng_seed.finalize().into()),
        send_rngs: (0..params.parties).map(|_| None).collect(),
        recv_rngs: (0..params.parties).map(|_| None).collect(),
        interp_t: (0..=params.parties)
            .map(|target| weights(&points_t, target))
            .collect(),
        interp_2t: (0..=params.parties)
            .map(|target| weights(&points_2t, target))
            .collect(),
        online_transcript: Sha256::new(),
    };

    let mut context = context.to_vec();
    context.extend_from_slice(&circuit.id());
    context.extend_from_slice(&(params.parties as u64).to_le_bytes());
    context.extend_from_slice(&(params.degree as u64).to_le_bytes());
    context.extend_from_slice(&(triple_count as u64).to_le_bytes());

    let configurations = engine.consistent_broadcast(context.clone()).await?;
    ensure!(
        configurations.iter().all(|c| *c == context),
        "Parties disagree on the computation"
    );

    // Round 2: exchange pairwise PRG seeds.
    engine.init_prg_seeds(&context).await?;

    // Round 3: generate all `and_total` double-random pairs in 1 round.
    let (r_t, r_2t) = engine.gen_double_random(and_total).await?;

    // Round 4: deal inputs over `GF(2^8)`.
    let own = Secrets(inputs.iter().map(|&b| F(u8::from(b))).collect());
    let dealt = engine.share_base(&own.0).await?;

    // Transpose dealt shares into `[wire * lanes + lane]` layout.
    let mut input = Secrets(vec![F(0); input_count * lanes]);
    for (p, row) in dealt.iter().enumerate() {
        for lane in 0..lanes {
            let src_base = lane * circuit.inputs_per_party;
            for bit in 0..circuit.inputs_per_party {
                let wire = p * circuit.inputs_per_party + bit;
                input.0[wire * lanes + lane] = row.0[src_base + bit];
            }
        }
    }
    drop(dealt);

    // Rounds 5..8: 128-bit batched degree-`t` check over all `r_t` and `input`.
    let mut deg_ctx = context.clone();
    deg_ctx.extend_from_slice(b"fedimint/mpc/pre-deg/v2");
    engine
        .check_degree_t(&[&r_t.0, &input.0], &[], &deg_ctx)
        .await?;

    // Compact live-wire buffer: `[slot * lanes + lane]`.
    let mut wires = Secrets(vec![F(0); schedule.slot_count * lanes]);
    for w in 0..input_count {
        let dst = schedule.wire_slot[w] * lanes;
        wires.0[dst..dst + lanes].copy_from_slice(&input.0[w * lanes..(w + 1) * lanes]);
    }

    // Compact 1-byte-per-element triple logs for the end-of-circuit 128-bit proof.
    let mut log_x = Secrets(Vec::with_capacity(triple_count));
    let mut log_y = Secrets(Vec::with_capacity(triple_count));
    let mut log_z = Secrets(Vec::with_capacity(triple_count));

    // Fold input bit-checks `x * (x + 1) == 0` directly into the verification
    // log with ZERO online rounds or double-random pairs.
    for &x in &input.0 {
        log_x.0.push(x);
        log_y.0.push(x + F(1));
        log_z.0.push(F(0));
    }
    drop(input);

    let mut r_cursor = 0usize;

    for depth in 0..schedule.linear.len() {
        let gates = &schedule.nonlinear[depth];

        if !gates.is_empty() {
            let count = gates.len() * lanes;
            let mut left = Secrets(Vec::with_capacity(count));
            let mut right = Secrets(Vec::with_capacity(count));

            for &i in gates {
                let Gate::And(a, b) = circuit.gates[i] else {
                    unreachable!("Only AND gates are scheduled as nonlinear");
                };

                let sa = schedule.wire_slot[a] * lanes;
                let sb = schedule.wire_slot[b] * lanes;
                left.0.extend_from_slice(&wires.0[sa..sa + lanes]);
                right.0.extend_from_slice(&wires.0[sb..sb + lanes]);
            }

            let products = engine
                .multiply_dn07(
                    &left.0,
                    &right.0,
                    &r_t.0[r_cursor..r_cursor + count],
                    &r_2t.0[r_cursor..r_cursor + count],
                )
                .await?;
            r_cursor += count;

            log_x.0.extend_from_slice(&left.0);
            log_y.0.extend_from_slice(&right.0);
            log_z.0.extend_from_slice(&products);

            for (idx, &i) in gates.iter().enumerate() {
                let dst = schedule.wire_slot[input_count + i] * lanes;
                wires.0[dst..dst + lanes]
                    .copy_from_slice(&products[idx * lanes..(idx + 1) * lanes]);
            }
        }

        for &i in &schedule.linear[depth] {
            let dst = schedule.wire_slot[input_count + i] * lanes;
            match circuit.gates[i] {
                Gate::Xor(a, b) => {
                    let sa = schedule.wire_slot[a] * lanes;
                    let sb = schedule.wire_slot[b] * lanes;
                    for lane in 0..lanes {
                        wires.0[dst + lane] = wires.0[sa + lane] + wires.0[sb + lane];
                    }
                }
                Gate::Not(a) => {
                    let sa = schedule.wire_slot[a] * lanes;
                    for lane in 0..lanes {
                        wires.0[dst + lane] = wires.0[sa + lane] + F(1);
                    }
                }
                Gate::And(..) => unreachable!("AND gates are nonlinear"),
            }
        }
    }

    ensure!(
        r_cursor == and_total,
        "The run left double-random pairs unused"
    );
    drop(r_t);
    drop(r_2t);

    // 128-bit malicious verification BEFORE revealing any output or dealing
    // any secret share.
    engine
        .verify_triples(&log_x.0, &log_y.0, &log_z.0, &context)
        .await?;
    drop(log_x);
    drop(log_y);
    drop(log_z);

    let mut outputs = Secrets(Vec::with_capacity(lanes * circuit.outputs.len()));
    for lane in 0..lanes {
        for &w in &circuit.outputs {
            outputs
                .0
                .push(wires.0[schedule.wire_slot[w] * lanes + lane]);
        }
    }

    let opened = engine.open_base(&outputs.0).await?;

    let public = opened
        .into_iter()
        .map(|x| match x.0 {
            0 => Ok(false),
            1 => Ok(true),
            _ => None.context("An output is not a bit"),
        })
        .collect::<Result<_>>()?;

    let mut secret = Secrets(Vec::with_capacity(lanes * circuit.secret_outputs.len()));
    for lane in 0..lanes {
        for &w in &circuit.secret_outputs {
            secret.0.push(wires.0[schedule.wire_slot[w] * lanes + lane]);
        }
    }

    let shares = engine.deal_secrets(&secret.0, &context).await?;

    Ok(Output { public, shares })
}
