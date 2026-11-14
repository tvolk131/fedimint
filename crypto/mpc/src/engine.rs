//! Honest-majority MPC with abort over Boolean circuits.
//!
//! Wires are degree-`degree` Shamir sharings over GF(2^64) holding 0 or 1;
//! party `i` holds the evaluation at `i + 1`. With `parties >= 2 * degree + 1`
//! and at most `degree` malicious parties:
//!
//! - Privacy: any `degree` shares are independent of the secret.
//! - Openings: every party sends its share to every party, and each receiver
//!   checks that all `parties` shares lie on one degree-`degree` polynomial.
//!   The honest parties hold at least `degree + 1` shares, which fix the
//!   polynomial, so a malicious share either matches it or the receiver aborts.
//!   All honest receivers that continue therefore see the same value.
//! - Multiplication: triples are made by local multiplication, degree reduction
//!   and resharing, then each is checked against a second triple sharing its
//!   `b` under a random challenge (sacrifice). Gates use Beaver's method.
//! - Inputs: every input wire is checked to be a bit.
//! - Secret outputs: a 256-bit secret `v`, held as bit sharings, becomes four
//!   field-element sharings by a local linear map. Each party then gets one
//!   Shamir share of `v`: the evaluation at its point of a degree-`degree`
//!   polynomial whose constant term is `v` and whose other coefficients are
//!   random values nobody knows. Every party computes its sharing of each
//!   recipient's share locally and sends it to that recipient only, who checks
//!   it like an opening. Nothing about a share is ever made public.
//!
//! A malicious party can make honest parties abort but not change an output.
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
use crate::field::{F, evaluate, point, weights};
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

/// Field elements that are wiped when dropped.
struct Secrets(Vec<F>);

impl Drop for Secrets {
    fn drop(&mut self) {
        for f in &mut self.0 {
            f.0.zeroize();
        }
    }
}

struct Triples {
    a: Secrets,
    b: Secrets,
    c: Secrets,
    next: usize,
}

struct Engine<'t, T> {
    transport: &'t mut T,
    params: Params,
    party: usize,
    round: u64,
    rng: ChaCha20Rng,
    /// `interpolation[p]` evaluates at point `p` the polynomial through the
    /// shares of the first `degree + 1` parties.
    interpolation: Vec<Vec<F>>,
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

        hash.update(b"fedimint/mpc/echo/v1");
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

    /// Deal a fresh sharing of each of `values` to every party and return, per
    /// dealer, the shares this party received.
    async fn share(&mut self, values: &[F]) -> Result<Vec<Secrets>> {
        let n = self.parties();

        let mut outgoing = vec![Vec::with_capacity(8 * values.len()); n];
        let mut coefficients = Secrets(vec![F(0); self.degree() + 1]);

        for &value in values {
            coefficients.0[0] = value;

            for c in &mut coefficients.0[1..] {
                *c = F(self.rng.next_u64());
            }

            for (p, data) in outgoing.iter_mut().enumerate() {
                data.extend_from_slice(&evaluate(&coefficients.0, point(p + 1)).0.to_le_bytes());
            }
        }

        let incoming = Zeroizing::new(self.exchange(outgoing).await?);

        incoming
            .iter()
            .map(|data| {
                ensure!(
                    data.len() == 8 * values.len(),
                    "A dealer sent the wrong number of shares"
                );

                Ok(Secrets(decode(data)))
            })
            .collect()
    }

    /// Sum every dealer's sharing of each value.
    async fn share_sum(&mut self, values: &[F]) -> Result<Secrets> {
        let rows = self.share(values).await?;

        let mut sum = Secrets(vec![F(0); values.len()]);

        for row in &rows {
            for (total, &share) in sum.0.iter_mut().zip(&row.0) {
                *total += share;
            }
        }

        Ok(sum)
    }

    /// Sharings of `count` random values nobody knows.
    async fn random(&mut self, count: usize) -> Result<Secrets> {
        let own = Secrets((0..count).map(|_| F(self.rng.next_u64())).collect());

        self.share_sum(&own.0).await
    }

    /// Reveal the values behind `shares`, checking that every party's share
    /// lies on one degree-`degree` polynomial.
    async fn open(&mut self, shares: &[F]) -> Result<Vec<F>> {
        let incoming = self.broadcast(encode(shares)).await?;

        self.reconstruct(&incoming, shares.len())
    }

    /// The values behind every party's shares in `incoming`, which must lie on
    /// one degree-`degree` polynomial per value.
    fn reconstruct(&self, incoming: &[Vec<u8>], count: usize) -> Result<Vec<F>> {
        let rows = incoming
            .iter()
            .map(|data| {
                ensure!(
                    data.len() == 8 * count,
                    "A party opened the wrong number of shares"
                );

                Ok(decode(data))
            })
            .collect::<Result<Vec<_>>>()?;

        let base = self.degree() + 1;

        let interpolate = |target: usize, i: usize| {
            self.interpolation[target]
                .iter()
                .zip(&rows[..base])
                .fold(F(0), |acc, (&w, row)| acc + w * row[i])
        };

        let mut values = Vec::with_capacity(count);

        for i in 0..count {
            for (p, row) in rows.iter().enumerate().skip(base) {
                ensure!(
                    interpolate(p + 1, i) == row[i],
                    "Opened shares are not on one polynomial"
                );
            }

            values.push(interpolate(0, i));
        }

        Ok(values)
    }

    /// Give every party a Shamir share of each 256-bit secret in `bits`
    /// (sharings of bits, most significant first), and return this party's
    /// shares.
    async fn deal_secrets(&mut self, bits: &[F]) -> Result<Vec<[u8; 32]>> {
        let degree = self.degree();
        let words = bits.len() / 64;

        // Bit b of a word, most significant first, is the field element with
        // only that bit set; composing a word is linear in its bit sharings.
        let values = Secrets(
            bits.as_chunks::<64>()
                .0
                .iter()
                .map(|word| {
                    word.iter()
                        .enumerate()
                        .fold(F(0), |acc, (b, &bit)| acc + bit * F(1u64 << (63 - b)))
                })
                .collect(),
        );

        let coefficients = self.random(words * degree).await?;

        let outgoing = (0..self.parties())
            .map(|recipient| {
                let x = point(recipient + 1);

                let shares = Secrets(
                    (0..words)
                        .map(|w| {
                            let higher = &coefficients.0[w * degree..(w + 1) * degree];

                            values.0[w] + evaluate(higher, x) * x
                        })
                        .collect(),
                );

                encode(&shares.0)
            })
            .collect();

        let incoming = Zeroizing::new(self.exchange(outgoing).await?);

        // Wiped when dropped.
        let own = Secrets(self.reconstruct(&incoming, words)?);

        let shares = own
            .0
            .as_chunks::<4>()
            .0
            .iter()
            .map(|value| {
                let mut out = [0u8; 32];

                for (chunk, word) in out.chunks_mut(8).zip(value) {
                    chunk.copy_from_slice(&word.0.to_be_bytes());
                }

                out
            })
            .collect();

        Ok(shares)
    }

    /// A random challenge no party can predict before it has committed.
    async fn coin(&mut self, context: &[u8]) -> Result<F> {
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

        hash.update(b"fedimint/mpc/coin-output/v1");
        hash.update(context);
        hash.update(mixed.as_ref());

        let digest = hash.finalize();

        Ok(F(u64::from_le_bytes(
            digest[..8].try_into().expect("eight bytes"),
        )))
    }

    /// `count` checked multiplication triples.
    async fn preprocess(&mut self, count: usize, context: &[u8]) -> Result<Triples> {
        let random = self.random(3 * count).await?;

        let (a, rest) = random.0.split_at(count);
        let (a_check, b) = rest.split_at(count);

        // Products of degree-`degree` shares lie on a degree-`2 * degree`
        // polynomial. Its value at zero is a fixed combination of the first
        // `2 * degree + 1` parties' products; each of them reshares its term.
        let points: Vec<usize> = (1..=2 * self.degree() + 1).collect();
        let factor = weights(&points, 0).get(self.party).copied().unwrap_or(F(0));

        let products = Secrets(
            a.iter()
                .zip(b)
                .chain(a_check.iter().zip(b))
                .map(|(&x, &y)| x * y * factor)
                .collect(),
        );

        let reduced = self.share_sum(&products.0).await?;

        let (c, c_check) = reduced.0.split_at(count);

        // Every candidate is fixed before anyone commits to the challenge.
        let t = self.coin(context).await?;

        let rho = Secrets(a.iter().zip(a_check).map(|(&a, &ac)| t * a + ac).collect());

        let rho = self.open(&rho.0).await?;

        // t * c + c_check + rho * b = t * (c - ab) + (c_check - a_check * b),
        // which is zero for correct triples and otherwise zero only with
        // probability 2^-64.
        let checks = Secrets(
            (0..count)
                .map(|i| t * c[i] + c_check[i] + rho[i] * b[i])
                .collect(),
        );

        let opened = self.open(&checks.0).await?;

        ensure!(
            opened.iter().all(|&x| x == F(0)),
            "A multiplication triple failed its check"
        );

        Ok(Triples {
            a: Secrets(a.to_vec()),
            b: Secrets(b.to_vec()),
            c: Secrets(c.to_vec()),
            next: 0,
        })
    }

    async fn multiply(&mut self, x: &[F], y: &[F], triples: &mut Triples) -> Result<Vec<F>> {
        ensure!(
            x.len() == y.len() && triples.next + x.len() <= triples.a.0.len(),
            "Out of multiplication triples"
        );

        let start = triples.next;

        // A triple is spent once anything derived from it is sent.
        triples.next += x.len();

        let masked = Secrets(
            x.iter()
                .zip(&triples.a.0[start..])
                .chain(y.iter().zip(&triples.b.0[start..]))
                .map(|(&v, &m)| v + m)
                .collect(),
        );

        let opened = self.open(&masked.0).await?;

        Ok((0..x.len())
            .map(|i| {
                let (d, e, j) = (opened[i], opened[x.len() + i], start + i);

                triples.c.0[j] + d * triples.b.0[j] + e * triples.a.0[j] + d * e
            })
            .collect())
    }
}

fn coin_commitment(party: usize, context: &[u8], nonce: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();

    hash.update(b"fedimint/mpc/coin/v1");
    hash.update((party as u64).to_le_bytes());
    hash.update(context);
    hash.update(nonce);

    hash.finalize().into()
}

fn encode(fields: &[F]) -> Vec<u8> {
    fields.iter().flat_map(|f| f.0.to_le_bytes()).collect()
}

fn decode(bytes: &[u8]) -> Vec<F> {
    bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| F(u64::from_le_bytes(*c)))
        .collect()
}

/// What a run gives this party.
pub struct Output {
    /// The public outputs, in circuit order.
    pub public: Vec<bool>,
    /// This party's Shamir share of each secret output, in circuit order,
    /// four big-endian GF(2^64) words each, at evaluation point `party + 1`.
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

    ensure!(party < params.parties, "Party index out of range");
    ensure!(
        circuit.parties == params.parties && inputs.len() == circuit.inputs_per_party,
        "Circuit does not match the parties or inputs"
    );

    let schedule = circuit.schedule();
    let input_count = circuit.input_count();
    let triple_count = schedule.and_count + input_count;

    ensure!(
        triple_count <= MAX_TRIPLES,
        "The run needs too many triples"
    );

    let mut rng_seed = Sha256::new();

    rng_seed.update(b"fedimint/mpc/engine-rng/v1");
    rng_seed.update(seed);

    let points: Vec<usize> = (1..=params.degree + 1).collect();

    let mut engine = Engine {
        transport,
        params,
        party,
        round: 0,
        rng: ChaCha20Rng::from_seed(rng_seed.finalize().into()),
        interpolation: (0..=params.parties)
            .map(|target| weights(&points, target))
            .collect(),
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

    let mut triples = engine.preprocess(triple_count, &context).await?;

    let own = Secrets(inputs.iter().map(|&b| F(u64::from(b))).collect());

    let dealt = engine.share(&own.0).await?;

    let input = Secrets(dealt.iter().flat_map(|row| row.0.iter().copied()).collect());

    let plus_one = Secrets(input.0.iter().map(|&x| x + F(1)).collect());

    let bit_checks = engine.multiply(&input.0, &plus_one.0, &mut triples).await?;

    ensure!(
        engine.open(&bit_checks).await?.iter().all(|&x| x == F(0)),
        "A party supplied an input that is not a bit"
    );

    let mut wires = Secrets(vec![F(0); circuit.wire_count()]);

    wires.0[..input_count].copy_from_slice(&input.0);

    for depth in 0..schedule.linear.len() {
        let gates = &schedule.nonlinear[depth];

        if !gates.is_empty() {
            let mut left = Secrets(Vec::with_capacity(gates.len()));
            let mut right = Secrets(Vec::with_capacity(gates.len()));

            for &i in gates {
                let Gate::And(a, b) = circuit.gates[i] else {
                    unreachable!("Only AND gates are scheduled as nonlinear");
                };

                left.0.push(wires.0[a]);
                right.0.push(wires.0[b]);
            }

            let products = engine.multiply(&left.0, &right.0, &mut triples).await?;

            for (&i, product) in gates.iter().zip(products) {
                wires.0[input_count + i] = product;
            }
        }

        for &i in &schedule.linear[depth] {
            wires.0[input_count + i] = match circuit.gates[i] {
                Gate::Xor(a, b) => wires.0[a] + wires.0[b],
                Gate::Not(a) => wires.0[a] + F(1),
                Gate::And(..) => unreachable!("AND gates are nonlinear"),
            };
        }
    }

    ensure!(triples.next == triple_count, "The run left triples unused");

    let outputs = Secrets(circuit.outputs.iter().map(|&i| wires.0[i]).collect());

    let opened = engine.open(&outputs.0).await?;

    let public = opened
        .into_iter()
        .map(|x| match x.0 {
            0 => Ok(false),
            1 => Ok(true),
            _ => None.context("An output is not a bit"),
        })
        .collect::<Result<_>>()?;

    let secret = Secrets(circuit.secret_outputs.iter().map(|&i| wires.0[i]).collect());

    let shares = engine.deal_secrets(&secret.0).await?;

    Ok(Output { public, shares })
}
