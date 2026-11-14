//! Boolean circuits and the preimage generator circuit.

use anyhow::{Context as _, Result, bail, ensure};
use sha2::{Digest as _, Sha256};

use crate::field::{F, point};
use crate::{MAX_PARTIES, MAX_TRIPLES};

/// AND gates in one SHA-256 compression of a 32-byte message.
pub const SHA256_AND_GATES: usize = 22_573;

/// The most preimages one run may generate.
pub const MAX_BATCH: usize = 16;

/// A gate reading earlier wires. Wires are numbered with every party's inputs
/// first, in party order, then one wire per gate.
#[derive(Clone, Copy, Debug)]
pub enum Gate {
    Xor(usize, usize),
    And(usize, usize),
    Not(usize),
}

#[derive(Clone, Debug)]
pub struct Circuit {
    pub parties: usize,
    pub inputs_per_party: usize,
    pub gates: Vec<Gate>,
    pub outputs: Vec<usize>,
}

/// Gates grouped into layers by AND depth. Layer `d` holds the AND gates
/// that need depth `d - 1` results, then the linear gates computable after
/// them.
pub struct Schedule {
    pub linear: Vec<Vec<usize>>,
    pub nonlinear: Vec<Vec<usize>>,
    pub and_count: usize,
}

impl Circuit {
    pub fn input_count(&self) -> usize {
        self.parties * self.inputs_per_party
    }

    pub fn wire_count(&self) -> usize {
        self.input_count() + self.gates.len()
    }

    /// Check that every gate only reads earlier wires and every output exists.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (3..=MAX_PARTIES).contains(&self.parties),
            "Unsupported party count"
        );

        for (i, gate) in self.gates.iter().enumerate() {
            let (a, b) = match *gate {
                Gate::Xor(a, b) | Gate::And(a, b) => (a, b),
                Gate::Not(a) => (a, a),
            };

            ensure!(
                a < self.input_count() + i && b < self.input_count() + i,
                "Gate {i} reads an undefined wire"
            );
        }

        ensure!(
            self.outputs.iter().all(|&w| w < self.wire_count()),
            "Undefined output wire"
        );

        Ok(())
    }

    /// A hash identifying the circuit, so parties can agree they run the same
    /// one.
    pub fn id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();

        hash.update(b"fedimint/mpc/circuit/v1");
        hash.update((self.parties as u64).to_le_bytes());
        hash.update((self.inputs_per_party as u64).to_le_bytes());

        for gate in &self.gates {
            let (tag, a, b) = match *gate {
                Gate::Xor(a, b) => (0u8, a, b),
                Gate::And(a, b) => (1, a, b),
                Gate::Not(a) => (2, a, a),
            };

            hash.update([tag]);
            hash.update((a as u64).to_le_bytes());
            hash.update((b as u64).to_le_bytes());
        }

        for &output in &self.outputs {
            hash.update((output as u64).to_le_bytes());
        }

        hash.finalize().into()
    }

    pub fn schedule(&self) -> Schedule {
        let input_count = self.input_count();
        let mut depths = vec![0; self.wire_count()];
        let mut linear = vec![vec![]];
        let mut nonlinear = vec![vec![]];
        let mut and_count = 0;

        for (i, gate) in self.gates.iter().enumerate() {
            let (a, b, interactive) = match *gate {
                Gate::Xor(a, b) => (a, b, false),
                Gate::And(a, b) => (a, b, true),
                Gate::Not(a) => (a, a, false),
            };

            let depth = depths[a].max(depths[b]) + usize::from(interactive);

            depths[input_count + i] = depth;

            while linear.len() <= depth {
                linear.push(vec![]);
                nonlinear.push(vec![]);
            }

            if interactive {
                nonlinear[depth].push(i);
                and_count += 1;
            } else {
                linear[depth].push(i);
            }
        }

        Schedule {
            linear,
            nonlinear,
            and_count,
        }
    }

    /// Evaluate in the clear, for tests.
    pub fn evaluate(&self, inputs: &[Vec<bool>]) -> Vec<bool> {
        let mut wires: Vec<bool> = inputs.iter().flatten().copied().collect();

        for gate in &self.gates {
            wires.push(match *gate {
                Gate::Xor(a, b) => wires[a] ^ wires[b],
                Gate::And(a, b) => wires[a] & wires[b],
                Gate::Not(a) => !wires[a],
            });
        }

        self.outputs.iter().map(|&i| wires[i]).collect()
    }

    fn add(&mut self, gate: Gate) -> usize {
        let wire = self.wire_count();

        self.gates.push(gate);

        wire
    }
}

/// Big-endian bits of `bytes`.
pub fn bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&b| (0..8).rev().map(move |i| (b >> i) & 1 != 0))
        .collect()
}

/// Bytes from big-endian bits.
pub fn bytes(bits: &[bool]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| c.iter().fold(0, |acc, &b| (acc << 1) | u8::from(b)))
        .collect()
}

/// One SHA-256 compression as a Bristol-format circuit.
struct Compression {
    wires: usize,
    gates: Vec<(Vec<usize>, usize, String)>,
}

impl Compression {
    fn parse() -> Result<Self> {
        let mut lines = include_str!("../circuits/sha256.txt").lines();

        let header: Vec<usize> = lines
            .next()
            .context("Missing circuit header")?
            .split_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<_, _>>()?;

        ensure!(
            header.len() == 2 && header[1] >= 768,
            "Invalid circuit header"
        );

        lines.next();
        lines.next();

        let mut gates = vec![];

        for line in lines.filter(|l| !l.trim().is_empty()) {
            let row: Vec<_> = line.split_whitespace().collect();
            let fan_in: usize = row[0].parse()?;

            ensure!(row.len() == fan_in + 4 && row[1] == "1", "Invalid gate row");

            let inputs = row[2..2 + fan_in]
                .iter()
                .map(|v| v.parse())
                .collect::<std::result::Result<Vec<_>, _>>()?;

            gates.push((inputs, row[2 + fan_in].parse()?, row[3 + fan_in].to_owned()));
        }

        ensure!(gates.len() == header[0], "Gate count mismatch");

        Ok(Self {
            wires: header[1],
            gates,
        })
    }

    /// Append SHA-256 of the 256 `message` wires, returning the digest wires
    /// in the circuit's bit order (least significant first).
    fn append(
        &self,
        circuit: &mut Circuit,
        message: &[usize],
        zero: usize,
        one: usize,
    ) -> Result<Vec<usize>> {
        ensure!(message.len() == 256, "SHA-256 input must be 32 bytes");

        let constant = |bit: bool| if bit { one } else { zero };

        // A 32-byte message fills one block: 0x80, zeros, then the length
        // (256 bits) in the last two bytes.
        let mut padding = [0u8; 32];

        padding[0] = 0x80;
        padding[30] = 1;

        let mut block = message.to_vec();

        block.extend(bits(&padding).into_iter().map(constant));
        block.reverse();

        let iv = [
            0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f,
            0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab,
            0x5b, 0xe0, 0xcd, 0x19,
        ];

        let mut iv_bits = bits(&iv);

        iv_bits.reverse();
        block.extend(iv_bits.into_iter().map(constant));

        let mut wires = vec![usize::MAX; self.wires];

        wires[..768].copy_from_slice(&block);

        for (inputs, output, op) in &self.gates {
            ensure!(
                *output < wires.len()
                    && inputs
                        .iter()
                        .all(|&i| i < wires.len() && wires[i] != usize::MAX),
                "Undefined wire in the compression circuit"
            );

            let gate = match (op.as_str(), inputs.as_slice()) {
                ("AND", &[a, b]) => Gate::And(wires[a], wires[b]),
                ("XOR", &[a, b]) => Gate::Xor(wires[a], wires[b]),
                ("INV", &[a]) => Gate::Not(wires[a]),
                _ => bail!("Unsupported compression gate {op}"),
            };

            wires[*output] = circuit.add(gate);
        }

        Ok(wires[self.wires - 256..].to_vec())
    }
}

/// Input slots of 256 bits each party supplies per preimage: its contribution
/// to `r`, to each of the `threshold - 1` higher share coefficients, and the
/// mask its own share is opened under.
pub fn slots(threshold: usize) -> usize {
    threshold + 1
}

/// Multiplication triples a direct-share run consumes: the AND gates plus one
/// bit check per input.
pub fn direct_triples(parties: usize, batch: usize, threshold: usize) -> usize {
    batch * SHA256_AND_GATES + parties * batch * slots(threshold) * 256
}

/// The generator: for each of `batch` preimages, `r` is the XOR of every
/// party's contribution. The circuit outputs `SHA256(r)`, then, for each party
/// in order, that party's Shamir share of `r` (threshold `threshold`,
/// evaluation point `party + 1`) XORed with a mask only that party supplied.
///
/// Opening the outputs therefore reveals the hash to everyone and each share
/// only to its owner.
pub fn direct(parties: usize, batch: usize, threshold: usize) -> Result<Circuit> {
    ensure!(
        (3..=MAX_PARTIES).contains(&parties),
        "Unsupported party count"
    );
    ensure!((1..=MAX_BATCH).contains(&batch), "Unsupported batch size");
    ensure!(
        threshold >= 2 && threshold <= parties,
        "Unsupported share threshold"
    );
    ensure!(
        direct_triples(parties, batch, threshold) <= MAX_TRIPLES,
        "The run would need too many triples"
    );

    let slots = slots(threshold);

    let mut circuit = Circuit {
        parties,
        inputs_per_party: batch * slots * 256,
        gates: vec![],
        outputs: vec![],
    };

    let input = |party: usize, item: usize, slot: usize, bit: usize| {
        party * batch * slots * 256 + (item * slots + slot) * 256 + bit
    };

    let zero = circuit.add(Gate::Xor(0, 0));
    let one = circuit.add(Gate::Not(zero));
    let compression = Compression::parse()?;

    for item in 0..batch {
        // Coefficient 0 is r; the rest randomise the shares.
        let mut coefficients = vec![];

        for slot in 0..threshold {
            let mut word = vec![];

            for bit in 0..256 {
                let mut wire = input(0, item, slot, bit);

                for party in 1..parties {
                    wire = circuit.add(Gate::Xor(wire, input(party, item, slot, bit)));
                }

                word.push(wire);
            }

            coefficients.push(word);
        }

        let digest = compression.append(&mut circuit, &coefficients[0], zero, one)?;

        circuit.outputs.extend(digest);

        for recipient in 0..parties {
            let mut share = vec![zero; 256];
            let mut factor = F(1);

            for coefficient in &coefficients {
                // Each 256-bit coefficient is four GF(2^64) words, most
                // significant bit first. Multiplying by a public element is
                // linear over GF(2), so it needs only XOR gates.
                for word in 0..4 {
                    for input_bit in 0..64 {
                        let product = F(1u64 << (63 - input_bit)) * factor;

                        for output_bit in 0..64 {
                            if (product.0 >> (63 - output_bit)) & 1 != 0 {
                                let out = word * 64 + output_bit;

                                share[out] = circuit
                                    .add(Gate::Xor(share[out], coefficient[word * 64 + input_bit]));
                            }
                        }
                    }
                }

                factor *= point(recipient + 1);
            }

            for (bit, &wire) in share.iter().enumerate() {
                let masked = circuit.add(Gate::Xor(wire, input(recipient, item, slots - 1, bit)));

                circuit.outputs.push(masked);
            }
        }
    }

    Ok(circuit)
}
