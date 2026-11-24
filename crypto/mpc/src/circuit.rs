//! Boolean circuits and the preimage generator circuit.

use anyhow::{Result, ensure};
use sha2::{Digest as _, Sha256};

use crate::{MAX_PARTIES, MAX_TRIPLES, sha256};

/// AND gates in one low-depth SHA-256 circuit for a 32-byte message.
pub const SHA256_AND_GATES: usize = 46_220;

/// The most preimages one run may generate.
pub const MAX_BATCH: usize = 512;

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
    /// Input bits per party per lane.
    pub inputs_per_party: usize,
    /// Number of independent SIMD lanes evaluated in lockstep with this circuit.
    pub lanes: usize,
    pub gates: Vec<Gate>,
    /// Wires opened to everyone (per lane).
    pub outputs: Vec<usize>,
    /// Wires never opened (per lane). Every 256 of them, most significant bit
    /// first, form a secret value that each party receives a Shamir share of.
    pub secret_outputs: Vec<usize>,
}

/// Gates grouped into layers by AND depth, together with a live-wire slot
/// allocation that recycles dead wires so large batches stay in cache.
pub struct Schedule {
    pub linear: Vec<Vec<usize>>,
    pub nonlinear: Vec<Vec<usize>>,
    /// AND gates in one lane.
    pub and_count: usize,
    /// Live slot index assigned to every wire (`0..wire_count()`).
    pub wire_slot: Vec<usize>,
    /// Peak concurrent live wire slots per lane.
    pub slot_count: usize,
}

impl Schedule {
    /// Multiplicative depth (number of interactive AND layers).
    pub fn depth(&self) -> usize {
        self.nonlinear
            .iter()
            .filter(|layer| !layer.is_empty())
            .count()
    }
}

impl Circuit {
    /// Total input wires in one lane across all parties.
    pub fn input_count(&self) -> usize {
        self.parties * self.inputs_per_party
    }

    /// Total input bits per party across all lanes.
    pub fn total_inputs_per_party(&self) -> usize {
        self.inputs_per_party * self.lanes
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
        ensure!(self.lanes >= 1, "Lane count must be positive");

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
            self.outputs
                .iter()
                .chain(&self.secret_outputs)
                .all(|&w| w < self.wire_count())
                && self.secret_outputs.len().is_multiple_of(256),
            "Undefined output wire"
        );

        Ok(())
    }

    /// A hash identifying the circuit, so parties can agree they run the same
    /// one.
    pub fn id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();

        hash.update(b"fedimint/mpc/circuit/v3");
        hash.update((self.parties as u64).to_le_bytes());
        hash.update((self.inputs_per_party as u64).to_le_bytes());
        hash.update((self.lanes as u64).to_le_bytes());
        hash.update((self.gates.len() as u64).to_le_bytes());

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

        hash.update((self.outputs.len() as u64).to_le_bytes());

        for &output in &self.outputs {
            hash.update((output as u64).to_le_bytes());
        }

        hash.update((self.secret_outputs.len() as u64).to_le_bytes());

        for &output in &self.secret_outputs {
            hash.update((output as u64).to_le_bytes());
        }

        hash.finalize().into()
    }

    pub fn schedule(&self) -> Schedule {
        let input_count = self.input_count();
        let wire_count = self.wire_count();
        let mut depths = vec![0; wire_count];
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

        // Compute remaining use counts so dead wire slots can be recycled.
        let mut uses = vec![0u32; wire_count];
        for gate in &self.gates {
            match *gate {
                Gate::Xor(a, b) | Gate::And(a, b) => {
                    uses[a] += 1;
                    uses[b] += 1;
                }
                Gate::Not(a) => {
                    uses[a] += 1;
                }
            }
        }
        // Pin outputs and secret outputs so they remain live until the end.
        for &w in self.outputs.iter().chain(&self.secret_outputs) {
            uses[w] += 1;
        }

        let mut wire_slot = vec![usize::MAX; wire_count];
        let mut free_slots: Vec<usize> = Vec::new();
        let mut slot_count = 0usize;

        let alloc = |free: &mut Vec<usize>, count: &mut usize| -> usize {
            if let Some(s) = free.pop() {
                s
            } else {
                let s = *count;
                *count += 1;
                s
            }
        };

        // Assign slots to input wires first.
        for w in 0..input_count {
            let s = alloc(&mut free_slots, &mut slot_count);
            wire_slot[w] = s;
            if uses[w] == 0 {
                free_slots.push(s);
            }
        }

        for depth in 0..linear.len() {
            // Allocate all outputs of this nonlinear layer before freeing its
            // inputs so parallel reads and writes never alias.
            for &i in &nonlinear[depth] {
                let w = input_count + i;
                wire_slot[w] = alloc(&mut free_slots, &mut slot_count);
            }
            for &i in &nonlinear[depth] {
                let Gate::And(a, b) = self.gates[i] else {
                    unreachable!("Only AND gates are scheduled as nonlinear");
                };
                for src in [a, b] {
                    uses[src] -= 1;
                    if uses[src] == 0 {
                        free_slots.push(wire_slot[src]);
                    }
                }
                let w = input_count + i;
                if uses[w] == 0 {
                    free_slots.push(wire_slot[w]);
                }
            }

            // Linear gates run sequentially; allocate dst before freeing src
            // so dst never aliases src on the same gate.
            for &i in &linear[depth] {
                let w = input_count + i;
                wire_slot[w] = alloc(&mut free_slots, &mut slot_count);
                match self.gates[i] {
                    Gate::Xor(a, b) => {
                        for src in [a, b] {
                            uses[src] -= 1;
                            if uses[src] == 0 {
                                free_slots.push(wire_slot[src]);
                            }
                        }
                    }
                    Gate::Not(a) => {
                        uses[a] -= 1;
                        if uses[a] == 0 {
                            free_slots.push(wire_slot[a]);
                        }
                    }
                    Gate::And(..) => unreachable!("AND gates are nonlinear"),
                }
                if uses[w] == 0 {
                    free_slots.push(wire_slot[w]);
                }
            }
        }

        Schedule {
            linear,
            nonlinear,
            and_count,
            wire_slot,
            slot_count,
        }
    }

    /// Evaluate lane 0 in the clear, for tests.
    pub fn evaluate(&self, inputs: &[Vec<bool>]) -> Vec<bool> {
        let mut wires: Vec<bool> = inputs
            .iter()
            .flat_map(|party_bits| party_bits[..self.inputs_per_party].iter().copied())
            .collect();

        for gate in &self.gates {
            wires.push(match *gate {
                Gate::Xor(a, b) => wires[a] ^ wires[b],
                Gate::And(a, b) => wires[a] & wires[b],
                Gate::Not(a) => !wires[a],
            });
        }

        self.outputs.iter().map(|&i| wires[i]).collect()
    }

    pub(crate) fn add(&mut self, gate: Gate) -> usize {
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

/// Multiplication triples a generator run consumes: the AND gates plus one
/// bit check per input, across all `batch` lanes.
pub fn direct_triples(parties: usize, batch: usize) -> usize {
    batch * SHA256_AND_GATES + parties * batch * 256
}

/// The generator: for each of `batch` preimages (evaluated as SIMD lanes of
/// one single-preimage circuit), `r` is the XOR of every party's 256-bit
/// contribution. The circuit outputs `SHA256(r)` publicly (MSB-first) and
/// keeps `r` as a secret output, which the engine hands out as Shamir shares
/// (see [`crate::engine::run`]).
pub fn direct(parties: usize, batch: usize) -> Result<Circuit> {
    ensure!(
        (3..=MAX_PARTIES).contains(&parties),
        "Unsupported party count"
    );
    ensure!((1..=MAX_BATCH).contains(&batch), "Unsupported batch size");
    ensure!(
        direct_triples(parties, batch) <= MAX_TRIPLES,
        "The run would need too many triples"
    );

    let mut circuit = Circuit {
        parties,
        inputs_per_party: 256,
        lanes: batch,
        gates: vec![],
        outputs: vec![],
        secret_outputs: vec![],
    };

    let input = |party: usize, bit: usize| party * 256 + bit;

    let zero = circuit.add(Gate::Xor(0, 0));
    let one = circuit.add(Gate::Not(zero));

    let mut preimage = Vec::with_capacity(256);
    for bit in 0..256 {
        let mut wire = input(0, bit);

        for party in 1..parties {
            wire = circuit.add(Gate::Xor(wire, input(party, bit)));
        }

        preimage.push(wire);
    }

    let digest = sha256::append_low_depth(&mut circuit, &preimage, zero, one)?;

    circuit.outputs.extend(digest);
    circuit.secret_outputs.extend(preimage);

    Ok(circuit)
}
