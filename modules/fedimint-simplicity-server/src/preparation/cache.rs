//! Decoded programs shared across validation attempts. Decoding depends only
//! on an input's program and witness bytes, so a submission's programs also
//! serve its revalidations and the consensus pass that applies it. As with
//! retention, a miss changes only performance, never validity.
use std::sync::{Arc, LazyLock, Mutex, PoisonError};

use fedimint_core::bitcoin::hashes::{Hash, HashEngine, sha256};
use fedimint_simplicity_common::{ContractError, ContractInput, runtime};
use lru::LruCache;
use simplicity::RedeemNode;

use super::{RETENTION_BUDGET, retention};
use crate::metrics;

/// Measured with the conservative retention charge, not an RSS bound.
const CAPACITY: usize = 32 * 1024 * 1024;

static PROGRAMS: LazyLock<Mutex<Programs>> = LazyLock::new(|| Mutex::new(Programs::new(CAPACITY)));

/// A decoded program and its retention charge, or `None` for a program over
/// [`RETENTION_BUDGET`].
pub(super) type Decoded = (Arc<RedeemNode>, Option<usize>);

/// Decode `input`, reusing an earlier successful decoding of the same bytes.
/// Failures are not cached.
pub(super) fn decode(input: &ContractInput) -> Result<Decoded, ContractError> {
    let key = key(input);
    let cached = lock().get(&key);
    metrics::PROGRAM_CACHE
        .with_label_values(&[if cached.is_some() { "hit" } else { "miss" }])
        .inc();
    if let Some(decoded) = cached {
        return Ok(decoded);
    }
    let program = runtime::decode_program(input)?;
    let charge = retention::charge(&program, RETENTION_BUDGET);
    // Drop evicted programs after the lock is released.
    let evicted = lock().insert(key, program.clone(), charge);
    drop(evicted);
    Ok((program, charge))
}

fn lock() -> std::sync::MutexGuard<'static, Programs> {
    // Every update leaves the cache consistent, so a panic elsewhere while
    // holding the lock cannot corrupt it.
    PROGRAMS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The length prefix keeps program and witness boundaries unambiguous.
fn key(input: &ContractInput) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    engine.input(&(input.program.len() as u64).to_le_bytes());
    engine.input(&input.program);
    engine.input(&input.witness);
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Least recently used programs are evicted once their total charge would
/// exceed the capacity.
struct Programs {
    entries: LruCache<[u8; 32], (Arc<RedeemNode>, usize)>,
    used: usize,
    capacity: usize,
}

impl Programs {
    fn new(capacity: usize) -> Self {
        Self {
            entries: LruCache::unbounded(),
            used: 0,
            capacity,
        }
    }

    fn get(&mut self, key: &[u8; 32]) -> Option<Decoded> {
        self.entries
            .get(key)
            .map(|(program, charge)| (program.clone(), Some(*charge)))
    }

    /// Returns the evicted programs so the caller can drop them outside the
    /// lock. Programs over the retention budget are not cached.
    fn insert(
        &mut self,
        key: [u8; 32],
        program: Arc<RedeemNode>,
        charge: Option<usize>,
    ) -> Vec<Arc<RedeemNode>> {
        let Some(charge) = charge.filter(|charge| *charge <= self.capacity) else {
            return Vec::new();
        };
        // Another thread may have decoded the same program meanwhile.
        if self.entries.contains(&key) {
            return Vec::new();
        }
        let mut evicted = Vec::new();
        while self.used + charge > self.capacity {
            let Some((_, (program, charge))) = self.entries.pop_lru() else {
                break;
            };
            self.used -= charge;
            evicted.push(program);
        }
        self.used += charge;
        self.entries.put(key, (program, charge));
        evicted
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::OutPoint;
    use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey};
    use fedimint_simplicity_client::ContractProgram;
    use fedimint_simplicity_client::compiler::{Value, arguments, witnesses};

    use super::*;

    fn input(ok: bool) -> ContractInput {
        let owner = Keypair::from_secret_key(
            SECP256K1,
            &SecretKey::from_slice(&[1; 32]).expect("valid secret key"),
        );
        ContractProgram::compile("fn main() { assert!(witness::OK); }", arguments([]))
            .expect("program compiles")
            .input(
                OutPoint {
                    txid: fedimint_core::TransactionId::all_zeros(),
                    out_idx: 0,
                },
                owner.public_key(),
                witnesses([("OK", Value::from(ok))]),
            )
            .expect("input builds")
    }

    #[test]
    fn repeated_inputs_reuse_one_decoding() {
        let input = input(true);
        let (first, charge) = decode(&input).expect("program decodes");
        let (second, cached) = decode(&input).expect("program decodes");
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(cached, charge);
        assert!(charge.is_some());
    }

    #[test]
    fn keys_cover_program_and_witness() {
        let ok = input(true);
        let mut moved = ok.clone();
        // Same concatenated bytes, different program/witness split.
        moved
            .witness
            .insert(0, moved.program.pop().expect("program bytes"));
        assert_ne!(key(&ok), key(&input(false)));
        assert_ne!(key(&ok), key(&moved));
    }

    #[test]
    fn failures_are_not_cached() {
        let mut malformed = input(true);
        malformed.program.truncate(1);
        assert_eq!(decode(&malformed).err(), Some(ContractError::Program));
        assert!(lock().get(&key(&malformed)).is_none());
    }

    #[test]
    fn least_recently_used_programs_are_evicted_by_charge() {
        let program = runtime::decode_program(&input(true)).expect("program decodes");
        let mut programs = Programs::new(10);
        assert!(
            programs
                .insert([1; 32], program.clone(), Some(4))
                .is_empty()
        );
        assert!(
            programs
                .insert([2; 32], program.clone(), Some(4))
                .is_empty()
        );
        assert!(programs.get(&[1; 32]).is_some());
        assert_eq!(programs.insert([3; 32], program.clone(), Some(4)).len(), 1);
        assert!(programs.get(&[2; 32]).is_none());
        assert!(programs.get(&[1; 32]).is_some());
        assert!(programs.get(&[3; 32]).is_some());
        assert_eq!(programs.used, 8);
        // Too large for the cache, or over the retention budget.
        assert!(
            programs
                .insert([4; 32], program.clone(), Some(11))
                .is_empty()
        );
        assert!(programs.insert([5; 32], program, None).is_empty());
        assert!(programs.get(&[4; 32]).is_none());
        assert!(programs.get(&[5; 32]).is_none());
        assert_eq!(programs.used, 8);
    }
}
