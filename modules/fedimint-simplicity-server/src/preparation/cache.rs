//! Decoded programs shared across validation attempts. Decoding depends only
//! on an input's program and witness bytes, so a submission's programs also
//! serve its revalidations and the consensus pass that applies it. As with
//! retention, a miss changes only performance, never validity.
//!
//! A program enters the cache only after it has passed the cost and commitment
//! checks against a stored contract, so programs that match no contract cannot
//! displace ones that do. The commitment does not cover the witness, though:
//! anyone who owns a contract can submit spends of it with ever-new witnesses
//! that fail execution, and so churn the cache. At worst every lookup misses
//! and validation decodes as it would without a cache, within the same bound.
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
pub(super) struct Decoded {
    pub(super) program: Arc<RedeemNode>,
    pub(super) charge: Option<usize>,
    /// The cache key of a fresh decoding, which is not cached yet.
    fresh: Option<[u8; 32]>,
}

/// Decode `input`, reusing an earlier decoding of the same bytes. Failures are
/// not cached, and a fresh decoding is cached only by [`Decoded::keep`].
pub(super) fn decode(input: &ContractInput) -> Result<Decoded, ContractError> {
    let key = key(input);
    let cached = lock().get(&key);
    metrics::PROGRAM_CACHE
        .with_label_values(&[if cached.is_some() { "hit" } else { "miss" }])
        .inc();
    if let Some((program, charge)) = cached {
        return Ok(Decoded {
            program,
            charge: Some(charge),
            fresh: None,
        });
    }
    let program = runtime::decode_program(input)?;
    let charge = retention::charge(&program, RETENTION_BUDGET);
    Ok(Decoded {
        program,
        charge,
        fresh: Some(key),
    })
}

impl Decoded {
    /// Cache a program that has passed the checks tying it to a stored
    /// contract. If another thread cached the same program first, return that
    /// copy instead, so both attempts share it.
    pub(super) fn keep(self) -> (Arc<RedeemNode>, Option<usize>) {
        let Some(key) = self.fresh else {
            return (self.program, self.charge);
        };
        let (program, dropped) = lock().insert(key, self.program, self.charge);
        // Free evicted and duplicate programs after the lock is released.
        drop(dropped);
        (program, self.charge)
    }
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

#[cfg(test)]
pub(super) fn contains(input: &ContractInput) -> bool {
    lock().entries.contains(&key(input))
}

/// Remove `input`'s program, so the next decoding of it is fresh.
#[cfg(test)]
pub(super) fn forget(input: &ContractInput) {
    let removed = lock().remove(&key(input));
    drop(removed);
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

    fn get(&mut self, key: &[u8; 32]) -> Option<(Arc<RedeemNode>, usize)> {
        self.entries
            .get(key)
            .map(|(program, charge)| (program.clone(), *charge))
    }

    /// Returns the cached copy of `program`, or `program` itself if it is too
    /// large to cache, along with the programs the caller must drop after
    /// releasing the lock. Programs over the retention budget are not cached.
    fn insert(
        &mut self,
        key: [u8; 32],
        program: Arc<RedeemNode>,
        charge: Option<usize>,
    ) -> (Arc<RedeemNode>, Vec<Arc<RedeemNode>>) {
        let Some(charge) = charge.filter(|charge| *charge <= self.capacity) else {
            return (program, Vec::new());
        };
        // Another thread may have decoded the same program meanwhile.
        if let Some((cached, _)) = self.entries.get(&key) {
            return (cached.clone(), vec![program]);
        }
        let mut dropped = Vec::new();
        while self.used + charge > self.capacity {
            let Some((_, (program, charge))) = self.entries.pop_lru() else {
                break;
            };
            self.used -= charge;
            dropped.push(program);
        }
        self.used += charge;
        self.entries.put(key, (program.clone(), charge));
        (program, dropped)
    }

    #[cfg(test)]
    fn remove(&mut self, key: &[u8; 32]) -> Option<Arc<RedeemNode>> {
        let (program, charge) = self.entries.pop(key)?;
        self.used -= charge;
        Some(program)
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::OutPoint;
    use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey};
    use fedimint_simplicity_client::ContractProgram;
    use fedimint_simplicity_client::compiler::{Value, arguments, witnesses};
    use fedimint_simplicity_common::compiler::ValueConstructible as _;

    use super::*;

    /// Bytes no other test decodes, so assertions about this entry hold while
    /// other tests use the shared cache.
    fn input(tag: u64) -> ContractInput {
        let owner = Keypair::from_secret_key(
            SECP256K1,
            &SecretKey::from_slice(&[1; 32]).expect("valid secret key"),
        );
        ContractProgram::compile(
            &format!("fn main() {{ assert!(jet::eq_64(witness::TAG, {tag})); }}"),
            arguments([]),
        )
        .expect("program compiles")
        .input(
            OutPoint {
                txid: fedimint_core::TransactionId::all_zeros(),
                out_idx: 0,
            },
            owner.public_key(),
            witnesses([("TAG", Value::u64(tag))]),
        )
        .expect("input builds")
    }

    #[test]
    fn programs_are_cached_only_when_kept_and_then_shared() {
        let input = input(0xcac4_e000_0001);
        let fresh = decode(&input).expect("program decodes");
        assert!(fresh.fresh.is_some());
        assert!(!contains(&input));
        let (kept, charge) = fresh.keep();
        assert!(charge.is_some());
        let cached = decode(&input).expect("program decodes");
        assert!(cached.fresh.is_none());
        assert_eq!(cached.charge, charge);
        assert!(Arc::ptr_eq(&kept, &cached.program));
        assert!(Arc::ptr_eq(&kept, &cached.keep().0));
    }

    #[test]
    fn concurrent_decodings_share_the_first_cached_copy() {
        let input = input(0xcac4_e000_0002);
        let first = decode(&input).expect("program decodes");
        let second = decode(&input).expect("program decodes");
        assert!(!Arc::ptr_eq(&first.program, &second.program));
        let (first, _) = first.keep();
        let (second, _) = second.keep();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn keys_cover_program_and_witness() {
        let tagged = input(0xcac4_e000_0003);
        let mut moved = tagged.clone();
        // Same concatenated bytes, different program/witness split.
        moved
            .witness
            .insert(0, moved.program.pop().expect("program bytes"));
        let mut witness = tagged.clone();
        witness.witness = input(0xcac4_e000_0004).witness;
        assert_ne!(key(&tagged), key(&witness));
        assert_ne!(key(&tagged), key(&moved));
    }

    #[test]
    fn failures_are_not_cached() {
        let mut malformed = input(0xcac4_e000_0005);
        malformed.program.truncate(1);
        assert_eq!(decode(&malformed).err(), Some(ContractError::Program));
        assert!(!contains(&malformed));
    }

    #[test]
    fn least_recently_used_programs_are_evicted_by_charge() {
        let program = runtime::decode_program(&input(0xcac4_e000_0006)).expect("program decodes");
        let mut programs = Programs::new(10);
        assert!(
            programs
                .insert([1; 32], program.clone(), Some(4))
                .1
                .is_empty()
        );
        assert!(
            programs
                .insert([2; 32], program.clone(), Some(4))
                .1
                .is_empty()
        );
        assert!(programs.get(&[1; 32]).is_some());
        assert_eq!(
            programs.insert([3; 32], program.clone(), Some(4)).1.len(),
            1
        );
        assert!(programs.get(&[2; 32]).is_none());
        assert!(programs.get(&[1; 32]).is_some());
        assert!(programs.get(&[3; 32]).is_some());
        assert_eq!(programs.used, 8);
        // Too large for the cache, or over the retention budget.
        assert!(
            programs
                .insert([4; 32], program.clone(), Some(11))
                .1
                .is_empty()
        );
        assert!(programs.insert([5; 32], program.clone(), None).1.is_empty());
        assert!(programs.get(&[4; 32]).is_none());
        assert!(programs.get(&[5; 32]).is_none());
        assert_eq!(programs.used, 8);
        assert!(programs.remove(&[1; 32]).is_some());
        assert_eq!(programs.used, 4);
    }
}
