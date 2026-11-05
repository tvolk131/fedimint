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
