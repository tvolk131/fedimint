//! Measure requested allocations, not RSS or whether decoding eventually fails.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey};
use fedimint_core::{OutPoint, TransactionId};
use fedimint_simplicity_common::{ContractError, ContractInput, runtime};
use simplicity::{BitWriter, encode};

struct Meter;

thread_local! {
    static LARGEST: Cell<Option<usize>> = const { Cell::new(None) };
}

fn record(size: usize) {
    let _ = LARGEST.try_with(|largest| {
        if let Some(old) = largest.get() {
            largest.set(Some(old.max(size)));
        }
    });
}

// SAFETY: allocation and deallocation are delegated unchanged to System; the
// meter only observes sizes in a non-allocating, thread-local Cell.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Meter = Meter;

fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    LARGEST.with(|largest| largest.set(Some(0)));
    let result = f();
    let largest = LARGEST.with(|largest| largest.replace(None).unwrap());
    (result, largest)
}

fn input(program: Vec<u8>) -> ContractInput {
    ContractInput {
        outpoint: OutPoint {
            txid: TransactionId::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
            out_idx: 0,
        },
        claim_key: Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[1; 32]).unwrap())
            .public_key(),
        program,
        witness: vec![],
    }
}

#[test]
fn truncated_words_are_rejected_before_allocating_the_declared_value() {
    // Verify that this meter observes a real allocation in the same thread.
    let (_, largest) = measure(|| black_box(vec![0u8; black_box(1_000_000)]));
    assert!(largest >= 1_000_000);
    for prefix in [false, true] {
        for exponent in 5..=32 {
            let mut bytes = Vec::new();
            let mut bits = BitWriter::new(&mut bytes);
            encode::encode_natural(if prefix { 2 } else { 1 }, &mut bits).unwrap();
            if prefix {
                bits.write_bits_be(0b01001, 5).unwrap(); // unit
            }
            bits.write_bits_be(0b10, 2).unwrap(); // constant word
            encode::encode_natural(exponent, &mut bits).unwrap();
            bits.flush_all().unwrap();
            let input = input(bytes);
            let (result, largest) = measure(|| runtime::decode_program(&input));
            assert_eq!(result.unwrap_err(), ContractError::Program);
            assert_eq!(largest, 0, "exponent {exponent}, prefix {prefix}");
        }
    }
}

#[test]
fn impossible_node_counts_are_rejected_before_reserving_nodes() {
    for count in [1_000, 10_000, 1_000_000, usize::MAX] {
        let mut bytes = Vec::new();
        let mut bits = BitWriter::new(&mut bytes);
        encode::encode_natural(count, &mut bits).unwrap();
        bits.flush_all().unwrap();
        let input = input(bytes);
        let (result, largest) = measure(|| runtime::decode_program(&input));
        assert_eq!(result.unwrap_err(), ContractError::Program);
        assert_eq!(largest, 0, "node count {count}");
    }
}

#[test]
fn compact_sum_witness_cannot_allocate_its_unselected_giant_branch() {
    use std::sync::Arc;

    use fedimint_simplicity_common::jet::FedimintJet;
    use simplicity::ConstructNode;
    use simplicity::node::{CoreConstructible, WitnessConstructible};

    for levels in [0, 8, 12, 20] {
        let program = simplicity::types::Context::with_context(|ctx| {
            // A -> 1, where A is a product of 512-bit words. Sharing keeps the
            // encoded program tiny even when A describes tens of MiB.
            let mut consume: Arc<ConstructNode> = Arc::comp(
                &Arc::jet(&ctx, &FedimintJet::Core(simplicity::jet::Core::Eq256)),
                &Arc::unit(&ctx),
            )
            .unwrap();
            for _ in 0..levels {
                consume = Arc::comp(
                    &Arc::pair(&Arc::take(&consume), &Arc::drop_(&consume)).unwrap(),
                    &Arc::unit(&ctx),
                )
                .unwrap();
            }
            let branches = Arc::case(&Arc::unit(&ctx), &Arc::take(&consume)).unwrap();
            let argument = Arc::pair(&Arc::witness(&ctx, None), &Arc::unit(&ctx)).unwrap();
            Arc::comp(&argument, &branches)
                .unwrap()
                .finalize_types()
                .unwrap()
                .to_vec_without_witness()
        });
        assert!(program.len() < 256);
        let mut input = input(program);
        input.witness = vec![0]; // Left unit, with no right-branch payload.
        let (result, largest) = measure(|| runtime::decode_program(&input));
        if levels <= 8 {
            result.unwrap(); // Positive controls: the encoding itself is valid.
        } else {
            assert_eq!(result.unwrap_err(), ContractError::Limit);
            assert!(
                largest < 128 * 1024,
                "expanded witness allocation: {largest}"
            );
        }
    }
}

#[test]
fn aggregate_byte_limit_rejects_before_allocating_decoded_constants() {
    use std::sync::Arc;

    use fedimint_core::core::DynInput;
    use fedimint_core::transaction::{Transaction, TransactionSignature};
    use fedimint_simplicity_common::resources;
    use simplicity::ConstructNode;
    use simplicity::node::CoreConstructible;

    let program = simplicity::types::Context::with_context(|ctx| {
        let word = simplicity::Value::from_byte_array([0x55; 4096])
            .to_word()
            .unwrap();
        let node: Arc<ConstructNode> = Arc::const_word(&ctx, word);
        Arc::comp(&node, &Arc::unit(&ctx))
            .unwrap()
            .finalize_types()
            .unwrap()
            .to_vec_without_witness()
    });
    let input = input(program);
    let (decoded, allocation) = measure(|| runtime::decode_program(&input));
    decoded.unwrap();
    assert!(
        allocation >= 4096,
        "control must exercise a large decoder allocation"
    );
    assert!(4 * input.program.len() > resources::MAX_TRANSACTION_REDEMPTION_BYTES);
    let tx = Transaction {
        inputs: (0..4)
            .map(|index| DynInput::from_typed(4 + index % 2, input.clone()))
            .collect(),
        outputs: vec![],
        nonce: [0; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    };
    let (result, allocation) = measure(|| resources::check_transaction(&tx));
    assert_eq!(result, Err(ContractError::Limit));
    assert!(
        allocation < 4096,
        "oversized transaction reached the decoder: {allocation}"
    );

    // A fitting transaction with the same large constant must reject cheap
    // faults before making the decoder allocation observed by the control.
    let mut tx = tx;
    tx.inputs.truncate(1);
    tx.signatures = TransactionSignature::NaiveMultisig(vec![
        fedimint_core::secp256k1::schnorr::Signature::from_slice(&[0; 64]).unwrap(),
    ]);
    let mut duplicate = tx.clone();
    duplicate.inputs.push(duplicate.inputs[0].clone());
    let mut bad_output = tx.clone();
    bad_output
        .outputs
        .push(fedimint_core::core::DynOutput::from_typed(
            4,
            fedimint_simplicity_common::ContractOutput {
                version: 2,
                amount: fedimint_core::Amount::ZERO,
                cmr: [0; 32],
                state: [0; 32],
                recovery: vec![],
                extension: None,
            },
        ));
    for (tx, expected) in [
        (duplicate, ContractError::UnknownContract),
        (bad_output, ContractError::Version),
    ] {
        let (result, allocation) = measure(|| resources::check_transaction(&tx));
        assert_eq!(result, Err(expected));
        assert!(
            allocation < 4096,
            "structural fault reached decoder: {allocation}"
        );
    }
    tx.signatures = TransactionSignature::NaiveMultisig(vec![]);
    let (result, allocation) = measure(|| resources::check_signed_transaction(&tx, 4));
    assert_eq!(
        result,
        Err(fedimint_core::transaction::TransactionError::InvalidWitnessLength)
    );
    assert!(
        allocation < 4096,
        "signature envelope fault reached decoder: {allocation}"
    );
}
