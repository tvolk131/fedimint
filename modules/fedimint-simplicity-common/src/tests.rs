use std::sync::Arc;

use fedimint_core::secp256k1::{Keypair, SECP256K1, SecretKey};
use fedimint_core::{OutPoint, TransactionId};
use simplicity::jet::{Core, Jet};
use simplicity::node::CoreConstructible;
use simplicity::{BitIter, ConstructNode};

use crate::jet::{ContextJet, FedimintJet};
use crate::{ContractError, ContractInput, runtime};

#[test]
fn small_encoding_cannot_request_unbounded_intermediate_values() {
    let program = simplicity::types::Context::with_context(|ctx| {
        let mut wide: Arc<ConstructNode> = Arc::jet(&ctx, &FedimintJet::Core(Core::Sha256Iv));
        // The shared DAG is tiny but its inferred intermediate value is 2^40 bits.
        for _ in 0..32 {
            wide = Arc::pair(&wide, &wide).unwrap();
        }
        Arc::comp(&wide, &Arc::unit(&ctx))
            .unwrap()
            .finalize_types()
            .unwrap()
            .to_vec_without_witness()
    });
    assert!(program.len() < 200);
    let input = ContractInput {
        outpoint: OutPoint {
            txid: TransactionId::from_raw_hash(bitcoin::hashes::Hash::all_zeros()),
            out_idx: 0,
        },
        claim_key: Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[1; 32]).unwrap())
            .public_key(),
        program,
        witness: vec![],
    };
    assert_eq!(
        runtime::decode_program(&input).unwrap_err(),
        ContractError::Limit
    );
}

#[test]
fn unknown_context_and_disallowed_core_jets_are_rejected() {
    // Family bit 1, then unassigned opcode 16.
    assert!(FedimintJet::decode(&mut BitIter::from([0x88, 0x00].into_iter())).is_err());
    assert!(FedimintJet::parse("multiply_64").is_err());
    assert_eq!(
        FedimintJet::decode(&mut BitIter::from([0x80, 0x00].into_iter())).unwrap(),
        FedimintJet::Context(ContextJet::SigHashAll)
    );
}
