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
        // The shared DAG is tiny but its inferred intermediate value is 2^40
        // bits.
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
    // Family bit 1, then unassigned opcode 255.
    assert!(FedimintJet::decode(&mut BitIter::from([0xff, 0x80].into_iter())).is_err());
    assert!(FedimintJet::parse("divide_64").is_err());
    assert_eq!(
        FedimintJet::decode(&mut BitIter::from([0x80, 0x00].into_iter())).unwrap(),
        FedimintJet::Context(ContextJet::SigHashAll)
    );
}

#[test]
fn legacy_output_encoding_is_preserved_and_asset_outputs_round_trip() {
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    use crate::assets::{ASSET_VERSION, AssetBundle, AssetExtension};
    let legacy = (
        0u32,
        fedimint_core::Amount::from_msats(42),
        [1u8; 32],
        [2u8; 32],
        vec![3u8],
    );
    let bytes = legacy.consensus_encode_to_vec();
    let decoded =
        crate::ContractOutput::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .unwrap();
    assert_eq!(decoded.extension, None);
    assert_eq!(decoded.consensus_encode_to_vec(), bytes);
    let mut asset = decoded;
    asset.version = ASSET_VERSION;
    asset.extension = Some(AssetExtension::Bundle(AssetBundle::default()));
    let round_trip = crate::ContractOutput::consensus_decode_whole(
        &asset.consensus_encode_to_vec(),
        &ModuleDecoderRegistry::default(),
    )
    .unwrap();
    assert_eq!(asset, round_trip);
}
