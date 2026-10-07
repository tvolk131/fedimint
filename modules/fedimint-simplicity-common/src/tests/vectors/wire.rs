use fedimint_core::config::FederationId;
use fedimint_core::core::{DynInput, DynOutput};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::transaction::{Transaction, TransactionSignature};

use super::*;
use crate::assets::{asset_id, namespace, signature_hash_v1};

pub(super) fn transaction() -> (FederationId, Transaction) {
    let federation = FederationId(bitcoin::hashes::sha256::Hash::from_byte_array([0x99; 32]));
    let mut foreign = input();
    foreign.outpoint.out_idx = 0;
    let tx = Transaction {
        inputs: vec![
            DynInput::from_typed(4, input()),
            DynInput::from_typed(7, foreign),
        ],
        outputs: vec![
            DynOutput::from_typed(4, legacy()),
            DynOutput::from_typed(4, asset()),
            DynOutput::from_typed(7, ContractOutput::action_output(actions())),
        ],
        nonce: [0x88; 8],
        signatures: TransactionSignature::NaiveMultisig(vec![]),
    };
    (federation, tx)
}

#[test]
fn encodings_and_domains_match_independent_reference() {
    let fixture = fixtures();
    let wire = &fixture["wire"];
    for (name, output) in [
        ("legacy_output", legacy()),
        ("asset_output", asset()),
        ("actions_output", ContractOutput::action_output(actions())),
    ] {
        let expected = bytes(wire[name].as_str().unwrap());
        assert_eq!(output.consensus_encode_to_vec(), expected, "{name}");
        assert_eq!(
            ContractOutput::consensus_decode_whole(&expected, &ModuleDecoderRegistry::default())
                .unwrap(),
            output
        );
    }
    let (federation, mut tx) = transaction();
    assert_eq!(
        tx.outputs.consensus_encode_to_vec(),
        bytes(wire["outputs"].as_str().unwrap())
    );
    for (name, hash) in [
        ("namespace", namespace(federation, 4, key())),
        ("asset_id_0", asset_id(federation, 4, key(), 0).0),
        ("asset_id_253", asset_id(federation, 4, key(), 253).0),
        (
            "outpoint_hash",
            input().outpoint.consensus_hash_sha256().to_byte_array(),
        ),
        (
            "sighash_v0",
            crate::signature_hash(federation, 4, &tx).unwrap(),
        ),
        ("sighash_v1", signature_hash_v1(federation, 4, &tx).unwrap()),
    ] {
        assert_eq!(
            hash.as_slice(),
            bytes(wire[name].as_str().unwrap()),
            "{name}"
        );
    }
    let v0 = crate::signature_hash(federation, 4, &tx).unwrap();
    let v1 = signature_hash_v1(federation, 4, &tx).unwrap();
    let mut changed_actions = actions();
    changed_actions.creations[0].signature = schnorr::Signature::from_slice(&[0x77; 64]).unwrap();
    tx.outputs[2] = DynOutput::from_typed(7, ContractOutput::action_output(changed_actions));
    assert_ne!(crate::signature_hash(federation, 4, &tx).unwrap(), v0);
    assert_eq!(signature_hash_v1(federation, 4, &tx).unwrap(), v1);
    // Foreign funding inputs are outside the inner intent; claim references in
    // this module are not. This also pins the two versions' signing boundary.
    tx.inputs.pop();
    assert_eq!(signature_hash_v1(federation, 4, &tx).unwrap(), v1);
    let mut changed = input();
    changed.outpoint.out_idx += 1;
    tx.inputs[0] = DynInput::from_typed(4, changed);
    assert_ne!(signature_hash_v1(federation, 4, &tx).unwrap(), v1);
}
