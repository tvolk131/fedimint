//! Fixed values from tests/vectors/reference.py; no runtime regeneration.
mod execution;
mod jets;
mod mutation;
#[cfg(feature = "compiler")]
mod pruning;
mod transcript;
mod wire;

use bitcoin::hashes::Hash;
use bitcoin::hex::FromHex;
use fedimint_core::secp256k1::{PublicKey, schnorr};
use fedimint_core::{Amount, OutPoint, TransactionId};

use crate::assets::{
    AssetActions, AssetAmount, AssetBundle, AssetCreation, AssetExtension, AssetId,
};
use crate::runtime::{Environment, EnvironmentInput, EnvironmentOutput};
use crate::{ContractInput, ContractOutput};

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("../../tests/vectors/consensus.json")).unwrap()
}

fn bytes(hex: &str) -> Vec<u8> {
    Vec::from_hex(hex).unwrap()
}

fn key() -> PublicKey {
    PublicKey::from_slice(&bytes(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    ))
    .unwrap()
}

fn input() -> ContractInput {
    ContractInput {
        outpoint: OutPoint {
            txid: TransactionId::from_raw_hash(bitcoin::hashes::sha256::Hash::from_byte_array(
                [0x33; 32],
            )),
            out_idx: 253,
        },
        claim_key: key(),
        program: vec![],
        witness: vec![],
    }
}

fn legacy() -> ContractOutput {
    ContractOutput {
        version: 0,
        amount: Amount::from_msats(1000),
        cmr: [0x11; 32],
        state: [0x22; 32],
        recovery: vec![0xde, 0xad],
        extension: None,
    }
}

fn asset() -> ContractOutput {
    let mut output = legacy();
    output.version = 1;
    output.amount = Amount::from_msats(65536);
    output.extension = Some(AssetExtension::Bundle(AssetBundle {
        balances: vec![
            AssetAmount {
                asset: AssetId([0x44; 32]),
                quantity: 253,
            },
            AssetAmount {
                asset: AssetId([0x55; 32]),
                quantity: 65536,
            },
        ],
        authorities: vec![AssetId([0x44; 32]), AssetId([0x55; 32])],
    }));
    output
}

fn actions() -> AssetActions {
    AssetActions {
        creations: vec![AssetCreation {
            key: key(),
            authority_outputs: vec![1],
            signature: schnorr::Signature::from_slice(&[0x66; 64]).unwrap(),
        }],
        issuance: vec![AssetAmount {
            asset: AssetId([0x44; 32]),
            quantity: 10,
        }],
        burns: vec![AssetAmount {
            asset: AssetId([0x55; 32]),
            quantity: 11,
        }],
    }
}

fn environment() -> Environment {
    Environment {
        inputs: vec![
            EnvironmentInput {
                outpoint: input().outpoint,
                contract: asset(),
            },
            EnvironmentInput {
                outpoint: input().outpoint,
                contract: legacy(),
            },
        ]
        .into(),
        actions: actions().into(),
        signature_hash: [0xab; 32],
        session_index: 0x0123456789abcdef,
        block_count: 0x1020304050607080,
        current: asset(),
        creation_session: 0x8877665544332211,
        creation_block_count: 0xffeeddccbbaa0099,
        input_index: 1,
        input_count: 2,
        outputs: vec![
            EnvironmentOutput {
                module_id: 4,
                hash: [0xaa; 32],
                contract: Some(asset()),
            },
            EnvironmentOutput {
                module_id: 0x1234,
                hash: [0xbb; 32],
                contract: None,
            },
            EnvironmentOutput {
                module_id: 4,
                hash: [0xcc; 32],
                contract: Some(legacy()),
            },
            EnvironmentOutput {
                module_id: 4,
                hash: [0xdd; 32],
                contract: Some(ContractOutput::action_output(actions())),
            },
        ]
        .into(),
    }
}
