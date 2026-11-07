use bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::Amount;
use fedimint_core::secp256k1::{Keypair, SecretKey};

use super::*;
use crate::EXECUTION_VERSION;
use crate::assets::{AssetBundle, AssetExtension};

const MODULE: ModuleInstanceId = 4;
const INTENT: [u8; 32] = [9; 32];

fn federation() -> FederationId {
    FederationId(sha256::Hash::hash(b"accounting"))
}

fn keypair(seed: u8) -> Keypair {
    Keypair::from_secret_key(SECP256K1, &SecretKey::from_slice(&[seed; 32]).unwrap())
}

fn id(ordinal: u32) -> AssetId {
    asset_id(federation(), MODULE, keypair(1).public_key(), ordinal)
}

fn authority_output(authorities: Vec<AssetId>) -> ContractOutput {
    ContractOutput {
        version: EXECUTION_VERSION,
        amount: Amount::ZERO,
        cmr: [1; 32],
        state: [2; 32],
        recovery: vec![],
        extension: Some(AssetExtension::Bundle(AssetBundle {
            balances: vec![],
            authorities,
        })),
    }
}

fn creation(intent: [u8; 32], authority_outputs: Vec<u32>) -> AssetCreation {
    AssetCreation {
        key: keypair(1).public_key(),
        authority_outputs,
        signature: SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest(intent), &keypair(1)),
    }
}

fn check<'a>(
    creation: &AssetCreation,
    intent: [u8; 32],
    outputs: &'a [ContractOutput],
) -> Result<Vec<CreatedAuthority<'a>>, ContractError> {
    check_creation(federation(), MODULE, creation, intent, |index| {
        outputs.get(index as usize)
    })
}

#[test]
fn creation_derives_ids_by_ordinal_and_returns_each_authority_output() {
    let outputs = [authority_output(vec![id(1)]), authority_output(vec![id(0)])];
    let authorities = check(&creation(INTENT, vec![1, 0]), INTENT, &outputs).unwrap();
    assert_eq!(
        authorities
            .iter()
            .map(|authority| (authority.id, authority.ordinal, authority.output_index))
            .collect::<Vec<_>>(),
        [(id(0), 0, 1), (id(1), 1, 0)]
    );
    assert!(std::ptr::eq(authorities[0].output, &outputs[1]));
    assert!(std::ptr::eq(authorities[1].output, &outputs[0]));
}

#[test]
fn creation_signature_is_checked_before_authority_outputs_are_resolved() {
    // No output resolves, so any authority check would fail with `Assets`.
    let creation = creation(INTENT, vec![0]);
    assert_eq!(
        check_creation(federation(), MODULE, &creation, [8; 32], |_| None).unwrap_err(),
        ContractError::CreationSignature
    );
    let mut other_key = creation.clone();
    other_key.key = keypair(2).public_key();
    assert_eq!(
        check_creation(federation(), MODULE, &other_key, INTENT, |_| None).unwrap_err(),
        ContractError::CreationSignature
    );
    assert_eq!(
        check_creation(federation(), MODULE, &creation, INTENT, |_| None).unwrap_err(),
        ContractError::Assets
    );
}

#[test]
fn authority_must_be_a_resolved_bundle_carrying_the_derived_id() {
    let creation = creation(INTENT, vec![0, 1]);
    let valid = [authority_output(vec![id(0)]), authority_output(vec![id(1)])];
    assert!(check(&creation, INTENT, &valid).is_ok());
    let mut action = authority_output(vec![]);
    action.extension = Some(AssetExtension::Actions(AssetActions::default()));
    let mut bare = authority_output(vec![]);
    bare.extension = None;
    for invalid in [
        // Unresolved index, such as a foreign module's output.
        vec![authority_output(vec![id(0)])],
        vec![authority_output(vec![id(0)]), authority_output(vec![])],
        // The ID derives from the ordinal, not from the output position.
        vec![authority_output(vec![id(1)]), authority_output(vec![id(0)])],
        vec![authority_output(vec![id(0)]), action],
        vec![authority_output(vec![id(0)]), bare],
    ] {
        assert_eq!(
            check(&creation, INTENT, &invalid).unwrap_err(),
            ContractError::Assets
        );
    }
}

#[test]
fn balance_check_applies_genesis_or_existing_rules_by_origin() {
    let none = AssetActions::default();
    // A lone original authority is valid genesis, but not a valid transfer.
    let authority = authority_output(vec![id(0)]);
    let minted = balances([], [&authority], &none).unwrap();
    assert_eq!(minted[&id(0)].check(true), Ok(()));
    assert_eq!(minted[&id(0)].check(false), Err(ContractError::Assets));
    // Moving a consumed authority is a valid transfer, but not a valid genesis.
    let moved = balances([&authority], [&authority], &none).unwrap();
    assert_eq!(moved[&id(0)].check(false), Ok(()));
    assert_eq!(moved[&id(0)].check(true), Err(ContractError::Assets));
}
