//! Explicit assets for execution version one. Creation always starts at zero
//! supply. An authority is an indivisible capability, not a fungible balance.
use bitcoin::hashes::Hash;
use fedimint_core::config::FederationId;
use fedimint_core::core::{DynOutput, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::transaction::Transaction;
use fedimint_core::{Amount, OutPoint};
use serde::{Deserialize, Serialize};

use crate::{ContractError, ContractInput, ContractOutput, MAX_CONTRACTS};

pub mod accounting;

pub const ASSET_VERSION: u32 = 1;
pub const MAX_ASSETS: usize = 32;
pub const CREATION_FEE_MSAT: u64 = 100;

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct AssetId(pub [u8; 32]);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct AssetAmount {
    pub asset: AssetId,
    pub quantity: u64,
}

#[derive(
    Debug, Clone, Default, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable,
)]
pub struct AssetBundle {
    /// Strictly increasing IDs and nonzero quantities.
    pub balances: Vec<AssetAmount>,
    /// Strictly increasing IDs; each authority has exactly one holder.
    pub authorities: Vec<AssetId>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct AssetCreation {
    pub key: PublicKey,
    /// Outer output indices holding each ordinal's original authority.
    pub authority_outputs: Vec<u32>,
    /// Signs the version-one intent, which excludes creation signatures.
    pub signature: Signature,
}

#[derive(
    Debug, Clone, Default, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable,
)]
pub struct AssetActions {
    pub creations: Vec<AssetCreation>,
    /// Sorted unique IDs. Issuance requires the asset's consumed authority.
    pub issuance: Vec<AssetAmount>,
    /// Sorted unique IDs. Destruction grants no automatic bitcoin entitlement.
    pub burns: Vec<AssetAmount>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum AssetExtension {
    Bundle(AssetBundle),
    /// At most one action output per transaction. It creates no spendable UTXO.
    Actions(AssetActions),
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct AssetRecord {
    pub creation_key: PublicKey,
    pub ordinal: u32,
    pub authority_outpoint: OutPoint,
    pub authority_cmr: [u8; 32],
    pub authority_state: [u8; 32],
}

pub fn namespace(federation: FederationId, module: ModuleInstanceId, key: PublicKey) -> [u8; 32] {
    (
        "fedimint/simplicity/namespace/v1".to_owned(),
        federation,
        module,
        key,
    )
        .consensus_hash_sha256()
        .to_byte_array()
}

pub fn asset_id(
    federation: FederationId,
    module: ModuleInstanceId,
    key: PublicKey,
    ordinal: u32,
) -> AssetId {
    AssetId(
        (
            "fedimint/simplicity/asset/v1".to_owned(),
            namespace(federation, module, key),
            ordinal,
        )
            .consensus_hash_sha256()
            .to_byte_array(),
    )
}

pub fn validate_amounts(amounts: &[AssetAmount]) -> Result<(), ContractError> {
    if amounts.len() > MAX_ASSETS
        || amounts.iter().any(|value| value.quantity == 0)
        || !amounts.windows(2).all(|pair| pair[0].asset < pair[1].asset)
    {
        return Err(ContractError::Assets);
    }
    Ok(())
}

impl ContractOutput {
    pub fn bundle(&self) -> Option<&AssetBundle> {
        match &self.extension {
            Some(AssetExtension::Bundle(bundle)) => Some(bundle),
            _ => None,
        }
    }

    pub fn actions(&self) -> Option<&AssetActions> {
        match &self.extension {
            Some(AssetExtension::Actions(actions)) => Some(actions),
            _ => None,
        }
    }

    pub fn action_output(actions: AssetActions) -> Self {
        Self {
            version: ASSET_VERSION,
            amount: Amount::ZERO,
            cmr: [0; 32],
            state: [0; 32],
            recovery: vec![],
            extension: Some(AssetExtension::Actions(actions)),
        }
    }
}

/// The v0 digest is unchanged. V1 removes only creation signatures, avoiding
/// self-reference, and commits all operations, claim keys, and outer outputs.
pub fn signature_hash_v1(
    federation: FederationId,
    module: ModuleInstanceId,
    tx: &Transaction,
) -> Result<[u8; 32], ContractError> {
    let spends = tx
        .inputs
        .iter()
        .filter(|input| input.module_instance_id() == module)
        .map(|input| {
            input
                .as_any()
                .downcast_ref::<ContractInput>()
                .map(|input| (input.outpoint, input.claim_key))
                .ok_or(ContractError::Context)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if spends.len() > MAX_CONTRACTS {
        return Err(ContractError::Limit);
    }
    let outputs = tx
        .outputs
        .iter()
        .map(|output| {
            let Some(contract) = output.as_any().downcast_ref::<ContractOutput>() else {
                return if output.module_instance_id() == module {
                    Err(ContractError::Context)
                } else {
                    Ok(output.clone())
                };
            };
            // Normalize only authorization material, in every Simplicity
            // instance, so simultaneous creation batches do not sign each
            // other's signatures. Other foreign output types stay opaque.
            let mut contract = contract.clone();
            if contract.version == ASSET_VERSION
                && let Some(AssetExtension::Actions(actions)) = &mut contract.extension
            {
                for creation in &mut actions.creations {
                    creation.signature =
                        Signature::from_slice(&[0; 64]).expect("fixed signature width");
                }
            }
            Ok(DynOutput::from_typed(output.module_instance_id(), contract))
        })
        .collect::<Result<Vec<_>, ContractError>>()?;
    Ok((
        "fedimint/simplicity/intent/v1".to_owned(),
        federation,
        module,
        spends,
        tx.nonce,
        outputs,
    )
        .consensus_hash_sha256()
        .to_byte_array())
}
