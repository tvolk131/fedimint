//! Experimental, explicit Bitcoin contract outputs controlled by Simplicity.
//! Execution version zero is a prototype, not a production consensus format.

#[cfg(feature = "compiler")]
pub mod compiler;
pub mod config;
pub mod jet;
pub mod runtime;

#[cfg(test)]
mod tests;

use std::fmt;

use bitcoin::hashes::{Hash, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::transaction::Transaction;
use fedimint_core::{Amount, OutPoint, plugin_types_trait_impl_common};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const KIND: ModuleKind = ModuleKind::from_static_str("simplicity");
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);
pub const EXECUTION_VERSION: u32 = 0;
pub const MAX_CONTRACTS: usize = 32;
pub const MAX_PROGRAM_BYTES: usize = 8_192;
pub const MAX_WITNESS_BYTES: usize = 8_192;
pub const MAX_RECOVERY_BYTES: usize = 1_024;

/// All amounts are Bitcoin millisatoshis in this first prototype.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ContractOutput {
    pub version: u32,
    pub amount: Amount,
    pub cmr: [u8; 32],
    pub state: [u8; 32],
    /// Opaque client data. Removing the live output does not erase history.
    pub recovery: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ContractInput {
    pub outpoint: OutPoint,
    /// The program authorizes this key to sign the enclosing transaction.
    pub claim_key: PublicKey,
    pub program: Vec<u8>,
    pub witness: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ContractOutcome;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct BlockCountVote(pub u64);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum ContractError {
    #[error("authenticated transaction context is required")]
    MissingContext,
    #[error("unsupported execution version")]
    Version,
    #[error("contract does not exist or was already spent")]
    UnknownContract,
    #[error("contract outpoint already exists")]
    DuplicateOutput,
    #[error("invalid transaction context")]
    Context,
    #[error("contract or program exceeds a resource limit")]
    Limit,
    #[error("invalid Simplicity program or witness")]
    Program,
    #[error("program commitment does not match the consumed contract")]
    Commitment,
    #[error("Simplicity program rejected the transition")]
    Rejected,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
#[error(transparent)]
pub struct ContractOutputError(#[from] pub ContractError);

pub struct SimplicityModuleTypes;
plugin_types_trait_impl_common!(
    KIND,
    SimplicityModuleTypes,
    config::SimplicityClientConfig,
    ContractInput,
    ContractOutput,
    ContractOutcome,
    BlockCountVote,
    ContractError,
    ContractOutputError
);

#[derive(Debug)]
pub struct SimplicityCommonInit;

impl CommonModuleInit for SimplicityCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;
    type ClientConfig = config::SimplicityClientConfig;

    fn decoder() -> Decoder {
        SimplicityModuleTypes::decoder_builder().build()
    }
}

macro_rules! display_type {
    ($($ty:ty),* $(,)?) => {$(
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($ty))
            }
        }
    )*};
}
display_type!(
    ContractInput,
    ContractOutput,
    ContractOutcome,
    BlockCountVote,
    config::SimplicityClientConfig
);

/// Signs all spends of this module instance and every enclosing output. Program
/// witnesses and outer signatures are excluded to avoid signature circularity.
/// Foreign funding inputs may be supplied by a sponsor. The claim keys are
/// bound here so a sponsor cannot redirect the approved transaction.
pub fn signature_hash(
    federation_id: FederationId,
    module_id: ModuleInstanceId,
    transaction: &Transaction,
) -> Result<[u8; 32], ContractError> {
    let mut engine = sha256::Hash::engine();
    let spends = transaction
        .inputs
        .iter()
        .filter(|input| input.module_instance_id() == module_id)
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
    (
        "fedimint/simplicity/intent/v0".to_owned(),
        federation_id,
        module_id,
        EXECUTION_VERSION,
        spends,
        transaction.nonce,
    )
        .consensus_encode(&mut engine)
        .expect("hash engines accept all bytes");
    transaction
        .outputs
        .consensus_encode(&mut engine)
        .expect("hash engines accept all bytes");
    Ok(sha256::Hash::from_engine(engine).to_byte_array())
}

pub fn output_fee(output: &ContractOutput) -> Amount {
    Amount::from_msats(100 + output.recovery.len() as u64)
}
