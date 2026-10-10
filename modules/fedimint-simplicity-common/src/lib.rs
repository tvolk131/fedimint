//! Experimental, explicit Bitcoin contract outputs controlled by Simplicity.
//! Execution version zero is a prototype, not a production consensus format.

pub mod assets;
#[cfg(feature = "compiler")]
pub mod compiler;
pub mod config;
pub mod consensus;
pub mod jet;
pub mod resources;
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
/// Immutable configuration baseline for the extensible consensus-item format.
/// Future activations must keep accepting configurations with this version.
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 1);
pub const EXECUTION_VERSION: u32 = 0;
pub const MAX_CONTRACTS: usize = 32;
pub const MAX_PROGRAM_BYTES: usize = 8_192;
pub const MAX_WITNESS_BYTES: usize = 8_192;
pub const MAX_RECOVERY_BYTES: usize = 1_024;

/// Bitcoin amounts remain millisatoshis; v1 adds explicit asset extensions.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ContractOutput {
    pub version: u32,
    pub amount: Amount,
    pub cmr: [u8; 32],
    pub state: [u8; 32],
    /// Opaque client data. Removing the live output does not erase history.
    pub recovery: Vec<u8>,
    pub extension: Option<assets::AssetExtension>,
}

/// Immutable contract context returned by the existing contract point query.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct StoredContract {
    pub output: ContractOutput,
    pub creation_session: u64,
    pub creation_block_count: u64,
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

/// The version-vote variant and its encoding must remain readable by every
/// future release, including releases that cannot execute the voted rules.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum SimplicityConsensusItem {
    BlockCount(u64),
    ModuleConsensusVersion(ModuleConsensusVersion),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

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
    #[error("invalid asset transition or conservation failure")]
    Assets,
    #[error("asset creation namespace has already been used")]
    NamespaceUsed,
    #[error("invalid asset creation authorization")]
    CreationSignature,
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
    SimplicityConsensusItem,
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
    SimplicityConsensusItem,
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
    let extra = output
        .extension
        .as_ref()
        .map(|extension| extension.consensus_encode_to_vec().len() as u64)
        .unwrap_or(0);
    let creation = output
        .actions()
        .map(|actions| {
            actions
                .creations
                .iter()
                .map(|creation| creation.authority_outputs.len() as u64)
                .sum::<u64>()
                * assets::CREATION_FEE_MSAT
        })
        .unwrap_or(0);
    Amount::from_msats(100 + output.recovery.len() as u64 + extra + creation)
}

// Preserve the exact v0 wire/database encoding. New fields are present only in
// version one, and unknown versions fail decoding rather than being
// reinterpreted.
impl Encodable for ContractOutput {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        (
            self.version,
            self.amount,
            self.cmr,
            self.state,
            &self.recovery,
        )
            .consensus_encode(writer)?;
        if self.version == assets::ASSET_VERSION {
            self.extension.consensus_encode(writer)?;
        }
        Ok(())
    }
}

impl Decodable for ContractOutput {
    fn consensus_decode_partial_from_finite_reader<R: std::io::Read>(
        reader: &mut R,
        modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let (version, amount, cmr, state, recovery) =
            Decodable::consensus_decode_partial_from_finite_reader(reader, modules)?;
        if version != EXECUTION_VERSION && version != assets::ASSET_VERSION {
            return Err(fedimint_core::encoding::DecodeError::from_str(
                "unknown Simplicity output version",
            ));
        }
        let extension = if version == assets::ASSET_VERSION {
            Decodable::consensus_decode_partial_from_finite_reader(reader, modules)?
        } else {
            None
        };
        Ok(Self {
            version,
            amount,
            cmr,
            state,
            recovery,
            extension,
        })
    }
}
