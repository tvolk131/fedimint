//! Experimental, explicit Bitcoin contract outputs controlled by Simplicity.
//! Execution version one is the fresh-federation beta baseline.

pub mod assets;
#[cfg(feature = "compiler")]
pub mod compiler;
pub mod config;
pub mod consensus;
pub mod jet;
pub mod limits;
pub mod resources;
pub mod runtime;

pub use assets::signature_hash;

#[cfg(test)]
mod tests;

use std::fmt;

use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{Amount, OutPoint, plugin_types_trait_impl_common};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const KIND: ModuleKind = ModuleKind::from_static_str("simplicity");
/// Immutable configuration baseline for the extensible consensus-item format.
/// Future activations must keep accepting configurations with this version.
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 1);
pub const EXECUTION_VERSION: u32 = 1;

/// One Simplicity output. Contracts are spendable; an action output only
/// changes asset state and creates nothing to spend.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum SimplicityOutput {
    Contract(ContractOutput),
    /// At most one per transaction and instance.
    Actions(ActionOutput),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

/// A spendable contract. Bitcoin amounts are millisatoshis; assets are
/// explicit.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ContractOutput {
    pub version: u32,
    pub amount: Amount,
    pub cmr: [u8; 32],
    pub state: [u8; 32],
    /// Opaque client data. Removing the live output does not erase history.
    pub recovery: Vec<u8>,
    pub assets: assets::AssetBundle,
}

/// Asset creations, issuance and burns for this instance's transaction.
#[derive(
    Debug, Clone, Default, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable,
)]
pub struct ActionOutput {
    pub actions: assets::AssetActions,
    /// Opaque client data, such as a sender receipt.
    pub recovery: Vec<u8>,
}

impl SimplicityOutput {
    pub fn contract(&self) -> Option<&ContractOutput> {
        match self {
            Self::Contract(contract) => Some(contract),
            _ => None,
        }
    }

    pub fn actions(&self) -> Option<&ActionOutput> {
        match self {
            Self::Actions(actions) => Some(actions),
            _ => None,
        }
    }

    pub fn recovery(&self) -> &[u8] {
        match self {
            Self::Contract(contract) => &contract.recovery,
            Self::Actions(actions) => &actions.recovery,
            Self::Default { .. } => &[],
        }
    }
}

impl From<ContractOutput> for SimplicityOutput {
    fn from(contract: ContractOutput) -> Self {
        Self::Contract(contract)
    }
}

impl From<ActionOutput> for SimplicityOutput {
    fn from(actions: ActionOutput) -> Self {
        Self::Actions(actions)
    }
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
    SimplicityOutput,
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
    SimplicityOutput,
    ContractOutcome,
    SimplicityConsensusItem,
    config::SimplicityClientConfig
);

pub fn output_fee(output: &SimplicityOutput) -> Amount {
    let (body, creation) = match output {
        SimplicityOutput::Contract(contract) => {
            (contract.assets.consensus_encode_to_vec().len(), 0)
        }
        SimplicityOutput::Actions(output) => (
            output.actions.consensus_encode_to_vec().len(),
            output
                .actions
                .creations
                .iter()
                .map(|creation| creation.authority_outputs.len() as u64)
                .sum::<u64>()
                * limits::CREATION_FEE_MSAT,
        ),
        SimplicityOutput::Default { .. } => (0, 0),
    };
    Amount::from_msats(
        limits::BASE_ITEM_FEE_MSAT + output.recovery().len() as u64 + body as u64 + creation,
    )
}
