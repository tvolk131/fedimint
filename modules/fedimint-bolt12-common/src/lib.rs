#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

//! Federated BOLT12 offline receives: common consensus, config, and gateway
//! types.

pub mod config;
pub mod endpoint_constants;
pub mod gateway_api;
pub mod invoice;
pub mod protocol;

use std::fmt;

use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{OutPoint, extensible_associated_module_type, plugin_types_trait_impl_common};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::Bolt12ClientConfig;

pub const KIND: ModuleKind = ModuleKind::from_static_str("bolt12");

pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

extensible_associated_module_type!(Bolt12Input, Bolt12InputV0, UnknownBolt12InputVariantError);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum Bolt12InputV0 {
    /// Claim or refund a funded federated BOLT12 receive.
    Receive(OutPoint, protocol::Bolt12Unlock),
}

impl fmt::Display for Bolt12InputV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bolt12InputV0")
    }
}

pub use crate::protocol::Bolt12OutputV0;

impl fmt::Display for Bolt12OutputV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bolt12OutputV0")
    }
}

extensible_associated_module_type!(
    Bolt12Output,
    Bolt12OutputV0,
    UnknownBolt12OutputVariantError
);

extensible_associated_module_type!(
    Bolt12OutputOutcome,
    Bolt12OutputOutcomeV0,
    UnknownBolt12OutputOutcomeVariantError
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct Bolt12OutputOutcomeV0;

impl fmt::Display for Bolt12OutputOutcomeV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Bolt12OutputOutcomeV0")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum Bolt12InputError {
    #[error("Unknown input variant: {0}")]
    UnknownVariant(u64),
    #[error("The contract does not exist")]
    UnknownContract,
    #[error("The decryption key is invalid")]
    InvalidDecryptionKey,
    #[error("The input fee overflows")]
    FeeOverflow,
}

impl From<UnknownBolt12InputVariantError> for Bolt12InputError {
    fn from(err: UnknownBolt12InputVariantError) -> Self {
        Self::UnknownVariant(err.variant)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum Bolt12OutputError {
    #[error("Unknown output variant: {0}")]
    UnknownVariant(u64),
    #[error("Invalid federated BOLT12 output: {0}")]
    Bolt12(String),
}

impl From<UnknownBolt12OutputVariantError> for Bolt12OutputError {
    fn from(err: UnknownBolt12OutputVariantError) -> Self {
        Self::UnknownVariant(err.variant)
    }
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub enum Bolt12ConsensusItem {
    /// Guardian consensus clock vote (unix timestamp in seconds).
    UnixTimeVote(u64),
    /// A guardian's vote on whether a gateway may reserve BOLT12 invoices.
    GatewayVote { gateway: PublicKey, approve: bool },
    /// Start generation run `run` because the pool is below its target.
    PoolStart { run: u64 },
    /// A committee member's encrypted shares from a finished run.
    PoolShares {
        run: u64,
        shares: Vec<protocol::PoolShare>,
    },
    /// Give up on run `run`, which has outlived its timeout.
    PoolAbandon { run: u64 },
    /// A committee member reports that its local execution of run `run`
    /// aborted; once `f + 1` members report an abort, consensus abandons the
    /// run immediately without waiting for `POOL_RUN_TIMEOUT`.
    PoolAbort { run: u64 },
    /// A member's commitment to its evidence from abandoned run `run`.
    PoolEvidence { run: u64, digest: sha256::Hash },
    /// A guardian's finding about abandoned run `run`.
    PoolVerdict {
        run: u64,
        verdict: protocol::PoolVerdict,
    },
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

impl fmt::Display for Bolt12ConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bolt12ConsensusItem::UnixTimeVote(t) => write!(f, "BOLT12 Unix Time {t}"),
            Bolt12ConsensusItem::GatewayVote { gateway, approve } => {
                write!(f, "BOLT12 Gateway Vote {gateway} {approve}")
            }
            Bolt12ConsensusItem::PoolStart { run } => write!(f, "BOLT12 Pool Start {run}"),
            Bolt12ConsensusItem::PoolShares { run, shares } => {
                write!(f, "BOLT12 Pool Shares {run} ({})", shares.len())
            }
            Bolt12ConsensusItem::PoolAbandon { run } => write!(f, "BOLT12 Pool Abandon {run}"),
            Bolt12ConsensusItem::PoolAbort { run } => write!(f, "BOLT12 Pool Abort {run}"),
            Bolt12ConsensusItem::PoolEvidence { run, .. } => {
                write!(f, "BOLT12 Pool Evidence {run}")
            }
            Bolt12ConsensusItem::PoolVerdict { run, .. } => {
                write!(f, "BOLT12 Pool Verdict {run}")
            }
            Bolt12ConsensusItem::Default { variant, bytes } => write!(
                f,
                "BOLT12 Unknown - variant: {variant}, bytes_len: {}",
                bytes.len()
            ),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum Bolt12ConsensusItemError {
    #[error("Unknown consensus item variant: {0}")]
    UnknownVariant(u64),
    #[error("Invalid BOLT12 consensus item: {0}")]
    Invalid(String),
}

#[derive(Debug)]
pub struct Bolt12CommonInit;

impl CommonModuleInit for Bolt12CommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = Bolt12ClientConfig;

    fn decoder() -> Decoder {
        Bolt12ModuleTypes::decoder_builder().build()
    }
}

pub struct Bolt12ModuleTypes;

plugin_types_trait_impl_common!(
    KIND,
    Bolt12ModuleTypes,
    Bolt12ClientConfig,
    Bolt12Input,
    Bolt12Output,
    Bolt12OutputOutcome,
    Bolt12ConsensusItem,
    Bolt12InputError,
    Bolt12OutputError
);
