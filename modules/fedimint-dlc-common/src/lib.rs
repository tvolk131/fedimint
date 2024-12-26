#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

//! # Discreet Log Contract Module
//!
//! This module allows to atomically and trustlessly (in the federated trust
//! model) interact with the Lightning network through a Lightning gateway.

extern crate core;

pub mod config;
pub mod contracts;
pub mod endpoint_constants;
pub mod gateway_api;

use bitcoin::hashes::sha256;
use bitcoin::secp256k1::schnorr::Signature;
use config::DlcClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{extensible_associated_module_type, plugin_types_trait_impl_common};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tpe::{AggregateDecryptionKey, DecryptionKeyShare};

use crate::contracts::{IncomingContract, OutgoingContract};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Bolt11InvoiceDescription {
    Direct(String),
    Hash(sha256::Hash),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
pub enum LightningInvoice {
    Bolt11(Bolt11Invoice),
}

pub const KIND: ModuleKind = ModuleKind::from_static_str("dlc");
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(1, 0);

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct ContractId(pub sha256::Hash);

extensible_associated_module_type!(DlcInput, DlcInputV0, UnknownDlcInputVariantError);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum DlcInputV0 {
    Outgoing(ContractId, OutgoingWitness),
    Incoming(ContractId, AggregateDecryptionKey),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum OutgoingWitness {
    Claim([u8; 32]),
    Refund,
    Cancel(Signature),
}

impl std::fmt::Display for DlcInputV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DlcInputV0",)
    }
}

extensible_associated_module_type!(DlcOutput, DlcOutputV0, UnknownDlcOutputVariantError);

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum DlcOutputV0 {
    Outgoing(OutgoingContract),
    Incoming(IncomingContract),
}

impl std::fmt::Display for DlcOutputV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DlcOutputV0")
    }
}

extensible_associated_module_type!(
    DlcOutputOutcome,
    DlcOutputOutcomeV0,
    UnknownDlcOutputOutcomeVariantError
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum DlcOutputOutcomeV0 {
    Outgoing,
    Incoming(DecryptionKeyShare),
}

impl std::fmt::Display for DlcOutputOutcomeV0 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DlcOutputOutcomeV0")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum DlcInputError {
    #[error("The dlc input version is not supported by this federation")]
    UnknownInputVariant(#[from] UnknownDlcInputVariantError),
    #[error("No contract found for given ContractId")]
    UnknownContract,
    #[error("The preimage is invalid")]
    InvalidPreimage,
    #[error("The contracts locktime has passed")]
    Expired,
    #[error("The contracts locktime has not yet passed")]
    NotExpired,
    #[error("The aggregate decryption key is invalid")]
    InvalidDecryptionKey,
    #[error("The forfeit signature is invalid")]
    InvalidForfeitSignature,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum DlcOutputError {
    #[error("The dlc output version is not supported by this federation")]
    UnknownOutputVariant(#[from] UnknownDlcOutputVariantError),
    #[error("The contract is invalid")]
    InvalidContract,
    #[error("The contract is expired")]
    ContractExpired,
    #[error("A contract with this ContractId already exists")]
    ContractAlreadyExists,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq, Encodable, Decodable, Serialize, Deserialize)]
pub enum DlcConsensusItem {
    BlockCountVote(u64),
    UnixTimeVote(u64),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

impl std::fmt::Display for DlcConsensusItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DlcConsensusItem")
    }
}

#[derive(Debug)]
pub struct DlcCommonInit;

impl CommonModuleInit for DlcCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = DlcClientConfig;

    fn decoder() -> Decoder {
        DlcModuleTypes::decoder()
    }
}

pub struct DlcModuleTypes;

plugin_types_trait_impl_common!(
    KIND,
    DlcModuleTypes,
    DlcClientConfig,
    DlcInput,
    DlcOutput,
    DlcOutputOutcome,
    DlcConsensusItem,
    DlcInputError,
    DlcOutputError
);
