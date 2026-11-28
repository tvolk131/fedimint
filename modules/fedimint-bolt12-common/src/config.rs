use std::collections::BTreeMap;

pub use bitcoin::Network;
use fedimint_core::config::ExcessiveRelativeFeeError;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, PeerId, plugin_types_trait_impl_config};
use serde::{Deserialize, Serialize};
use tpe::{AggregatePublicKey, PublicKeyShare, SecretKeyShare};

use crate::Bolt12CommonInit;
use crate::protocol::{Bolt12Config, Bolt12OutputV0, output_amount_and_fee};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bolt12ModuleConfig {
    pub private: Bolt12ConfigPrivate,
    pub consensus: Bolt12ConfigConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct Bolt12ConfigConsensus {
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub fee_consensus: FeeConsensus,
    pub network: Network,
    pub bolt12: Bolt12Config,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bolt12ConfigPrivate {
    pub sk: SecretKeyShare,
    pub bolt12: Bolt12PrivateConfig,
}

/// This guardian's share of the invoice signing key and its private channel
/// identity.
#[derive(Clone, Serialize, Deserialize)]
pub struct Bolt12PrivateConfig {
    /// Serialized FROST key package.
    pub key_package: Vec<u8>,
    pub transport_secret: bitcoin::secp256k1::SecretKey,
}

impl std::fmt::Debug for Bolt12PrivateConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bolt12PrivateConfig")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Bolt12ClientConfig {
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub fee_consensus: FeeConsensus,
    pub network: Network,
    pub bolt12: Bolt12Config,
}

impl Bolt12ClientConfig {
    /// The fee the federation charges for `output`. `declared` is the amount
    /// the client attaches to it, which only a funded BOLT12 receive needs
    /// because its amount is fixed by the reservation, not the output.
    pub fn output_fee(&self, output: &Bolt12OutputV0, declared: Amount) -> Option<Amount> {
        output_amount_and_fee(&self.fee_consensus, &self.bolt12, output, declared)
            .map(|(_, fee)| fee)
    }
}

impl std::fmt::Display for Bolt12ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Bolt12ClientConfig {self:?}")
    }
}

plugin_types_trait_impl_config!(
    Bolt12CommonInit,
    Bolt12ModuleConfig,
    Bolt12ConfigPrivate,
    Bolt12ConfigConsensus,
    Bolt12ClientConfig
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConsensus {
    pub base: Amount,
    pub parts_per_million: u64,
}

impl FeeConsensus {
    pub fn new(parts_per_million: u64) -> Result<Self, ExcessiveRelativeFeeError> {
        const MAX_PARTS_PER_MILLION: u64 = 1_000;

        if parts_per_million > MAX_PARTS_PER_MILLION {
            return Err(ExcessiveRelativeFeeError {
                parts_per_million,
                max: MAX_PARTS_PER_MILLION,
            });
        }

        Ok(Self {
            base: Amount::from_sats(1),
            parts_per_million,
        })
    }

    pub fn zero() -> Self {
        Self {
            base: Amount::ZERO,
            parts_per_million: 0,
        }
    }

    pub fn fee(&self, amount: Amount) -> Amount {
        Amount::from_msats(self.fee_msats(amount.msats))
    }

    fn fee_msats(&self, msats: u64) -> u64 {
        msats
            .saturating_mul(self.parts_per_million)
            .saturating_div(1_000_000)
            .checked_add(self.base.msats)
            .expect("The division creates sufficient headroom to add the base fee")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bolt12GenParams {
    pub local: Bolt12GenParamsLocal,
    pub consensus: Bolt12GenParamsConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bolt12GenParamsLocal {
    pub bitcoin_rpc: fedimint_core::envs::BitcoinRpcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bolt12GenParamsConsensus {
    pub fee_consensus: Option<FeeConsensus>,
    pub network: Network,
}

impl Default for Bolt12GenParams {
    fn default() -> Self {
        Self {
            local: Bolt12GenParamsLocal {
                bitcoin_rpc: fedimint_core::envs::BitcoinRpcConfig::get_defaults_from_env_vars()
                    .expect("Valid bitcoin rpc config"),
            },
            consensus: Bolt12GenParamsConsensus {
                fee_consensus: None,
                network: Network::Regtest,
            },
        }
    }
}

impl Bolt12GenParams {
    pub fn regtest(bitcoin_rpc: fedimint_core::envs::BitcoinRpcConfig) -> Self {
        Self {
            local: Bolt12GenParamsLocal { bitcoin_rpc },
            consensus: Bolt12GenParamsConsensus {
                fee_consensus: None,
                network: Network::Regtest,
            },
        }
    }
}
