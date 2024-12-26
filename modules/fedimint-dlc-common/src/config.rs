use std::collections::BTreeMap;

pub use bitcoin::Network;
use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::{plugin_types_trait_impl_config, Amount, PeerId};
use group::Curve;
use serde::{Deserialize, Serialize};
use tpe::{AggregatePublicKey, PublicKeyShare, SecretKeyShare};

use crate::DlcCommonInit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlcGenParams {
    pub local: DlcGenParamsLocal,
    pub consensus: DlcGenParamsConsensus,
}

impl DlcGenParams {
    #[allow(clippy::missing_panics_doc)]
    pub fn regtest(bitcoin_rpc: BitcoinRpcConfig) -> Self {
        Self {
            local: DlcGenParamsLocal { bitcoin_rpc },
            consensus: DlcGenParamsConsensus {
                fee_consensus: FeeConsensus::new(1000).expect("Relative fee is within range"),
                network: Network::Regtest,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlcGenParamsConsensus {
    pub fee_consensus: FeeConsensus,
    pub network: Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlcGenParamsLocal {
    pub bitcoin_rpc: BitcoinRpcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlcConfig {
    pub local: DlcConfigLocal,
    pub private: DlcConfigPrivate,
    pub consensus: DlcConfigConsensus,
}

#[derive(Clone, Debug, Serialize, Deserialize, Decodable, Encodable)]
pub struct DlcConfigLocal {
    pub bitcoin_rpc: BitcoinRpcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct DlcConfigConsensus {
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub fee_consensus: FeeConsensus,
    pub network: Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlcConfigPrivate {
    pub sk: SecretKeyShare,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DlcClientConfig {
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub fee_consensus: FeeConsensus,
    pub network: Network,
}

impl std::fmt::Display for DlcClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DlcClientConfig {self:?}")
    }
}

// Wire together the configs for this module
plugin_types_trait_impl_config!(
    DlcCommonInit,
    DlcGenParams,
    DlcGenParamsLocal,
    DlcGenParamsConsensus,
    DlcConfig,
    DlcConfigLocal,
    DlcConfigPrivate,
    DlcConfigConsensus,
    DlcClientConfig
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeConsensus {
    base: Amount,
    parts_per_million: u64,
}

impl FeeConsensus {
    /// The lightning module will charge a non-configurable base fee of one
    /// satoshi per transaction input and output to account for the costs
    /// incurred by the federation for processing the transaction. On top of
    /// that the federation may charge a additional relative fee per input and
    /// output of up to one thousand parts per million which is equal to one
    /// tenth of one percent.
    ///
    /// # Errors
    /// - This constructor returns an error if the relative fee is in excess of
    ///   one thousand parts per million.
    pub fn new(parts_per_million: u64) -> anyhow::Result<Self> {
        anyhow::ensure!(
            parts_per_million <= 1_000,
            "Relative fee over one thousand parts per million is excessive"
        );

        Ok(Self {
            base: Amount::from_sats(1),
            parts_per_million,
        })
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

#[test]
fn test_fee_consensus() {
    let fee_consensus = FeeConsensus::new(1_000).expect("Relative fee is within range");

    assert_eq!(
        fee_consensus.fee(Amount::from_msats(999)),
        Amount::from_sats(1)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_sats(1)),
        Amount::from_msats(1) + Amount::from_sats(1)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_sats(1000)),
        Amount::from_sats(1) + Amount::from_sats(1)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_bitcoins(1)),
        Amount::from_sats(100_000) + Amount::from_sats(1)
    );

    assert_eq!(
        fee_consensus.fee(Amount::from_bitcoins(100_000)),
        Amount::from_bitcoins(100) + Amount::from_sats(1)
    );
}
