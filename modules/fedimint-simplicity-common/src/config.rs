use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, plugin_types_trait_impl_config};
use serde::{Deserialize, Serialize};

use crate::SimplicityCommonInit;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplicityConfig {
    pub private: SimplicityConfigPrivate,
    pub consensus: SimplicityConfigConsensus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimplicityConfigPrivate;

#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct SimplicityConfigConsensus {
    pub peers: Vec<PeerId>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct SimplicityClientConfig;

plugin_types_trait_impl_config!(
    SimplicityCommonInit,
    SimplicityConfig,
    SimplicityConfigPrivate,
    SimplicityConfigConsensus,
    SimplicityClientConfig
);
