//! Capability observations are advisory; guardians enforce ordered activation.
use anyhow::ensure;
use fedimint_api_client::api::FederationApiExt as _;
use fedimint_core::module::{ApiRequestErased, ModuleConsensusVersion};

use crate::SimplicityClientModule;
use crate::common::consensus::{ACTIVE_CONSENSUS_VERSION_ENDPOINT, SUPPORTED_CONSENSUS_VERSION};

impl SimplicityClientModule {
    /// Quorum-authenticated active rules, distinct from individual guardians'
    /// installed capabilities. Activation is monotone, so a stale observation
    /// can delay using new features but cannot enable them prematurely.
    pub async fn active_consensus_version(&self) -> anyhow::Result<ModuleConsensusVersion> {
        let active: ModuleConsensusVersion = self
            .context
            .module_api()
            .request_current_consensus(
                ACTIVE_CONSENSUS_VERSION_ENDPOINT.to_owned(),
                ApiRequestErased::default(),
            )
            .await?;
        ensure!(
            active >= crate::common::MODULE_CONSENSUS_VERSION
                && active <= SUPPORTED_CONSENSUS_VERSION,
            crate::pruning::InvalidPruningPlan::UnsupportedConsensusVersion(active)
        );
        Ok(active)
    }
}
