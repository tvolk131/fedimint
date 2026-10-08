//! Reusable execution context for local pruning. Clocks are observations, not
//! reservations: consensus can advance before a spend is included.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context as _, ensure};
use bitcoin::hashes::Hash as _;
use fedimint_api_client::api::FederationApiExt as _;
use fedimint_core::OutPoint;
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::encoding::Encodable as _;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::transaction::Transaction;
use futures::{StreamExt as _, TryStreamExt as _, stream};

use crate::SimplicityClientModule;
use crate::common::runtime::{Environment, EnvironmentInput, EnvironmentOutput};
use crate::common::{self, ContractInput, ContractOutput, StoredContract};

/// Applications may reuse a snapshot across many local quotes. Supplying
/// already authenticated metadata avoids contract-specific network queries.
#[derive(Debug, Clone, Default)]
pub struct PruningSnapshot {
    pub session_index: u64,
    pub block_count: u64,
    pub contracts: BTreeMap<OutPoint, StoredContract>,
}

impl PruningSnapshot {
    /// `index` counts this module instance's inputs, not outer transaction
    /// inputs.
    pub fn environment(
        &self,
        federation: FederationId,
        module: ModuleInstanceId,
        tx: &Transaction,
        index: usize,
    ) -> anyhow::Result<Environment> {
        let mut inputs = Vec::new();
        for input in tx
            .inputs
            .iter()
            .filter(|input| input.module_instance_id() == module)
        {
            let input = input
                .as_any()
                .downcast_ref::<ContractInput>()
                .context("invalid Simplicity input")?;
            let stored = self
                .contracts
                .get(&input.outpoint)
                .context("missing pruning input context")?;
            inputs.push(EnvironmentInput {
                outpoint: input.outpoint,
                contract: stored.output.clone(),
            });
        }
        let current = inputs.get(index).context("invalid pruning input index")?;
        let stored = &self.contracts[&current.outpoint];
        let mut actions = None;
        let mut outputs = Vec::new();
        for output in &tx.outputs {
            let contract = if output.module_instance_id() == module {
                let contract = output
                    .as_any()
                    .downcast_ref::<ContractOutput>()
                    .context("invalid Simplicity output")?;
                if let Some(value) = contract.actions() {
                    ensure!(actions.is_none(), "multiple action outputs");
                    actions = Some(value.clone());
                }
                Some(contract.clone())
            } else {
                None
            };
            outputs.push(EnvironmentOutput {
                module_id: output.module_instance_id(),
                hash: output.consensus_hash_sha256().to_byte_array(),
                contract,
            });
        }
        Ok(Environment {
            signature_hash: match stored.output.version {
                common::EXECUTION_VERSION => common::signature_hash(federation, module, tx)?,
                common::assets::ASSET_VERSION => {
                    common::assets::signature_hash_v1(federation, module, tx)?
                }
                _ => anyhow::bail!("unsupported execution version"),
            },
            session_index: self.session_index,
            block_count: self.block_count,
            current: stored.output.clone(),
            creation_session: stored.creation_session,
            creation_block_count: stored.creation_block_count,
            input_index: u32::try_from(index)?,
            input_count: u32::try_from(inputs.len())?,
            inputs: inputs.into(),
            outputs: outputs.into(),
            actions: Arc::new(actions.unwrap_or_default()),
        })
    }
}

/// A plan must be rebuilt before another snapshot attempt can succeed.
/// Transport/quorum failures remain ordinary API errors and may be retried.
#[derive(Debug, thiserror::Error)]
pub enum InvalidPruningPlan {
    #[error("too many pruning inputs")]
    TooManyInputs,
    #[error("pruning input {0} is no longer unspent")]
    Unavailable(OutPoint),
}

impl SimplicityClientModule {
    /// Fetch existing point-query metadata and consensus clock observations.
    /// Queries disclose the requested outpoints to guardians. Reuse the result
    /// for local route quotes, or construct it from authenticated metadata.
    /// No network I/O should be performed inside a wallet write transaction.
    pub async fn pruning_snapshot(
        &self,
        points: impl IntoIterator<Item = OutPoint>,
    ) -> anyhow::Result<PruningSnapshot> {
        let points: BTreeSet<_> = points.into_iter().collect();
        ensure!(
            points.len() <= common::MAX_CONTRACTS,
            InvalidPruningPlan::TooManyInputs
        );
        if points.is_empty() {
            return Ok(PruningSnapshot::default());
        }
        let api = self.context.module_api();
        let contracts = stream::iter(points)
            .map(|point| {
                let api = api.clone();
                async move {
                    let stored: Option<StoredContract> = api
                        .request_current_consensus(
                            "contract".to_owned(),
                            ApiRequestErased::new(point),
                        )
                        .await?;
                    Ok::<_, anyhow::Error>((
                        point,
                        stored.ok_or(InvalidPruningPlan::Unavailable(point))?,
                    ))
                }
            })
            .buffered(4)
            .try_collect()
            .await?;
        Ok(PruningSnapshot {
            contracts,
            session_index: self.context.global_api().session_count().await?,
            block_count: self.consensus_block_count().await?,
        })
    }
}
