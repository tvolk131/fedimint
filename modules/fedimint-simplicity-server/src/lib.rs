//! Experimental Simplicity guardian module.

pub mod db;
mod metrics;
mod preparation;
#[cfg(test)]
mod tests;
mod upgrades;
mod validation;

use std::collections::BTreeMap;

use anyhow::ensure;
use async_trait::async_trait;
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiVersion, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, TransactionItemAmounts, public_api_endpoint,
};
use fedimint_core::{InPoint, NumPeersExt, OutPoint, PeerId};
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::{
    ConfigGenModuleArgs, ModuleTransactionContext, ModuleTransactionValidation, ServerModule,
    ServerModuleInit, ServerModuleInitArgs,
};
use fedimint_simplicity_common::assets::{AssetId, AssetRecord};
use fedimint_simplicity_common::config::{
    SimplicityClientConfig, SimplicityConfig, SimplicityConfigConsensus, SimplicityConfigPrivate,
};
use fedimint_simplicity_common::consensus::{
    ACTIVE_CONSENSUS_VERSION_ENDPOINT, SUPPORTED_CONSENSUS_VERSION_ENDPOINT,
};
use fedimint_simplicity_common::{
    ContractError, ContractInput, ContractOutcome, ContractOutput, ContractOutputError,
    MAX_CONTRACTS, MODULE_CONSENSUS_VERSION, SimplicityCommonInit, SimplicityConsensusItem,
    SimplicityModuleTypes, output_fee,
};
use futures::StreamExt;

use crate::db::{
    AssetKey, BlockVoteKey, BlockVotePrefix, ContractKey, ContractPrefix, NamespaceKey,
    StoredContract,
};
use crate::validation::ValidatedTransaction;

#[derive(Debug, Clone)]
pub struct SimplicityInit;

impl ModuleInit for SimplicityInit {
    type Common = SimplicityCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let items = dbtx
            .find_by_prefix(&ContractPrefix)
            .await
            .map(|(key, value)| {
                (
                    format!("{key:?}"),
                    Box::new(value) as Box<dyn erased_serde::Serialize + Send>,
                )
            })
            .collect::<Vec<_>>()
            .await;
        Box::new(items.into_iter())
    }
}

#[async_trait]
impl ServerModuleInit for SimplicityInit {
    type Module = Simplicity;

    fn is_enabled_by_default(&self) -> bool {
        false
    }

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }
    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Simplicity> {
        let cfg = load_config(args.cfg())?;
        let mut module = Simplicity {
            cfg,
            monitor: Some(args.server_bitcoin_rpc_monitor()),
            upgrades: upgrades::Upgrades::new(args.our_peer_id()),
        };
        module
            .ensure_supported(&mut args.db().begin_transaction_nc().await)
            .await?;
        module.upgrades.readiness = Some(upgrades::spawn_readiness(
            args.module_api().clone(),
            args.task_group(),
            args.our_peer_id(),
        ));
        Ok(module)
    }
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        _args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        peers
            .iter()
            .map(|peer| (*peer, config(peers.to_vec()).to_erased()))
            .collect()
    }
    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        _args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        Ok(config(peers.num_peers().peer_ids().collect()).to_erased())
    }
    fn get_client_config(
        &self,
        cfg: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<SimplicityClientConfig> {
        validate_consensus_version(cfg.version)?;
        validate_peers(&SimplicityConfigConsensus::from_erased(cfg)?.peers)?;
        Ok(SimplicityClientConfig)
    }
    fn validate_config(&self, identity: &PeerId, cfg: ServerModuleConfig) -> anyhow::Result<()> {
        let cfg = load_config(&cfg)?;
        ensure!(
            cfg.consensus.peers.contains(identity),
            "guardian missing from configured peers"
        );
        Ok(())
    }
}

/// Check the envelope before decoding its payload: loading a familiar payload
/// must not silently activate rules different from the federation's version.
fn validate_consensus_version(version: ModuleConsensusVersion) -> anyhow::Result<()> {
    ensure!(
        version == MODULE_CONSENSUS_VERSION,
        "unsupported Simplicity module consensus version {version}; this binary supports {MODULE_CONSENSUS_VERSION}"
    );
    Ok(())
}

fn load_config(cfg: &ServerModuleConfig) -> anyhow::Result<SimplicityConfig> {
    validate_consensus_version(cfg.consensus.version)?;
    let cfg: SimplicityConfig = cfg.to_typed()?;
    validate_peers(&cfg.consensus.peers)?;
    Ok(cfg)
}

fn config(peers: Vec<PeerId>) -> SimplicityConfig {
    SimplicityConfig {
        private: SimplicityConfigPrivate,
        consensus: SimplicityConfigConsensus { peers },
    }
}

fn validate_peers(peers: &[PeerId]) -> anyhow::Result<()> {
    ensure!(!peers.is_empty(), "empty guardian set");
    ensure!(
        peers.windows(2).all(|pair| pair[0] < pair[1]),
        "guardian set must be sorted and unique"
    );
    Ok(())
}

#[derive(Debug)]
pub struct Simplicity {
    cfg: SimplicityConfig,
    monitor: Option<ServerBitcoinRpcMonitor>,
    upgrades: upgrades::Upgrades,
}

impl Simplicity {
    /// Construct an instance with manually supplied consensus votes, for tests
    /// and embedded prototypes. Production initialization uses the RPC monitor.
    pub fn new_for_testing(peers: Vec<PeerId>) -> anyhow::Result<Self> {
        validate_peers(&peers)?;
        Ok(Self {
            upgrades: upgrades::Upgrades::new(peers[0]),
            cfg: config(peers),
            monitor: None,
        })
    }

    pub async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let mut votes = dbtx
            .find_by_prefix(&BlockVotePrefix)
            .await
            .map(|(_, vote)| vote)
            .collect::<Vec<_>>()
            .await;
        votes.sort_unstable_by(|a, b| b.cmp(a));
        votes
            .get(self.cfg.consensus.peers.to_num_peers().threshold() - 1)
            .copied()
            .unwrap_or(0)
    }
}

#[async_trait]
impl ServerModule for Simplicity {
    type Common = SimplicityModuleTypes;
    type Init = SimplicityInit;

    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<SimplicityConsensusItem> {
        self.assert_supported(dbtx).await;
        let mut items = Vec::new();
        if let Some(status) = self.monitor.as_ref().and_then(|monitor| monitor.status()) {
            items.push(SimplicityConsensusItem::BlockCount(status.block_count));
        }
        if let Some(version) = self.upgrade_proposal(dbtx).await {
            items.push(SimplicityConsensusItem::ModuleConsensusVersion(version));
        }
        items
    }
    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        item: SimplicityConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        self.assert_supported(dbtx).await;
        ensure!(self.cfg.consensus.peers.contains(&peer), "unknown guardian");
        match item {
            SimplicityConsensusItem::BlockCount(count) => {
                let previous = dbtx.get_value(&BlockVoteKey(peer)).await.unwrap_or(0);
                ensure!(count > previous, "redundant block count vote");
                dbtx.insert_entry(&BlockVoteKey(peer), &count).await;
            }
            SimplicityConsensusItem::ModuleConsensusVersion(version) => {
                self.process_version_vote(dbtx, peer, version).await?;
            }
            SimplicityConsensusItem::Default { variant, .. } => {
                anyhow::bail!("unknown Simplicity consensus item {variant}");
            }
        }
        Ok(())
    }
    fn verify_transaction(
        context: &ModuleTransactionContext<'_>,
    ) -> Result<(), fedimint_core::transaction::TransactionError> {
        let call = metrics::VALIDATION.start(metrics::Phase::Structure);
        // State resolution and kind-wide decoding follow these cheap checks.
        call.finish(
            fedimint_simplicity_common::resources::check_signed_structure(
                context.transaction,
                context.module_instance_id,
            )
            .map(|_| ()),
        )
    }
    async fn prepare_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        context: &ModuleTransactionContext<'_>,
    ) -> Result<ModuleTransactionValidation, fedimint_core::transaction::TransactionError> {
        let call = metrics::VALIDATION.start(metrics::Phase::Resolve);
        self.assert_supported(dbtx).await;
        let active = self.active_consensus_version(dbtx).await;
        call.finish(preparation::resolve(dbtx, context, active).await)
    }
    fn prepare_kind_transaction(
        context: &ModuleTransactionContext<'_>,
        instances: BTreeMap<ModuleInstanceId, ModuleTransactionValidation>,
    ) -> Result<ModuleTransactionValidation, fedimint_core::transaction::TransactionError> {
        let call = metrics::VALIDATION.start(metrics::Phase::Prepare);
        call.finish(preparation::prepare(context, instances))
    }
    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b ContractInput,
        _point: InPoint,
    ) -> Result<InputMeta, ContractError> {
        Err(ContractError::MissingContext)
    }
    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a ContractOutput,
        _point: OutPoint,
    ) -> Result<TransactionItemAmounts, ContractOutputError> {
        Err(ContractError::MissingContext.into())
    }
    async fn validate_transaction(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        context: &ModuleTransactionContext<'_>,
    ) -> Result<ModuleTransactionValidation, fedimint_core::transaction::TransactionError> {
        let call = metrics::VALIDATION.start(metrics::Phase::Validate);
        self.assert_supported(dbtx).await;
        call.finish(
            validation::validate(self, dbtx, context)
                .await
                .map(ModuleTransactionValidation::new),
        )
    }
    async fn process_input_with_context<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b ContractInput,
        point: InPoint,
        context: &ModuleTransactionContext<'_>,
    ) -> Result<InputMeta, ContractError> {
        let validated = validated(context)?;
        let index = context
            .transaction
            .inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| input.module_instance_id() == context.module_instance_id)
            .position(|(index, _)| index as u64 == point.in_idx)
            .ok_or(ContractError::Context)?;
        if dbtx
            .remove_entry(&ContractKey(input.outpoint))
            .await
            .is_none()
        {
            return Err(ContractError::UnknownContract);
        }
        let meta = validated.inputs.get(index).ok_or(ContractError::Context)?;
        Ok(InputMeta {
            pub_key: meta.pub_key,
            amount: meta.amount.clone(),
        })
    }
    async fn process_output_with_context<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a ContractOutput,
        point: OutPoint,
        context: &ModuleTransactionContext<'_>,
    ) -> Result<TransactionItemAmounts, ContractOutputError> {
        let validated = validated(context)?;
        if output.actions().is_some() {
            for namespace in &validated.namespaces {
                if dbtx.get_value(&NamespaceKey(*namespace)).await.is_some() {
                    return Err(ContractError::NamespaceUsed.into());
                }
                dbtx.insert_new_entry(&NamespaceKey(*namespace), &()).await;
            }
            for (id, record) in &validated.creations {
                dbtx.insert_new_entry(&AssetKey(*id), record).await;
            }
            return Ok(TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(output.amount),
                fees: Amounts::new_bitcoin(output_fee(output)),
            });
        }
        if dbtx.get_value(&ContractKey(point)).await.is_some() {
            return Err(ContractError::DuplicateOutput.into());
        }
        let stored = StoredContract {
            output: output.clone(),
            creation_session: context.consensus.session_index,
            creation_block_count: self.consensus_block_count(dbtx).await,
        };
        dbtx.insert_new_entry(&ContractKey(point), &stored).await;
        Ok(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin(output.amount),
            fees: Amounts::new_bitcoin(output_fee(output)),
        })
    }
    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _point: OutPoint,
    ) -> Option<ContractOutcome> {
        None
    }
    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_id: ModuleInstanceId,
    ) {
        audit
            .add_items(dbtx, module_id, &ContractPrefix, |_, contract| {
                -(contract.output.amount.msats as i64)
            })
            .await;
    }
    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            public_api_endpoint! {
                ACTIVE_CONSENSUS_VERSION_ENDPOINT, ApiVersion::new(0, 2),
                async |module: &Simplicity, context, _params: ()| -> ModuleConsensusVersion {
                    Ok(module.active_consensus_version(&mut context.db().begin_transaction_nc().await).await)
                }
            },
            public_api_endpoint! {
                SUPPORTED_CONSENSUS_VERSION_ENDPOINT, ApiVersion::new(0, 2),
                async |module: &Simplicity, _context, _params: ()| -> ModuleConsensusVersion {
                    Ok(module.upgrades.supported)
                }
            },
            public_api_endpoint! {
                "contract", ApiVersion::new(0, 0),
                async |_module: &Simplicity, context, point: OutPoint| -> Option<StoredContract> {
                    Ok(context.db().begin_transaction_nc().await.get_value(&ContractKey(point)).await)
                }
            },
            public_api_endpoint! {
                "asset", ApiVersion::new(0, 1),
                async |_module: &Simplicity, context, id: AssetId| -> Option<AssetRecord> {
                    Ok(context.db().begin_transaction_nc().await.get_value(&AssetKey(id)).await)
                }
            },
            public_api_endpoint! {
                "block_count", ApiVersion::new(0, 0),
                async |module: &Simplicity, context, _params: ()| -> u64 {
                    Ok(module.consensus_block_count(&mut context.db().begin_transaction_nc().await).await)
                }
            },
        ]
    }
}

fn validate_shape(context: &ModuleTransactionContext<'_>) -> Result<(), ContractError> {
    if context.transaction.outputs.len() > 128
        || context
            .transaction
            .inputs
            .iter()
            .filter(|input| input.module_instance_id() == context.module_instance_id)
            .count()
            > MAX_CONTRACTS
        || context
            .transaction
            .outputs
            .iter()
            .filter(|output| output.module_instance_id() == context.module_instance_id)
            .count()
            > MAX_CONTRACTS
    {
        return Err(ContractError::Limit);
    }
    Ok(())
}

fn validated<'a>(
    context: &'a ModuleTransactionContext<'_>,
) -> Result<&'a ValidatedTransaction, ContractError> {
    let validated = context
        .validation
        .and_then(|validation| validation.get::<ValidatedTransaction>())
        .ok_or(ContractError::MissingContext)?;
    if validated.txid != context.transaction.tx_hash() {
        return Err(ContractError::Context);
    }
    Ok(validated)
}
