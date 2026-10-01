//! Experimental Simplicity guardian module.

pub mod db;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use anyhow::ensure;
use async_trait::async_trait;
use fedimint_core::bitcoin::hashes::Hash;
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable;
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiVersion, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, TransactionItemAmounts, public_api_endpoint,
};
use fedimint_core::{InPoint, NumPeersExt, OutPoint, PeerId};
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::{
    ConfigGenModuleArgs, ModuleTransactionContext, ServerModule, ServerModuleInit,
    ServerModuleInitArgs,
};
use fedimint_simplicity_common::config::{
    SimplicityClientConfig, SimplicityConfig, SimplicityConfigConsensus, SimplicityConfigPrivate,
};
use fedimint_simplicity_common::runtime::{
    Environment, EnvironmentOutput, decode_program, execute,
};
use fedimint_simplicity_common::{
    BlockCountVote, ContractError, ContractInput, ContractOutcome, ContractOutput,
    ContractOutputError, EXECUTION_VERSION, MAX_CONTRACTS, MAX_RECOVERY_BYTES,
    MODULE_CONSENSUS_VERSION, SimplicityCommonInit, SimplicityModuleTypes, output_fee,
    signature_hash,
};
use futures::StreamExt;

use crate::db::{BlockVoteKey, BlockVotePrefix, ContractKey, ContractPrefix, StoredContract};

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
        let cfg: SimplicityConfig = args.cfg().to_typed()?;
        validate_peers(&cfg.consensus.peers)?;
        Ok(Simplicity {
            cfg,
            monitor: Some(args.server_bitcoin_rpc_monitor()),
        })
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
        validate_peers(&SimplicityConfigConsensus::from_erased(cfg)?.peers)?;
        Ok(SimplicityClientConfig)
    }
    fn validate_config(&self, identity: &PeerId, cfg: ServerModuleConfig) -> anyhow::Result<()> {
        let cfg: SimplicityConfig = cfg.to_typed()?;
        validate_peers(&cfg.consensus.peers)?;
        ensure!(
            cfg.consensus.peers.contains(identity),
            "guardian missing from configured peers"
        );
        Ok(())
    }
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
}

impl Simplicity {
    /// Construct an instance with manually supplied consensus votes, for tests
    /// and embedded prototypes. Production initialization uses the RPC monitor.
    pub fn new_for_testing(peers: Vec<PeerId>) -> anyhow::Result<Self> {
        validate_peers(&peers)?;
        Ok(Self {
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

    async fn consensus_proposal(&self, _dbtx: &mut DatabaseTransaction<'_>) -> Vec<BlockCountVote> {
        self.monitor
            .as_ref()
            .and_then(|monitor| monitor.status())
            .map(|status| vec![BlockCountVote(status.block_count)])
            .unwrap_or_default()
    }
    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        item: BlockCountVote,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        ensure!(self.cfg.consensus.peers.contains(&peer), "unknown guardian");
        let previous = dbtx.get_value(&BlockVoteKey(peer)).await.unwrap_or(0);
        ensure!(item.0 > previous, "redundant block count vote");
        dbtx.insert_entry(&BlockVoteKey(peer), &item.0).await;
        Ok(())
    }
    fn verify_input(&self, input: &ContractInput) -> Result<(), ContractError> {
        decode_program(input).map(|_| ())
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
    async fn process_input_with_context<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b ContractInput,
        point: InPoint,
        context: &ModuleTransactionContext<'_>,
    ) -> Result<InputMeta, ContractError> {
        validate_shape(context)?;
        let stored = dbtx
            .get_value(&ContractKey(input.outpoint))
            .await
            .ok_or(ContractError::UnknownContract)?;
        if stored.output.version != EXECUTION_VERSION {
            return Err(ContractError::Version);
        }
        let inputs = context
            .transaction
            .inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| input.module_instance_id() == context.module_instance_id)
            .map(|(index, _)| index as u64)
            .collect::<Vec<_>>();
        let index = inputs
            .iter()
            .position(|index| *index == point.in_idx)
            .ok_or(ContractError::Context)?;
        let outputs = context
            .transaction
            .outputs
            .iter()
            .map(|output| {
                let contract = if output.module_instance_id() == context.module_instance_id {
                    Some(
                        output
                            .as_any()
                            .downcast_ref::<ContractOutput>()
                            .ok_or(ContractError::Context)?
                            .clone(),
                    )
                } else {
                    None
                };
                Ok(EnvironmentOutput {
                    module_id: output.module_instance_id(),
                    hash: output.consensus_hash_sha256().to_byte_array(),
                    contract,
                })
            })
            .collect::<Result<Vec<_>, ContractError>>()?;
        let environment = Environment {
            signature_hash: signature_hash(
                context.consensus.federation_id,
                context.module_instance_id,
                context.transaction,
            )?,
            session_index: context.consensus.session_index,
            block_count: self.consensus_block_count(dbtx).await,
            current: stored.output.clone(),
            creation_session: stored.creation_session,
            creation_block_count: stored.creation_block_count,
            input_index: index as u32,
            input_count: inputs.len() as u32,
            outputs,
        };
        let fee = execute(input, &environment)?;
        dbtx.remove_entry(&ContractKey(input.outpoint)).await;
        Ok(InputMeta {
            pub_key: input.claim_key,
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(stored.output.amount),
                fees: Amounts::new_bitcoin(fee),
            },
        })
    }
    async fn process_output_with_context<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a ContractOutput,
        point: OutPoint,
        context: &ModuleTransactionContext<'_>,
    ) -> Result<TransactionItemAmounts, ContractOutputError> {
        validate_shape(context)?;
        if output.version != EXECUTION_VERSION {
            return Err(ContractError::Version.into());
        }
        if output.recovery.len() > MAX_RECOVERY_BYTES
            || output.amount.msats > 2_100_000_000_000_000_000
        {
            return Err(ContractError::Limit.into());
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
                "contract", ApiVersion::new(0, 0),
                async |_module: &Simplicity, context, point: OutPoint| -> Option<StoredContract> {
                    Ok(context.db().begin_transaction_nc().await.get_value(&ContractKey(point)).await)
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
