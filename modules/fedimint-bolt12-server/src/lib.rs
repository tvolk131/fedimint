#![deny(clippy::pedantic)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

//! Server module for federated BOLT12 offline receives.

mod bolt12;
pub mod db;
mod metrics;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, anyhow, ensure};
use bls12_381::{G1Projective, Scalar};
use fedimint_bolt12_common::config::{
    Bolt12ClientConfig, Bolt12ConfigConsensus, Bolt12ConfigPrivate, Bolt12ModuleConfig,
    FeeConsensus,
};
use fedimint_bolt12_common::endpoint_constants::{
    ADD_GATEWAY_ENDPOINT, GATEWAYS_ENDPOINT, REMOVE_GATEWAY_ENDPOINT,
};
use fedimint_bolt12_common::{
    Bolt12CommonInit, Bolt12ConsensusItem, Bolt12Input, Bolt12InputError, Bolt12InputV0,
    Bolt12ModuleTypes, Bolt12Output, Bolt12OutputError, Bolt12OutputOutcome,
    MODULE_CONSENSUS_VERSION,
};
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiVersion, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, TransactionItemAmounts, admin_api_endpoint, public_api_endpoint,
};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{
    Amount, NumPeers, NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send,
    push_db_key_items, push_db_pair_items,
};
use fedimint_logging::LOG_MODULE_LNV2;
use fedimint_server_core::config::{PeerHandleOps, eval_poly_g1};
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, EnvVarDoc, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
use futures::StreamExt;
use group::Curve;
use group::ff::Field;
use rand::rngs::OsRng;
use strum::IntoEnumIterator;
use tpe::{AggregatePublicKey, PublicKeyShare, SecretKeyShare, derive_pk_share};
use tracing::trace;

pub use crate::bolt12::keys::{
    FM_BOLT12_POOL_BATCH_ENV, FM_BOLT12_POOL_TARGET_ENV, FM_ENABLE_FEDERATED_BOLT12_ENV,
};
use crate::db::{
    Bolt12ContractPrefix, Bolt12GatewayDesiredVotePrefix, Bolt12GatewayVoteKey, DbKeyPrefix,
    GatewayKey, GatewayPrefix, UnixTimeVoteKey, UnixTimeVotePrefix,
};
use crate::metrics::BOLT12_FUNDED_CONTRACT_SATS;

#[derive(Debug, Clone)]
pub struct Bolt12Init;

impl ModuleInit for Bolt12Init {
    type Common = Bolt12CommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::UnixTimeVote => {
                    push_db_pair_items!(
                        dbtx,
                        UnixTimeVotePrefix,
                        UnixTimeVoteKey,
                        u64,
                        items,
                        "BOLT12 Unix Time Vote"
                    );
                }
                DbKeyPrefix::Gateway => {
                    push_db_key_items!(
                        dbtx,
                        GatewayPrefix,
                        GatewayKey,
                        items,
                        "BOLT12 Vetted Gateways"
                    );
                }
                _ => {}
            }
        }

        Box::new(items.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for Bolt12Init {
    type Module = Bolt12;

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn is_enabled_by_default(&self) -> bool {
        true
    }

    fn get_documented_env_vars(&self) -> Vec<EnvVarDoc> {
        vec![
            EnvVarDoc {
                name: FM_ENABLE_FEDERATED_BOLT12_ENV,
                description: "Experimental: set while starting fedimintd / generating a federation to attach the standalone federated BOLT12 receive module. Requires at least four guardians.",
            },
            EnvVarDoc {
                name: FM_BOLT12_POOL_TARGET_ENV,
                description: "Experimental: optional override for Bolt12Config::pool_target during federation setup (defaults to 32; 0 disables pool generation).",
            },
            EnvVarDoc {
                name: FM_BOLT12_POOL_BATCH_ENV,
                description: "Experimental: optional override for Bolt12Config::pool_batch during federation setup (defaults to 8; must be in 1..=32).",
            },
        ]
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        for source in ["stock", "pool"] {
            BOLT12_FUNDED_CONTRACT_SATS
                .with_label_values(&[source])
                .get_sample_count();
        }

        let cfg: Bolt12ModuleConfig = args.cfg().to_typed()?;

        let worker = (cfg.consensus.bolt12.pool_target > 0).then(|| {
            bolt12::worker::Worker::spawn(
                cfg.clone(),
                args.our_peer_id(),
                args.db().clone(),
                args.module_api().clone(),
                args.task_group(),
            )
        });

        Ok(Bolt12 {
            cfg,
            our_peer_id: args.our_peer_id(),
            signer: tokio::sync::Mutex::default(),
            worker,
            db: args.db().clone(),
        })
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let polynomial = dealer_polynomial(peers.to_num_peers());
        let (bolt12_public, bolt12_private) = bolt12::keys::fixture(peers)
            .expect("Valid federated BOLT12 configuration for guardian count");

        let tpe_pks = peers
            .iter()
            .map(|peer| (*peer, dealer_pk(&polynomial, *peer)))
            .collect::<BTreeMap<PeerId, PublicKeyShare>>();

        peers
            .iter()
            .map(|peer| {
                let cfg = Bolt12ModuleConfig {
                    consensus: Bolt12ConfigConsensus {
                        tpe_agg_pk: dealer_agg_pk(&polynomial),
                        tpe_pks: tpe_pks.clone(),
                        fee_consensus: if args.disable_base_fees {
                            FeeConsensus::zero()
                        } else {
                            FeeConsensus::new(0).expect("Relative fee is within range")
                        },
                        network: args.network,
                        bolt12: bolt12_public.clone(),
                    },
                    private: Bolt12ConfigPrivate {
                        sk: dealer_sk(&polynomial, *peer),
                        bolt12: bolt12_private[peer].clone(),
                    },
                };

                (*peer, cfg.to_erased())
            })
            .collect()
    }

    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        let (polynomial, sks) = peers.run_dkg_g1().await?;
        let (bolt12_public, bolt12_private) = bolt12::keys::generate(peers).await?;

        let server = Bolt12ModuleConfig {
            consensus: Bolt12ConfigConsensus {
                tpe_agg_pk: tpe::AggregatePublicKey(polynomial[0].to_affine()),
                tpe_pks: peers
                    .num_peers()
                    .peer_ids()
                    .map(|peer| (peer, PublicKeyShare(eval_poly_g1(&polynomial, &peer))))
                    .collect(),
                fee_consensus: if args.disable_base_fees {
                    FeeConsensus::zero()
                } else {
                    FeeConsensus::new(0).expect("Relative fee is within range")
                },
                network: args.network,
                bolt12: bolt12_public,
            },
            private: Bolt12ConfigPrivate {
                sk: SecretKeyShare(sks),
                bolt12: bolt12_private,
            },
        };

        Ok(server.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<Bolt12ModuleConfig>()?;

        ensure!(
            tpe::derive_pk_share(&config.private.sk)
                == *config
                    .consensus
                    .tpe_pks
                    .get(identity)
                    .context("Public key set has no key for our identity")?,
            "Preimage encryption secret key share does not match our public key share"
        );

        bolt12::keys::validate(*identity, &config)?;

        Ok(())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<Bolt12ClientConfig> {
        let config = Bolt12ConfigConsensus::from_erased(config)?;
        Ok(Bolt12ClientConfig {
            tpe_agg_pk: config.tpe_agg_pk,
            tpe_pks: config.tpe_pks,
            fee_consensus: config.fee_consensus,
            network: config.network,
            bolt12: config.bolt12,
        })
    }

    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Bolt12>> {
        BTreeMap::new()
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(DbKeyPrefix::iter().map(|p| p as u8).collect())
    }
}

fn dealer_polynomial(num_peers: NumPeers) -> Vec<Scalar> {
    (0..num_peers.threshold())
        .map(|_| Scalar::random(&mut OsRng))
        .collect()
}

fn dealer_agg_pk(polynomial: &[Scalar]) -> AggregatePublicKey {
    AggregatePublicKey((G1Projective::generator() * polynomial[0]).to_affine())
}

fn dealer_pk(polynomial: &[Scalar], peer: PeerId) -> PublicKeyShare {
    derive_pk_share(&dealer_sk(polynomial, peer))
}

fn dealer_sk(polynomial: &[Scalar], peer: PeerId) -> SecretKeyShare {
    let x = Scalar::from(u64::try_from(peer.to_usize()).expect("peer id fits in u64") + 1);
    let y = polynomial
        .iter()
        .rev()
        .fold(Scalar::zero(), |acc, coeff| acc * x + coeff);

    SecretKeyShare(y)
}

#[derive(Debug)]
pub struct Bolt12 {
    cfg: Bolt12ModuleConfig,
    our_peer_id: PeerId,
    signer: tokio::sync::Mutex<bolt12::signer::Signer>,
    worker: Option<Arc<bolt12::worker::Worker>>,
    db: Database,
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Bolt12 {
    type Common = Bolt12ModuleTypes;
    type Init = Bolt12Init;

    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<Bolt12ConsensusItem> {
        let mut items = vec![Bolt12ConsensusItem::UnixTimeVote(
            60 * (duration_since_epoch().as_secs() / 60),
        )];

        let desired = dbtx
            .find_by_prefix(&Bolt12GatewayDesiredVotePrefix)
            .await
            .collect::<Vec<_>>()
            .await;

        for (key, approve) in desired {
            let current = dbtx
                .get_value(&Bolt12GatewayVoteKey(key.0, self.our_peer_id))
                .await
                .unwrap_or(false);

            if current != approve {
                items.push(Bolt12ConsensusItem::GatewayVote {
                    gateway: key.0,
                    approve,
                });
            }
        }

        items.extend(self.bolt12_pool_proposals(dbtx).await);

        items
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: Bolt12ConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        trace!(target: LOG_MODULE_LNV2, ?consensus_item, "Processing bolt12 consensus item");

        match consensus_item {
            Bolt12ConsensusItem::UnixTimeVote(vote) => {
                let current_vote = dbtx
                    .insert_entry(&UnixTimeVoteKey(peer), &vote)
                    .await
                    .unwrap_or(0);

                ensure!(current_vote < vote, "Unix time vote is redundant");

                Ok(())
            }
            Bolt12ConsensusItem::GatewayVote { gateway, approve } => {
                bolt12::process_gateway_vote(dbtx, &self.cfg, peer, gateway, approve).await
            }
            Bolt12ConsensusItem::PoolStart { run } => {
                let now = self.consensus_unix_time(dbtx).await;
                bolt12::pool::process_start(dbtx, &self.cfg, run, now).await
            }
            Bolt12ConsensusItem::PoolShares { run, shares } => {
                bolt12::pool::process_shares(dbtx, &self.cfg, peer, run, shares).await
            }
            Bolt12ConsensusItem::PoolAbandon { run } => {
                let now = self.consensus_unix_time(dbtx).await;
                bolt12::pool::process_abandon(dbtx, &self.cfg, run, now).await
            }
            Bolt12ConsensusItem::PoolAbort { run } => {
                let now = self.consensus_unix_time(dbtx).await;
                bolt12::pool::process_abort(dbtx, &self.cfg, peer, run, now).await
            }
            Bolt12ConsensusItem::PoolEvidence { run, digest } => {
                let now = self.consensus_unix_time(dbtx).await;
                bolt12::pool::process_evidence(dbtx, &self.cfg, peer, run, digest, now).await
            }
            Bolt12ConsensusItem::PoolVerdict { run, verdict } => {
                let now = self.consensus_unix_time(dbtx).await;
                bolt12::pool::process_verdict(dbtx, &self.cfg, peer, run, verdict, now).await
            }
            Bolt12ConsensusItem::Default { variant, .. } => Err(anyhow!(
                "Received bolt12 consensus item with unknown variant {variant}"
            )),
        }
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b Bolt12Input,
        _in_point: fedimint_core::InPoint,
    ) -> Result<InputMeta, Bolt12InputError> {
        let Bolt12InputV0::Receive(outpoint, unlock) = input.ensure_v0_ref()?;

        let effect = bolt12::process_input(dbtx, &self.cfg, *outpoint, unlock).await?;

        let fee = self
            .cfg
            .consensus
            .fee_consensus
            .fee(effect.amount)
            .checked_add(effect.premium)
            .ok_or(Bolt12InputError::FeeOverflow)?;

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(effect.amount),
                fees: Amounts::new_bitcoin(fee),
            },
            pub_key: effect.pub_key,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a Bolt12Output,
        outpoint: OutPoint,
    ) -> Result<TransactionItemAmounts, Bolt12OutputError> {
        let output = output.ensure_v0_ref()?;
        let now = self.consensus_unix_time(dbtx).await;

        let effect = bolt12::process_output(dbtx, &self.cfg, output, outpoint, now)
            .await
            .map_err(|e| Bolt12OutputError::Bolt12(e.to_string()))?;

        if effect.funded {
            observe_funded_contract(dbtx, "incoming", effect.amount);
        }

        Ok(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin(effect.amount),
            fees: Amounts::new_bitcoin(effect.fee),
        })
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<Bolt12OutputOutcome> {
        None
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &Bolt12ContractPrefix,
                |_, contract| -(contract.amount.msats as i64),
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        let mut endpoints = vec![
            admin_api_endpoint! {
                ADD_GATEWAY_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, gateway: SafeUrl| -> bool {
                    Ok(Bolt12::add_gateway(context.db(), gateway).await)
                }
            },
            admin_api_endpoint! {
                REMOVE_GATEWAY_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, gateway: SafeUrl| -> bool {
                    Ok(Bolt12::remove_gateway(context.db(), gateway).await)
                }
            },
            public_api_endpoint! {
                GATEWAYS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, _params: ()| -> Vec<SafeUrl> {
                    Ok(Bolt12::gateways(context.db()).await)
                }
            },
        ];

        endpoints.extend(Self::bolt12_api_endpoints());
        endpoints.extend(Self::bolt12_pool_endpoints());
        endpoints.extend(Self::bolt12_signing_endpoints());

        endpoints
    }
}

impl Bolt12 {
    async fn consensus_unix_time(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let num_peers = self.cfg.consensus.tpe_pks.to_num_peers();

        let mut times = dbtx
            .find_by_prefix(&UnixTimeVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<u64>>()
            .await;

        times.sort_unstable();
        times.reverse();

        assert!(times.last() <= times.first());

        times.get(num_peers.threshold() - 1).copied().unwrap_or(0)
    }

    async fn add_gateway(db: Database, gateway: SafeUrl) -> bool {
        let mut dbtx = db.begin_transaction().await;
        let is_new_entry = dbtx.insert_entry(&GatewayKey(gateway), &()).await.is_none();
        dbtx.commit_tx().await;
        is_new_entry
    }

    async fn remove_gateway(db: Database, gateway: SafeUrl) -> bool {
        let mut dbtx = db.begin_transaction().await;
        let entry_existed = dbtx.remove_entry(&GatewayKey(gateway)).await.is_some();
        dbtx.commit_tx().await;
        entry_existed
    }

    async fn gateways(db: Database) -> Vec<SafeUrl> {
        db.begin_transaction_nc()
            .await
            .find_by_prefix(&GatewayPrefix)
            .await
            .map(|entry| entry.0.0)
            .collect()
            .await
    }

    pub async fn consensus_unix_time_ui(&self) -> u64 {
        self.consensus_unix_time(&mut self.db.begin_transaction_nc().await)
            .await
    }

    pub async fn add_gateway_ui(&self, gateway: SafeUrl) -> bool {
        Self::add_gateway(self.db.clone(), gateway).await
    }

    pub async fn remove_gateway_ui(&self, gateway: SafeUrl) -> bool {
        Self::remove_gateway(self.db.clone(), gateway).await
    }

    pub async fn gateways_ui(&self) -> Vec<SafeUrl> {
        Self::gateways(self.db.clone()).await
    }
}

fn observe_funded_contract(
    dbtx: &mut DatabaseTransaction<'_>,
    source: &'static str,
    amount: Amount,
) {
    dbtx.on_commit(move || {
        BOLT12_FUNDED_CONTRACT_SATS
            .with_label_values(&[source])
            .observe(amount.sats_f64());
    });
}
