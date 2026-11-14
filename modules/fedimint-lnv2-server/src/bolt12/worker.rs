//! This guardian's part in generation runs. Not consensus: consensus starts
//! runs and collects their results; the worker runs the MPC in between.
//!
//! Before sending anything in a run the worker durably records it, together
//! with the seed all of its randomness comes from, and it never takes part in a
//! recorded run again: a restarted guardian lets the run time out rather than
//! repeat messages with fresh randomness.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, Result};
use fedimint_api_client::api::DynModuleApi;
use fedimint_core::PeerId;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable as _;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_lnv2_common::bolt12::{POOL_RUN_TIMEOUT, PoolRun, PoolShare, pool_share_binding};
use fedimint_lnv2_common::config::LightningConfig;
use fedimint_logging::LOG_MODULE_LNV2;
use futures::StreamExt as _;
use mpc::direct;
use mpc::engine::Params;
use rand::RngCore as _;
use rand::rngs::OsRng;
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::transport::{ApiTransport, Channels, MpcPacket};
use crate::db::{Bolt12PoolLocalRunKey, Bolt12PoolLocalRunPrefix, Bolt12PoolRunKey, LocalRun};

const POLL_INTERVAL: Duration = Duration::from_secs(1);

pub struct Worker {
    /// The channels of the run in progress, for the packet endpoint.
    channels: Mutex<Option<Arc<Channels>>>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker").finish_non_exhaustive()
    }
}

impl Worker {
    pub fn spawn(
        cfg: LightningConfig,
        me: PeerId,
        db: Database,
        api: DynModuleApi,
        task_group: &TaskGroup,
    ) -> Arc<Self> {
        let worker = Arc::new(Self {
            channels: Mutex::new(None),
        });

        let this = worker.clone();

        task_group.spawn_cancellable("bolt12 preimage generation", async move {
            loop {
                if let Err(err) = this.tick(&cfg, me, &db, &api).await {
                    warn!(target: LOG_MODULE_LNV2, err = %format!("{err:#}"), "Preimage generation run failed");
                }

                sleep(POLL_INTERVAL).await;
            }
        });

        worker
    }

    /// Hand a packet from the endpoint to the run in progress.
    pub fn receive(&self, packet: &MpcPacket) -> Result<()> {
        let channels = self
            .channels
            .lock()
            .expect("not poisoned")
            .clone()
            .filter(|channels| channels.run() == packet.run)
            .context("This guardian is not in that run")?;

        channels.receive(packet)
    }

    async fn tick(
        &self,
        cfg: &LightningConfig,
        me: PeerId,
        db: &Database,
        api: &DynModuleApi,
    ) -> Result<()> {
        let mut dbtx = db.begin_transaction().await;

        let active = dbtx.get_value(&Bolt12PoolRunKey).await;

        // Forget runs that are over; their shares are in consensus or void.
        let finished: Vec<u64> = dbtx
            .find_by_prefix(&Bolt12PoolLocalRunPrefix)
            .await
            .map(|(key, _)| key.0)
            .filter(|run| std::future::ready(active.as_ref().is_none_or(|a| a.run != *run)))
            .collect()
            .await;

        for run in finished {
            dbtx.remove_entry(&Bolt12PoolLocalRunKey(run)).await;
        }

        let Some(active) = active.filter(|active| active.position(me).is_some()) else {
            dbtx.commit_tx_result().await?;

            return Ok(());
        };

        if dbtx
            .get_value(&Bolt12PoolLocalRunKey(active.run))
            .await
            .is_some()
        {
            dbtx.commit_tx_result().await?;

            return Ok(());
        }

        let mut seed = Zeroizing::new([0; 32]);

        OsRng.fill_bytes(seed.as_mut());

        dbtx.insert_new_entry(
            &Bolt12PoolLocalRunKey(active.run),
            &LocalRun {
                seed: *seed,
                submission: None,
            },
        )
        .await;

        dbtx.commit_tx_result().await?;

        info!(target: LOG_MODULE_LNV2, run = active.run, "Starting a preimage generation run");

        let result = self.generate(cfg, me, api, &active, &seed).await;

        *self.channels.lock().expect("not poisoned") = None;

        let submission = result?;

        let mut dbtx = db.begin_transaction().await;

        dbtx.insert_entry(
            &Bolt12PoolLocalRunKey(active.run),
            &LocalRun {
                seed: *seed,
                submission: Some(submission),
            },
        )
        .await;

        dbtx.commit_tx_result().await?;

        info!(target: LOG_MODULE_LNV2, run = active.run, "Finished a preimage generation run");

        Ok(())
    }

    async fn generate(
        &self,
        cfg: &LightningConfig,
        me: PeerId,
        api: &DynModuleApi,
        active: &PoolRun,
        seed: &[u8; 32],
    ) -> Result<Vec<PoolShare>> {
        let bolt12 = cfg
            .consensus
            .bolt12
            .as_ref()
            .context("Federated BOLT12 is disabled")?;

        let private = cfg
            .private
            .bolt12
            .as_ref()
            .context("Missing private BOLT12 configuration")?;

        let position = active.position(me).context("Not on the committee")?;
        let degree = PoolRun::degree(cfg.consensus.tpe_pks.len());
        let params = Params::new(active.committee.len(), degree)?;
        let batch = usize::try_from(active.batch)?;
        let circuit = direct::circuit(params, batch)?;

        let channels = Channels::new(
            active.run,
            me,
            active.committee.clone(),
            &private.transport_secret,
            &bolt12.transport_keys,
        )?;

        *self.channels.lock().expect("not poisoned") = Some(channels.clone());

        let mut transport = ApiTransport::new(channels, api.clone());

        let context = (
            "fedimint/bolt12/pool-run/v1",
            bolt12.signing_key,
            active.clone(),
        )
            .consensus_encode_to_vec();

        let generated = fedimint_core::runtime::timeout(
            Duration::from_secs(POOL_RUN_TIMEOUT),
            direct::generate(
                &mut transport,
                params,
                usize::from(position),
                batch,
                &circuit,
                seed,
                &context,
            ),
        )
        .await
        .context("The run timed out")??;

        Ok(generated
            .iter()
            .map(|item| {
                let mut encryption_seed = Zeroizing::new([0; 32]);

                OsRng.fill_bytes(encryption_seed.as_mut());

                PoolShare {
                    payment_hash: item.payment_hash,
                    ciphertext: tpe::encrypt_preimage(
                        &cfg.consensus.tpe_agg_pk,
                        &encryption_seed,
                        item.share.value(),
                        &pool_share_binding(active.run, position, item.payment_hash),
                    ),
                }
            })
            .collect())
    }
}
