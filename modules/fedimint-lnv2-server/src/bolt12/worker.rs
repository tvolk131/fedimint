//! This guardian's part in generation runs. Not consensus: consensus starts,
//! completes, abandons and judges runs; the worker runs the MPC in between
//! and prepares what this guardian proposes.
//!
//! Before sending anything in a run the worker durably records it, together
//! with the seed all of its randomness comes from, and it never takes part in a
//! recorded run again: a restarted guardian lets the run time out rather than
//! repeat messages with fresh randomness. When its part ends, it stores the
//! signed messages it received and commits to them with the seed as evidence.
//! Evidence is revealed only once consensus has abandoned the run, so it
//! never exposes a preimage that can still be used.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use fedimint_api_client::api::{DynModuleApi, FederationApiExt as _};
use fedimint_core::bitcoin::hashes::sha256;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::{PeerId, runtime};
use fedimint_lnv2_common::bolt12::{
    AbandonedRun, EVIDENCE_WINDOW, POOL_RUN_TIMEOUT, PoolRun, PoolShare, PoolVerdict,
    pool_share_binding,
};
use fedimint_lnv2_common::config::LightningConfig;
use fedimint_lnv2_common::endpoint_constants::BOLT12_MPC_EVIDENCE_ENDPOINT;
use fedimint_logging::LOG_MODULE_LNV2;
use futures::StreamExt as _;
use mpc::direct;
use mpc::engine::Params;
use mpc::replay::{Evidence, Received, judge};
use rand::RngCore as _;
use rand::rngs::OsRng;
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::transport::{ApiTransport, Channels, MpcPacket, verify_message};
use crate::db::{
    Bolt12PoolAbandonedKey, Bolt12PoolAbandonedPrefix, Bolt12PoolLocalRunKey,
    Bolt12PoolLocalRunPrefix, Bolt12PoolLocalVerdictKey, Bolt12PoolLocalVerdictPrefix,
    Bolt12PoolRunKey, Bolt12PoolTranscriptKey, Bolt12PoolTranscriptRunPrefix, Bolt12PoolVerdictKey,
    LocalRun, SignedMessage,
};

const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How long after the evidence window closes, by this guardian's clock, it
/// waits before judging, so late commitments are in.
const JUDGE_MARGIN: u64 = 120;

/// Message bytes in one page of evidence.
const EVIDENCE_PAGE_BYTES: usize = 1024 * 1024;

/// The most rounds a run may have; bounds the evidence a peer can make us
/// fetch.
const MAX_ROUNDS: usize = 100_000;

/// A page of a member's evidence, as the evidence endpoint returns it.
#[derive(Debug, Encodable, Decodable)]
pub struct EvidencePage {
    pub seed: [u8; 32],
    /// Rounds from the requested one on.
    pub rounds: Vec<Vec<Option<SignedMessage>>>,
    /// Whether rounds remain after these.
    pub more: bool,
}

pub(super) type Rounds = Vec<Vec<Option<SignedMessage>>>;

/// The commitment a member makes to its evidence.
pub(super) fn evidence_digest(seed: &[u8; 32], rounds: &Rounds) -> sha256::Hash {
    ("fedimint/bolt12/mpc-evidence/v1", *seed, rounds.clone()).consensus_hash()
}

/// What every member binds a run's challenges to.
fn run_context(cfg: &LightningConfig, run: &PoolRun) -> Result<Vec<u8>> {
    let bolt12 = cfg
        .consensus
        .bolt12
        .as_ref()
        .context("Federated BOLT12 is disabled")?;

    Ok((
        "fedimint/bolt12/pool-run/v1",
        bolt12.signing_key,
        run.clone(),
    )
        .consensus_encode_to_vec())
}

fn run_params(cfg: &LightningConfig, run: &PoolRun) -> Result<(Params, usize)> {
    let degree = PoolRun::degree(cfg.consensus.tpe_pks.len());

    Ok((
        Params::new(run.committee.len(), degree)?,
        usize::try_from(run.batch)?,
    ))
}

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
                    warn!(target: LOG_MODULE_LNV2, err = %format!("{err:#}"), "Preimage generation failed");
                }

                if let Err(err) = judge_abandoned(&cfg, me, &db, &api).await {
                    warn!(target: LOG_MODULE_LNV2, err = %format!("{err:#}"), "Judging an abandoned run failed");
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
        forget_finished(db).await?;

        let mut dbtx = db.begin_transaction().await;

        let Some(active) = dbtx
            .get_value(&Bolt12PoolRunKey)
            .await
            .filter(|active| active.position(me).is_some())
        else {
            return Ok(());
        };

        if dbtx
            .get_value(&Bolt12PoolLocalRunKey(active.run))
            .await
            .is_some()
        {
            return Ok(());
        }

        let mut seed = Zeroizing::new([0; 32]);

        OsRng.fill_bytes(seed.as_mut());

        dbtx.insert_new_entry(
            &Bolt12PoolLocalRunKey(active.run),
            &LocalRun {
                seed: *seed,
                submission: None,
                evidence: None,
            },
        )
        .await;

        dbtx.commit_tx_result().await?;

        info!(target: LOG_MODULE_LNV2, run = active.run, "Starting a preimage generation run");

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

        let channels = Channels::new(
            active.run,
            me,
            active.committee.clone(),
            &private.transport_secret,
            &bolt12.transport_keys,
        )?;

        *self.channels.lock().expect("not poisoned") = Some(channels.clone());

        // Stop when consensus moves on, so evidence is ready in time.
        let result = tokio::select! {
            result = generate(cfg, me, api, &active, &seed, channels.clone()) => result,
            () = run_ends(db, active.run) => Err(anyhow::anyhow!("Consensus ended the run")),
        };

        *self.channels.lock().expect("not poisoned") = None;

        let rounds = channels.transcript();
        let evidence = evidence_digest(&seed, &rounds);

        let mut dbtx = db.begin_transaction().await;

        for (round, row) in rounds.into_iter().enumerate() {
            dbtx.insert_entry(&Bolt12PoolTranscriptKey(active.run, round as u64), &row)
                .await;
        }

        let submission = match result {
            Ok(submission) => {
                info!(target: LOG_MODULE_LNV2, run = active.run, "Finished a preimage generation run");

                Some(submission)
            }
            Err(err) => {
                warn!(target: LOG_MODULE_LNV2, run = active.run, err = %format!("{err:#}"), "Preimage generation run aborted");

                None
            }
        };

        dbtx.insert_entry(
            &Bolt12PoolLocalRunKey(active.run),
            &LocalRun {
                seed: *seed,
                submission,
                evidence: Some(evidence),
            },
        )
        .await;

        dbtx.commit_tx_result().await?;

        Ok(())
    }
}

/// Resolves once run `run` is no longer in progress.
async fn run_ends(db: &Database, run: u64) {
    loop {
        let active = db
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12PoolRunKey)
            .await;

        if active.is_none_or(|active| active.run != run) {
            return;
        }

        sleep(POLL_INTERVAL).await;
    }
}

/// Delete local state of runs that are neither in progress nor being judged.
async fn forget_finished(db: &Database) -> Result<()> {
    let mut dbtx = db.begin_transaction().await;

    let active = dbtx.get_value(&Bolt12PoolRunKey).await.map(|run| run.run);

    let judged: Vec<u64> = dbtx
        .find_by_prefix(&Bolt12PoolAbandonedPrefix)
        .await
        .map(|(key, _)| key.0)
        .collect()
        .await;

    let keep = |run: u64| Some(run) == active || judged.contains(&run);

    let local: Vec<u64> = dbtx
        .find_by_prefix(&Bolt12PoolLocalRunPrefix)
        .await
        .map(|(key, _)| key.0)
        .collect()
        .await;

    for run in local.into_iter().filter(|run| !keep(*run)) {
        dbtx.remove_entry(&Bolt12PoolLocalRunKey(run)).await;
        dbtx.remove_by_prefix(&Bolt12PoolTranscriptRunPrefix(run))
            .await;
    }

    let verdicts: Vec<u64> = dbtx
        .find_by_prefix(&Bolt12PoolLocalVerdictPrefix)
        .await
        .map(|(key, _)| key.0)
        .collect()
        .await;

    for run in verdicts.into_iter().filter(|run| !judged.contains(run)) {
        dbtx.remove_entry(&Bolt12PoolLocalVerdictKey(run)).await;
    }

    dbtx.commit_tx_result().await?;

    Ok(())
}

async fn generate(
    cfg: &LightningConfig,
    me: PeerId,
    api: &DynModuleApi,
    active: &PoolRun,
    seed: &[u8; 32],
    channels: Arc<Channels>,
) -> Result<Vec<PoolShare>> {
    let position = active.position(me).context("Not on the committee")?;
    let (params, batch) = run_params(cfg, active)?;
    let circuit = direct::circuit(params, batch)?;
    let context = run_context(cfg, active)?;

    let mut transport = ApiTransport::new(channels, api.clone());

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

/// A page of this guardian's evidence about run `run`, from round `from`.
/// Refused unless consensus has abandoned the run.
pub async fn serve_evidence(db: &Database, run: u64, from: u64) -> Result<EvidencePage> {
    let mut dbtx = db.begin_transaction_nc().await;

    ensure!(
        dbtx.get_value(&Bolt12PoolAbandonedKey(run)).await.is_some(),
        "The run has not been abandoned"
    );

    let local = dbtx
        .get_value(&Bolt12PoolLocalRunKey(run))
        .await
        .filter(|local| local.evidence.is_some())
        .context("This guardian has no evidence about the run")?;

    let rows: Vec<(Bolt12PoolTranscriptKey, Vec<Option<SignedMessage>>)> = dbtx
        .find_by_range(Bolt12PoolTranscriptKey(run, from)..Bolt12PoolTranscriptKey(run, u64::MAX))
        .await
        .collect()
        .await;

    let mut rounds = vec![];
    let mut bytes = 0;

    for (_, row) in &rows {
        if bytes >= EVIDENCE_PAGE_BYTES {
            break;
        }

        bytes += row
            .iter()
            .flatten()
            .map(|signed| signed.message.len())
            .sum::<usize>();

        rounds.push(row.clone());
    }

    Ok(EvidencePage {
        seed: local.seed,
        more: rounds.len() < rows.len(),
        rounds,
    })
}

/// A member's evidence: from our database for ourselves, from its endpoint
/// otherwise.
async fn fetch_evidence(
    db: &Database,
    api: &DynModuleApi,
    me: PeerId,
    member: PeerId,
    run: u64,
) -> Result<([u8; 32], Rounds)> {
    let mut seed = None;
    let mut rounds = vec![];

    loop {
        let page = if member == me {
            serve_evidence(db, run, rounds.len() as u64).await?
        } else {
            let hex: String = api
                .request_single_peer(
                    BOLT12_MPC_EVIDENCE_ENDPOINT.to_owned(),
                    ApiRequestErased::new((run, rounds.len() as u64)),
                    member,
                )
                .await?;

            EvidencePage::consensus_decode_hex(&hex, &ModuleRegistry::default())?
        };

        ensure!(
            seed.is_none_or(|seed| seed == page.seed),
            "The seed changed between pages"
        );
        ensure!(
            !page.rounds.is_empty() || !page.more,
            "An empty page claims more follow"
        );

        seed = Some(page.seed);
        rounds.extend(page.rounds);

        ensure!(rounds.len() <= MAX_ROUNDS, "Too many rounds of evidence");

        if !page.more {
            break;
        }
    }

    Ok((seed.context("No evidence")?, rounds))
}

/// Judge abandoned runs whose evidence is in and that this guardian has not
/// judged yet.
async fn judge_abandoned(
    cfg: &LightningConfig,
    me: PeerId,
    db: &Database,
    api: &DynModuleApi,
) -> Result<()> {
    let now = duration_since_epoch().as_secs();

    let abandoned: Vec<AbandonedRun> = db
        .begin_transaction_nc()
        .await
        .find_by_prefix(&Bolt12PoolAbandonedPrefix)
        .await
        .map(|(_, abandoned)| abandoned)
        .collect()
        .await;

    for abandoned in abandoned {
        let run = abandoned.run.run;

        if now < abandoned.abandoned_at + EVIDENCE_WINDOW + JUDGE_MARGIN || abandoned.is_stale(now)
        {
            continue;
        }

        let mut dbtx = db.begin_transaction_nc().await;

        if dbtx
            .get_value(&Bolt12PoolLocalVerdictKey(run))
            .await
            .is_some()
            || dbtx
                .get_value(&Bolt12PoolVerdictKey(run, me))
                .await
                .is_some()
        {
            continue;
        }

        drop(dbtx);

        let verdict = verdict(cfg, me, db, api, &abandoned).await?;

        info!(target: LOG_MODULE_LNV2, run, ?verdict, "Judged an abandoned preimage generation run");

        let mut dbtx = db.begin_transaction().await;

        dbtx.insert_entry(&Bolt12PoolLocalVerdictKey(run), &verdict)
            .await;
        dbtx.commit_tx_result().await?;
    }

    Ok(())
}

/// Only the messages in `rounds` whose sender signed them, as `member`
/// received them.
pub(super) fn signed_messages(
    cfg: &LightningConfig,
    run: &PoolRun,
    member: PeerId,
    rounds: &Rounds,
) -> Result<Received> {
    let keys = &cfg
        .consensus
        .bolt12
        .as_ref()
        .context("Federated BOLT12 is disabled")?
        .transport_keys;

    Ok(rounds
        .iter()
        .enumerate()
        .map(|(round, row)| {
            row.iter()
                .enumerate()
                .map(|(position, signed)| {
                    let signed = signed.as_ref()?;
                    let sender = *run.committee.get(position)?;
                    let key = keys.get(&sender)?;

                    (sender != member
                        && verify_message(run.run, (sender, key), member, round as u64, signed))
                    .then(|| signed.message.clone())
                })
                .collect()
        })
        .collect())
}

/// Replay an abandoned run from its members' evidence and find who is to
/// blame.
async fn verdict(
    cfg: &LightningConfig,
    me: PeerId,
    db: &Database,
    api: &DynModuleApi,
    abandoned: &AbandonedRun,
) -> Result<PoolVerdict> {
    let run = &abandoned.run;
    let mut evidence = Vec::with_capacity(run.committee.len());

    for member in &run.committee {
        let Some(digest) = abandoned.evidence.get(member) else {
            evidence.push(None);
            continue;
        };

        // Evidence we cannot fetch, or that does not match the commitment,
        // counts as withheld.
        let fetched = match fetch_evidence(db, api, me, *member, run.run).await {
            Ok((seed, rounds)) if evidence_digest(&seed, &rounds) == *digest => Some(Evidence {
                seed,
                received: signed_messages(cfg, run, *member, &rounds)?,
            }),
            Ok(_) => {
                warn!(target: LOG_MODULE_LNV2, run = run.run, %member, "Evidence does not match its commitment");

                None
            }
            Err(err) => {
                warn!(target: LOG_MODULE_LNV2, run = run.run, %member, err = %format!("{err:#}"), "Could not fetch evidence");

                None
            }
        };

        evidence.push(fetched);
    }

    let submitted: Vec<bool> = run
        .committee
        .iter()
        .map(|member| abandoned.submitted.contains(member))
        .collect();

    let (params, batch) = run_params(cfg, run)?;
    let context = run_context(cfg, run)?;

    // Replaying every member is as much work as the run itself.
    let found = runtime::spawn_blocking(move || {
        let circuit = direct::circuit(params, batch)?;

        runtime::block_on(judge(
            params, batch, &circuit, &context, &evidence, &submitted,
        ))
    })
    .await?;

    let member = |position: usize| run.committee[position];

    Ok(PoolVerdict {
        culprits: found
            .culprits
            .into_iter()
            .map(member)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        disputes: found
            .disputes
            .into_iter()
            .map(|(a, b)| (member(a).min(member(b)), member(a).max(member(b))))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    })
}
