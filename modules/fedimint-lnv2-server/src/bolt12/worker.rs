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

use super::transport::{
    ApiTransport, CHUNK, ChannelLimits, Channels, FetchRequest, MAX_FAULT_CIPHERTEXT_LEN,
    MAX_RELAY_WITNESSES, MpcPacket, RelayRequest, verify_message, verify_transport_fault_convicts,
};
use crate::db::{
    Bolt12PoolAbandonedKey, Bolt12PoolAbandonedPrefix, Bolt12PoolLocalRunKey,
    Bolt12PoolLocalRunPrefix, Bolt12PoolLocalVerdictKey, Bolt12PoolLocalVerdictPrefix,
    Bolt12PoolRelayEvidenceKey, Bolt12PoolRelayEvidencePrefix, Bolt12PoolRunKey,
    Bolt12PoolTranscriptKey, Bolt12PoolTranscriptRunPrefix, Bolt12PoolVerdictKey, LocalRun,
    RelayEvidence, SignedMessage,
};

const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// How long after the evidence window closes, by this guardian's clock, it
/// waits before judging, so late commitments are in.
const JUDGE_MARGIN: u64 = 30;

/// Message bytes in one page of evidence.
const EVIDENCE_PAGE_BYTES: usize = 1024 * 1024;

/// The most rounds a run may have; bounds the evidence a peer can make us
/// fetch.
const MAX_ROUNDS: usize = 100_000;

/// Minimum total decoded transcript byte cap per member for small runs.
const MIN_MEMBER_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

/// A page of a member's evidence, as the evidence endpoint returns it.
#[derive(Debug, Encodable, Decodable)]
pub struct EvidencePage {
    pub seed: [u8; 32],
    /// Rounds from the requested one on.
    pub rounds: Vec<Vec<Option<SignedMessage>>>,
    /// Relay witnesses and undecryptable signed packets (populated on page 0).
    pub relay: RelayEvidence,
    /// Whether rounds remain after these.
    pub more: bool,
}

pub(super) type Rounds = Vec<Vec<Option<SignedMessage>>>;

/// The commitment a member makes to its evidence.
pub(super) fn evidence_digest(
    seed: &[u8; 32],
    rounds: &Rounds,
    relay: &RelayEvidence,
) -> sha256::Hash {
    (
        "fedimint/bolt12/mpc-evidence/v2",
        *seed,
        rounds.clone(),
        relay.clone(),
    )
        .consensus_hash()
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
    /// Active channels of the run in progress, for `receive` and `relay`.
    /// Cleared immediately once `run_ends` resolves so local evidence is
    /// frozen before committing.
    channels: Mutex<Option<Arc<Channels>>>,
    /// Read-only handle retained past `run_ends` for `serve_packets` so
    /// lagging honest relays can still fetch cached outbox packets without
    /// race-induced false `relay_missing` witnesses. Replaced only when a new
    /// run starts.
    outbox_channels: Mutex<Option<Arc<Channels>>>,
    api: DynModuleApi,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Worker").finish_non_exhaustive()
    }
}

enum RunOutcome {
    Completed(Vec<PoolShare>, ApiTransport),
    Aborted(anyhow::Error),
    ConsensusEnded,
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
            outbox_channels: Mutex::new(None),
            api: api.clone(),
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

    fn active_channels(&self, run: u64) -> Result<Arc<Channels>> {
        self.channels
            .lock()
            .expect("not poisoned")
            .clone()
            .filter(|channels| channels.run() == run)
            .context("This guardian is not in that run")
    }

    fn outbox_channels(&self, run: u64) -> Result<Arc<Channels>> {
        self.outbox_channels
            .lock()
            .expect("not poisoned")
            .clone()
            .filter(|channels| channels.run() == run)
            .context("This guardian is not in that run")
    }

    /// Hand a packet from the endpoint to the run in progress.
    pub fn receive(&self, packet: &MpcPacket) -> Result<()> {
        self.active_channels(packet.run)?.receive(packet)
    }

    /// Serve cached encrypted packets for an authenticated committee
    /// [`FetchRequest`]. Remains available after `run_ends` until the next run
    /// starts so staggered polling across guardians cannot trigger false relay
    /// witnesses.
    pub fn serve_packets(&self, request: &FetchRequest) -> Result<Vec<MpcPacket>> {
        self.outbox_channels(request.run)?.serve_packets(request)
    }

    /// Fetch and return `request.sender`'s encrypted packets for
    /// `request.recipient`, recording a witness if `sender` refuses.
    pub async fn relay(&self, request: &RelayRequest) -> Result<Vec<MpcPacket>> {
        let channels = self.active_channels(request.run)?;

        channels.relay_fetch(&self.api, request).await
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

        let (params, batch) = run_params(cfg, &active)?;
        let limits = ChannelLimits::for_run(params.parties(), params.degree(), batch);
        let channels = Channels::new(
            active.run,
            me,
            active.committee.clone(),
            limits,
            &seed,
            &private.transport_secret,
            &bolt12.transport_keys,
        )?;

        *self.channels.lock().expect("not poisoned") = Some(channels.clone());
        *self.outbox_channels.lock().expect("not poisoned") = Some(channels.clone());

        // Stop when consensus moves on, so evidence is ready in time.
        let outcome = tokio::select! {
            result = generate(cfg, me, api, &active, &seed, channels.clone()) => match result {
                Ok((submission, transport)) => RunOutcome::Completed(submission, transport),
                Err(err) => RunOutcome::Aborted(err),
            },
            () = run_ends(db, active.run) => RunOutcome::ConsensusEnded,
        };

        self.finish_run(db, active.run, *seed, &channels, outcome)
            .await
    }

    async fn finish_run(
        &self,
        db: &Database,
        run: u64,
        seed: [u8; 32],
        channels: &Channels,
        outcome: RunOutcome,
    ) -> Result<()> {
        match outcome {
            RunOutcome::Completed(submission, _transport) => {
                info!(target: LOG_MODULE_LNV2, run, "Finished a preimage generation run");

                // Publish our shares immediately so consensus does not wait on
                // slow final-round direct sends, while keeping channels and
                // background deliveries live until consensus ends the run.
                let mut dbtx = db.begin_transaction().await;
                dbtx.insert_entry(
                    &Bolt12PoolLocalRunKey(run),
                    &LocalRun {
                        seed,
                        submission: Some(submission.clone()),
                        evidence: None,
                    },
                )
                .await;
                dbtx.commit_tx_result().await?;

                run_ends(db, run).await;

                // Stop receiving/relaying so evidence is frozen; `outbox_channels`
                // stays live for read-only `serve_packets` until the next run.
                *self.channels.lock().expect("not poisoned") = None;

                if db
                    .begin_transaction_nc()
                    .await
                    .get_value(&Bolt12PoolAbandonedKey(run))
                    .await
                    .is_some()
                {
                    save_evidence(db, run, seed, Some(submission), channels).await?;
                }
            }
            RunOutcome::Aborted(err) => {
                warn!(target: LOG_MODULE_LNV2, run, err = %format!("{err:#}"), "Preimage generation run aborted");

                // Freeze receive/relay before persisting evidence so our
                // commitment matches what we serve, while `outbox_channels`
                // keeps serving cached packets until the next run starts.
                *self.channels.lock().expect("not poisoned") = None;

                save_evidence(db, run, seed, None, channels).await?;
            }
            RunOutcome::ConsensusEnded => {
                warn!(target: LOG_MODULE_LNV2, run, "Consensus ended the run");

                *self.channels.lock().expect("not poisoned") = None;

                save_evidence(db, run, seed, None, channels).await?;
            }
        }

        Ok(())
    }
}

/// Persist this guardian's transcript, relay evidence, and evidence commitment
/// for an aborted or abandoned run.
async fn save_evidence(
    db: &Database,
    run: u64,
    seed: [u8; 32],
    submission: Option<Vec<PoolShare>>,
    channels: &Channels,
) -> Result<()> {
    let rounds = channels.transcript();
    let relay = channels.relay_evidence();
    let evidence = evidence_digest(&seed, &rounds, &relay);

    let mut dbtx = db.begin_transaction().await;

    for (round, row) in rounds.into_iter().enumerate() {
        dbtx.insert_entry(&Bolt12PoolTranscriptKey(run, round as u64), &row)
            .await;
    }
    dbtx.insert_entry(&Bolt12PoolRelayEvidenceKey(run), &relay)
        .await;
    dbtx.insert_entry(
        &Bolt12PoolLocalRunKey(run),
        &LocalRun {
            seed,
            submission,
            evidence: Some(evidence),
        },
    )
    .await;

    dbtx.commit_tx_result().await?;

    Ok(())
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
        dbtx.remove_entry(&Bolt12PoolRelayEvidenceKey(run)).await;
        dbtx.remove_by_prefix(&Bolt12PoolTranscriptRunPrefix(run))
            .await;
    }

    let relay_runs: Vec<u64> = dbtx
        .find_by_prefix(&Bolt12PoolRelayEvidencePrefix)
        .await
        .map(|(key, _)| key.0)
        .collect()
        .await;

    for run in relay_runs.into_iter().filter(|run| !keep(*run)) {
        dbtx.remove_entry(&Bolt12PoolRelayEvidenceKey(run)).await;
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
) -> Result<(Vec<PoolShare>, ApiTransport)> {
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

    let shares = generated
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
        .collect();

    Ok((shares, transport))
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

        // Account for per-row and per-entry framing plus the 64-byte Schnorr
        // signature so encoded pages stay strictly below `max_evidence_page_hex`.
        bytes = bytes.saturating_add(8);
        for entry in row {
            bytes = bytes.saturating_add(match entry {
                Some(signed) => signed.message.len().saturating_add(80),
                None => 1,
            });
        }

        rounds.push(row.clone());
    }

    let relay = if from == 0 {
        dbtx.get_value(&Bolt12PoolRelayEvidenceKey(run))
            .await
            .unwrap_or_default()
    } else {
        RelayEvidence::default()
    };

    Ok(EvidencePage {
        seed: local.seed,
        more: rounds.len() < rows.len(),
        rounds,
        relay,
    })
}

pub(super) fn max_evidence_page_hex(committee_len: usize, limits: ChannelLimits) -> usize {
    let max_chunks = usize::try_from(limits.chunks).expect("bounded by MAX_CHUNKS");
    let max_msg_wire = max_chunks.saturating_mul(CHUNK);
    let max_row = committee_len.saturating_mul(max_msg_wire.saturating_add(128));
    let fault_meta = committee_len
        .saturating_mul(max_chunks.saturating_add(2))
        .saturating_mul(160);
    let relay_meta = MAX_RELAY_WITNESSES.saturating_mul(16);
    let raw_limit = EVIDENCE_PAGE_BYTES
        .saturating_add(max_row)
        .saturating_add(limits.fault_bytes)
        .saturating_add(fault_meta)
        .saturating_add(relay_meta)
        .saturating_add(65_536);

    raw_limit.saturating_mul(2)
}

fn max_member_evidence_bytes(committee_len: usize, limits: ChannelLimits) -> usize {
    let max_chunks = usize::try_from(limits.chunks).expect("bounded by MAX_CHUNKS");
    let max_row = committee_len.saturating_mul(max_chunks.saturating_mul(CHUNK));
    max_row.saturating_mul(6).max(MIN_MEMBER_EVIDENCE_BYTES)
}

fn validate_relay_evidence(
    relay: &RelayEvidence,
    committee_len: usize,
    limits: ChannelLimits,
) -> Result<()> {
    ensure!(
        relay.relay_missing.len() <= MAX_RELAY_WITNESSES,
        "Too many relay witnesses in evidence"
    );
    ensure!(
        relay.faults.len() <= committee_len,
        "Too many transport faults in evidence"
    );

    let mut total_fault_bytes = 0usize;
    for fault in &relay.faults {
        ensure!(
            fault.max_ciphertext_len() <= MAX_FAULT_CIPHERTEXT_LEN,
            "Oversized ciphertext in transport fault evidence"
        );
        total_fault_bytes = total_fault_bytes.saturating_add(fault.ciphertext_bytes());
        ensure!(
            total_fault_bytes <= limits.fault_bytes,
            "Transport fault evidence exceeds byte cap"
        );
    }

    Ok(())
}

/// A member's evidence: from our database for ourselves, from its endpoint
/// otherwise.
async fn fetch_evidence(
    db: &Database,
    api: &DynModuleApi,
    me: PeerId,
    member: PeerId,
    run: &PoolRun,
    limits: ChannelLimits,
) -> Result<([u8; 32], Rounds, RelayEvidence)> {
    let committee_len = run.committee.len();
    let max_page_hex = max_evidence_page_hex(committee_len, limits);
    let max_total_bytes = max_member_evidence_bytes(committee_len, limits);
    let mut seed = None;
    let mut rounds = vec![];
    let mut relay = None;
    let mut total_bytes = 0usize;

    loop {
        let page = if member == me {
            serve_evidence(db, run.run, rounds.len() as u64).await?
        } else {
            let hex: String = api
                .request_single_peer(
                    BOLT12_MPC_EVIDENCE_ENDPOINT.to_owned(),
                    ApiRequestErased::new((run.run, rounds.len() as u64)),
                    member,
                )
                .await?;

            ensure!(hex.len() <= max_page_hex, "Oversized evidence page");

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

        for row in &page.rounds {
            ensure!(
                row.len() <= committee_len,
                "Evidence round row exceeds committee size"
            );
            for signed in row.iter().flatten() {
                total_bytes = total_bytes.saturating_add(signed.message.len());
                ensure!(
                    total_bytes <= max_total_bytes,
                    "Evidence exceeds total byte cap"
                );
            }
        }

        if relay.is_none() {
            validate_relay_evidence(&page.relay, committee_len, limits)?;
            relay = Some(page.relay);
        }
        seed = Some(page.seed);
        rounds.extend(page.rounds);

        ensure!(rounds.len() <= MAX_ROUNDS, "Too many rounds of evidence");

        if !page.more {
            break;
        }
    }

    Ok((
        seed.context("No evidence")?,
        rounds,
        relay.unwrap_or_default(),
    ))
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

        let ready = abandoned.all_evidence_committed()
            || now
                >= abandoned
                    .abandoned_at
                    .saturating_add(EVIDENCE_WINDOW + JUDGE_MARGIN);

        if !ready || abandoned.is_stale(now) {
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
                .take(run.committee.len())
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

/// Convict any sender proven to have sent a corrupt, conflicting, or
/// improperly-signed transport packet (verified against its outer envelope
/// signature and revealed seed-derived ephemeral key).
fn collect_transport_culprits(
    run: &PoolRun,
    keys: &std::collections::BTreeMap<PeerId, fedimint_core::secp256k1::PublicKey>,
    evidence: &[Option<Evidence>],
    faults_by_member: &[(PeerId, RelayEvidence)],
    max_chunks: u32,
) -> BTreeSet<PeerId> {
    let mut culprits = BTreeSet::new();

    for (recipient, relay) in faults_by_member {
        let Some(recipient_pk) = keys.get(recipient) else {
            continue;
        };
        for fault in &relay.faults {
            let Some(sender) = fault.sender() else {
                continue;
            };
            let Some(sender_pos) = run.position(sender).map(usize::from) else {
                continue;
            };
            let Some(sender_pk) = keys.get(&sender) else {
                continue;
            };
            let Some(sender_ev) = evidence.get(sender_pos).and_then(Option::as_ref) else {
                continue;
            };

            if verify_transport_fault_convicts(
                run.run,
                (sender, sender_pk),
                (*recipient, recipient_pk),
                &sender_ev.seed,
                fault,
                max_chunks,
            ) {
                culprits.insert(sender);
            }
        }
    }

    culprits
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
    let keys = cfg
        .consensus
        .bolt12
        .as_ref()
        .context("Federated BOLT12 is disabled")?
        .transport_keys
        .clone();
    let (params, batch) = run_params(cfg, run)?;
    let limits = ChannelLimits::for_run(params.parties(), params.degree(), batch);

    let mut evidence = Vec::with_capacity(run.committee.len());
    let mut faults_by_member: Vec<(PeerId, RelayEvidence)> =
        Vec::with_capacity(run.committee.len());

    for member in &run.committee {
        let Some(digest) = abandoned.evidence.get(member) else {
            evidence.push(None);
            continue;
        };

        // Evidence we cannot fetch, or that does not match the commitment,
        // counts as withheld.
        let fetched = match fetch_evidence(db, api, me, *member, run, limits).await {
            Ok((seed, rounds, relay)) if evidence_digest(&seed, &rounds, &relay) == *digest => {
                let relay_missing: BTreeSet<(usize, usize, u64)> = relay
                    .relay_missing
                    .iter()
                    .filter_map(|&(sender, recipient, round)| {
                        Some((
                            usize::from(run.position(sender)?),
                            usize::from(run.position(recipient)?),
                            round,
                        ))
                    })
                    .collect();

                faults_by_member.push((*member, relay));

                Some(Evidence {
                    seed,
                    received: signed_messages(cfg, run, *member, &rounds)?,
                    relay_missing,
                })
            }
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

    let context = run_context(cfg, run)?;
    let run_cloned = run.clone();

    // Replaying every member and verifying transport faults is CPU-intensive.
    let (found, transport_culprits) = runtime::spawn_blocking(move || {
        let transport_culprits = collect_transport_culprits(
            &run_cloned,
            &keys,
            &evidence,
            &faults_by_member,
            limits.chunks,
        );
        let circuit = direct::circuit(params, batch)?;
        let found = runtime::block_on(judge(
            params, batch, &circuit, &context, &evidence, &submitted,
        ))?;

        Ok::<_, anyhow::Error>((found, transport_culprits))
    })
    .await?;

    let member = |position: usize| run.committee[position];

    let culprits: BTreeSet<PeerId> = found
        .culprits
        .into_iter()
        .map(member)
        .chain(transport_culprits)
        .collect();

    // Disputes are only reported when nobody is provably at fault.
    let disputes: BTreeSet<(PeerId, PeerId)> = if culprits.is_empty() {
        found
            .disputes
            .into_iter()
            .map(|(a, b)| (member(a).min(member(b)), member(a).max(member(b))))
            .collect()
    } else {
        BTreeSet::new()
    };

    Ok(PoolVerdict {
        culprits: culprits.into_iter().collect(),
        disputes: disputes.into_iter().collect(),
    })
}
