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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use fedimint_api_client::api::{DynModuleApi, FederationApiExt as _};
use fedimint_core::bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, Message, PublicKey, SECP256K1};
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::{NumPeersExt as _, PeerId, runtime};
use fedimint_lnv2_common::bolt12::{
    AbandonedRun, POOL_RUN_TIMEOUT, PoolRun, PoolShare, PoolVerdict, pool_share_binding,
};
use fedimint_lnv2_common::config::LightningConfig;
use fedimint_lnv2_common::endpoint_constants::BOLT12_MPC_EVIDENCE_ENDPOINT;
use fedimint_logging::LOG_MODULE_LNV2;
use futures::StreamExt as _;
use futures::future::join_all;
use mpc::direct;
use mpc::engine::Params;
use mpc::replay::{Evidence, Received, judge};
use rand::RngCore as _;
use rand::rngs::OsRng;
use tracing::{info, warn};
use zeroize::Zeroizing;

use super::transport::{
    ApiTransport, CHUNK, ChannelLimits, Channels, FetchRequest, MAX_FAULT_CIPHERTEXT_LEN,
    MAX_RELAY_WITNESSES, MpcPacket, RelayRequest, verify_message, verify_r0_ephemeral_fault,
    verify_transport_fault_convicts,
};
use crate::db::{
    Bolt12PoolAbandonedKey, Bolt12PoolAbandonedPrefix, Bolt12PoolLocalRunKey,
    Bolt12PoolLocalRunPrefix, Bolt12PoolLocalVerdictKey, Bolt12PoolLocalVerdictPrefix,
    Bolt12PoolRelayEvidenceKey, Bolt12PoolRelayEvidencePrefix, Bolt12PoolRunKey,
    Bolt12PoolTranscriptKey, Bolt12PoolTranscriptRunPrefix, Bolt12PoolVerdictKey, LocalRun,
    RelayEvidence, SignedMessage, UnixTimeVotePrefix,
};

const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Target decoded evidence payload bytes per page. Sized so every hex-encoded
/// page stays comfortably below the 10 MiB WebSocket response cap even on page
/// 0 (which includes `RelayEvidence`) and when a single message is up to
/// `1.48 MiB`.
const EVIDENCE_PAGE_BYTES: usize = 512 * 1024;

/// Longest hex-encoded [`EvidenceRequest`] accepted by the evidence endpoint.
pub const MAX_EVIDENCE_REQUEST_HEX: usize = 512;

/// Per-page timeout when fetching a peer's evidence.
const EVIDENCE_PAGE_TIMEOUT: Duration = Duration::from_secs(10);

/// Retries per evidence page on transient network/timeout errors.
const EVIDENCE_PAGE_ATTEMPTS: usize = 3;

const EVIDENCE_RETRY_BACKOFF: Duration = Duration::from_millis(250);

/// Total wall-clock timeout for fetching all evidence pages of one committee
/// member so a stalling peer cannot starve judging or exhaust `JUDGE_TIMEOUT`.
const EVIDENCE_MEMBER_TIMEOUT: Duration = Duration::from_secs(60);

/// Minimum total decoded transcript byte cap per member for small runs.
const MIN_MEMBER_EVIDENCE_BYTES: usize = 64 * 1024 * 1024;

/// Authenticated request from any federation guardian asking a committee member
/// for one page of its evidence about an abandoned run.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable)]
pub struct EvidenceRequest {
    pub run: u64,
    pub requester: PeerId,
    pub from_round: u64,
    pub from_peer: u16,
    pub signature: Signature,
}

impl EvidenceRequest {
    fn digest(run: u64, requester: PeerId, from_round: u64, from_peer: u16) -> Message {
        let hash: sha256::Hash = (
            "fedimint/bolt12/mpc-evidence-req/v1",
            run,
            requester,
            from_round,
            from_peer,
        )
            .consensus_hash();

        Message::from_digest(hash.to_byte_array())
    }

    pub fn new(
        run: u64,
        requester: PeerId,
        from_round: u64,
        from_peer: u16,
        signing_key: &Keypair,
    ) -> Self {
        let signature = SECP256K1.sign_schnorr(
            &Self::digest(run, requester, from_round, from_peer),
            signing_key,
        );

        Self {
            run,
            requester,
            from_round,
            from_peer,
            signature,
        }
    }

    pub fn verify(&self, requester_pk: &PublicKey) -> bool {
        SECP256K1
            .verify_schnorr(
                &self.signature,
                &Self::digest(self.run, self.requester, self.from_round, self.from_peer),
                &requester_pk.x_only_public_key().0,
            )
            .is_ok()
    }
}

/// Decode an [`EvidenceRequest`] from its hex form.
pub fn decode_evidence_request(hex: &str) -> Result<EvidenceRequest> {
    if hex.len() > MAX_EVIDENCE_REQUEST_HEX {
        bail!("Oversized evidence request");
    }

    Ok(EvidenceRequest::consensus_decode_hex(
        hex,
        &ModuleRegistry::default(),
    )?)
}

/// A page of a member's evidence, as the evidence endpoint returns it.
#[derive(Debug, Encodable, Decodable)]
pub struct EvidencePage {
    pub seed: [u8; 32],
    /// Total number of transcript rounds recorded for this run.
    pub total_rounds: u64,
    /// Non-empty `(round, position, signed_message)` entries from the requested
    /// cursor onward, in strictly ascending `(round, position)` order.
    pub entries: Vec<(u64, u16, SignedMessage)>,
    /// Relay witnesses, round-0 ephemeral proofs, and transport faults
    /// (populated only on page 0 when `(from_round, from_peer) == (0, 0)`).
    pub relay: RelayEvidence,
    /// Next `(round, position)` cursor if more entries remain.
    pub next_cursor: Option<(u64, u16)>,
}

pub(super) type Rounds = Vec<Vec<Option<SignedMessage>>>;

/// The commitment a member makes to its evidence.
pub(super) fn evidence_digest(
    seed: &[u8; 32],
    rounds: &Rounds,
    relay: &RelayEvidence,
) -> sha256::Hash {
    (
        "fedimint/bolt12/mpc-evidence/v3",
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

/// Tight upper bound on rounds an honest MPC execution for `(params, batch)`
/// can ever produce.
fn max_rounds_for_run(params: Params, batch: usize) -> Result<usize> {
    let circuit = direct::circuit(params, batch)?;
    let depth = circuit.schedule().depth();
    Ok(depth.saturating_mul(2).saturating_add(128))
}

async fn consensus_unix_time(cfg: &LightningConfig, db: &Database) -> u64 {
    let num_peers = cfg.consensus.tpe_pks.to_num_peers();
    let mut dbtx = db.begin_transaction_nc().await;
    let mut times = dbtx
        .find_by_prefix(&UnixTimeVotePrefix)
        .await
        .map(|entry| entry.1)
        .collect::<Vec<u64>>()
        .await;

    times.sort_unstable();
    times.reverse();

    times.get(num_peers.threshold() - 1).copied().unwrap_or(0)
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
        let gen_cfg = cfg.clone();
        let gen_db = db.clone();
        let gen_api = api.clone();

        task_group.spawn_cancellable("bolt12 preimage generation", async move {
            loop {
                if let Err(err) = this.tick(&gen_cfg, me, &gen_db, &gen_api).await {
                    warn!(target: LOG_MODULE_LNV2, err = %format!("{err:#}"), "Preimage generation failed");
                }

                sleep(POLL_INTERVAL).await;
            }
        });

        // Judging runs in an independent task so slow or adversarial evidence
        // fetches can never block generation ticks.
        task_group.spawn_cancellable("bolt12 abandoned run judge", async move {
            loop {
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

    /// Serve a bounded page of cached encrypted packets for an authenticated
    /// committee [`FetchRequest`]. Remains available after `run_ends` until
    /// the next run starts so staggered polling across guardians cannot trigger
    /// false relay witnesses.
    pub fn serve_packets(&self, request: &FetchRequest) -> Result<(u32, Vec<MpcPacket>)> {
        self.outbox_channels(request.run)?.serve_packets(request)
    }

    /// Fetch and return a bounded page of `request.sender`'s encrypted packets
    /// for `request.recipient`, recording a witness if `sender` refuses.
    pub async fn relay(&self, request: &RelayRequest) -> Result<(u32, Vec<MpcPacket>)> {
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
                transcript_rounds: 0,
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

        self.finish_run(db, active.run, seed, &channels, outcome)
            .await
    }

    async fn finish_run(
        &self,
        db: &Database,
        run: u64,
        seed: Zeroizing<[u8; 32]>,
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
                        seed: *seed,
                        submission: Some(submission.clone()),
                        evidence: None,
                        transcript_rounds: 0,
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
                    save_evidence(db, run, &seed, Some(submission), channels).await?;
                }
            }
            RunOutcome::Aborted(err) => {
                warn!(target: LOG_MODULE_LNV2, run, err = %format!("{err:#}"), "Preimage generation run aborted");

                // Freeze receive/relay before persisting evidence so our
                // commitment matches what we serve, while `outbox_channels`
                // keeps serving cached packets until the next run starts.
                *self.channels.lock().expect("not poisoned") = None;

                save_evidence(db, run, &seed, None, channels).await?;
            }
            RunOutcome::ConsensusEnded => {
                warn!(target: LOG_MODULE_LNV2, run, "Consensus ended the run");

                *self.channels.lock().expect("not poisoned") = None;

                save_evidence(db, run, &seed, None, channels).await?;
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
    seed: &Zeroizing<[u8; 32]>,
    submission: Option<Vec<PoolShare>>,
    channels: &Channels,
) -> Result<()> {
    let rounds = channels.transcript();
    let relay = channels.relay_evidence();
    let transcript_rounds = u64::try_from(rounds.len())?;
    let evidence = evidence_digest(seed, &rounds, &relay);

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
            seed: **seed,
            submission,
            evidence: Some(evidence),
            transcript_rounds,
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

/// Lazily stream one page of this guardian's evidence about abandoned run
/// `run`, starting at `(from_round, from_peer)`. Refused unless consensus has
/// abandoned the run.
pub async fn serve_evidence(
    db: &Database,
    run: u64,
    from_round: u64,
    from_peer: u16,
) -> Result<EvidencePage> {
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

    let mut entries = Vec::new();
    let mut bytes = 0usize;
    let mut next_cursor = None;

    {
        let mut stream = dbtx
            .find_by_range(
                Bolt12PoolTranscriptKey(run, from_round)..Bolt12PoolTranscriptKey(run, u64::MAX),
            )
            .await;

        'outer: while let Some((key, row)) = stream.next().await {
            let round = key.1;
            let start_pos = if round == from_round {
                usize::from(from_peer)
            } else {
                0
            };

            for (pos, slot) in row.into_iter().enumerate().skip(start_pos) {
                let Some(signed) = slot else {
                    continue;
                };
                let pos_u16 = u16::try_from(pos).expect("committee position fits in u16");
                if bytes >= EVIDENCE_PAGE_BYTES {
                    next_cursor = Some((round, pos_u16));
                    break 'outer;
                }
                bytes = bytes.saturating_add(signed.message.len().saturating_add(80));
                entries.push((round, pos_u16, signed));
            }
        }
    }

    let relay = if from_round == 0 && from_peer == 0 {
        dbtx.get_value(&Bolt12PoolRelayEvidenceKey(run))
            .await
            .unwrap_or_default()
    } else {
        RelayEvidence::default()
    };

    Ok(EvidencePage {
        seed: local.seed,
        total_rounds: local.transcript_rounds,
        entries,
        relay,
        next_cursor,
    })
}

pub(super) fn max_evidence_page_hex(committee_len: usize, limits: ChannelLimits) -> usize {
    let max_chunks = usize::try_from(limits.chunks).expect("bounded by MAX_CHUNKS");
    let max_single_msg = max_chunks.saturating_mul(CHUNK).saturating_add(128);
    let fault_meta = committee_len
        .saturating_mul(max_chunks.saturating_add(2))
        .saturating_mul(200);
    let r0_meta = committee_len.saturating_mul(MAX_FAULT_CIPHERTEXT_LEN.saturating_add(200));
    let relay_meta = MAX_RELAY_WITNESSES.saturating_mul(16);
    let raw_limit = EVIDENCE_PAGE_BYTES
        .saturating_add(max_single_msg)
        .saturating_add(limits.fault_bytes)
        .saturating_add(fault_meta)
        .saturating_add(r0_meta)
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
    ensure!(
        relay.r0_packets.len() <= committee_len,
        "Too many round-0 packets in evidence"
    );

    for r0 in &relay.r0_packets {
        ensure!(
            r0.ciphertext.len() <= MAX_FAULT_CIPHERTEXT_LEN,
            "Oversized round-0 packet in evidence"
        );
    }

    let mut total_fault_bytes = 0usize;
    for fault in &relay.faults {
        ensure!(
            fault.max_chunk_ciphertext_len() <= MAX_FAULT_CIPHERTEXT_LEN,
            "Oversized ciphertext in transport fault evidence"
        );
        ensure!(
            fault.max_equivocation_msg_len() <= limits.message,
            "Oversized equivocation message in transport fault evidence"
        );
        total_fault_bytes = total_fault_bytes.saturating_add(fault.ciphertext_bytes());
        ensure!(
            total_fault_bytes <= limits.fault_bytes,
            "Transport fault evidence exceeds byte cap"
        );
    }

    Ok(())
}

/// Request one authenticated evidence page from `member`, retrying transient
/// RPC/timeout errors.
async fn fetch_evidence_page(
    api: &DynModuleApi,
    me: PeerId,
    signing_key: &Keypair,
    member: PeerId,
    run: u64,
    cursor: (u64, u16),
    max_page_hex: usize,
) -> Result<EvidencePage> {
    let req =
        EvidenceRequest::new(run, me, cursor.0, cursor.1, signing_key).consensus_encode_to_hex();
    let mut last_err = anyhow::anyhow!("Evidence fetch failed");

    for attempt in 0..EVIDENCE_PAGE_ATTEMPTS {
        let fetched = runtime::timeout(
            EVIDENCE_PAGE_TIMEOUT,
            api.request_single_peer::<String>(
                BOLT12_MPC_EVIDENCE_ENDPOINT.to_owned(),
                ApiRequestErased::new(req.clone()),
                member,
            ),
        )
        .await;

        match fetched {
            Ok(Ok(hex)) => {
                ensure!(hex.len() <= max_page_hex, "Oversized evidence page");
                return Ok(EvidencePage::consensus_decode_hex(
                    &hex,
                    &ModuleRegistry::default(),
                )?);
            }
            Ok(Err(err)) => {
                last_err = err.into();
            }
            Err(_) => {
                last_err = anyhow::anyhow!("Evidence page request timed out");
            }
        }

        if attempt + 1 < EVIDENCE_PAGE_ATTEMPTS {
            sleep(EVIDENCE_RETRY_BACKOFF).await;
        }
    }

    Err(last_err)
}

/// Fetch one committee member's evidence, enforcing strict cursor progress,
/// per-entry signature overhead accounting, and total byte/round/time caps.
#[allow(clippy::too_many_arguments)]
async fn fetch_evidence(
    db: &Database,
    api: &DynModuleApi,
    me: PeerId,
    signing_key: &Keypair,
    member: PeerId,
    run: &PoolRun,
    limits: ChannelLimits,
    max_rounds: usize,
) -> Result<([u8; 32], Rounds, RelayEvidence)> {
    runtime::timeout(
        EVIDENCE_MEMBER_TIMEOUT,
        fetch_evidence_inner(db, api, me, signing_key, member, run, limits, max_rounds),
    )
    .await
    .context("Timed out fetching member evidence")?
}

#[allow(clippy::too_many_arguments)]
async fn fetch_evidence_inner(
    db: &Database,
    api: &DynModuleApi,
    me: PeerId,
    signing_key: &Keypair,
    member: PeerId,
    run: &PoolRun,
    limits: ChannelLimits,
    max_rounds: usize,
) -> Result<([u8; 32], Rounds, RelayEvidence)> {
    let committee_len = run.committee.len();
    let committee_u16 = u16::try_from(committee_len).expect("committees are small");
    let max_page_hex = max_evidence_page_hex(committee_len, limits);
    let max_total_bytes = max_member_evidence_bytes(committee_len, limits);

    let mut seed = None;
    let mut total_rounds: Option<usize> = None;
    let mut rounds: Rounds = vec![];
    let mut relay = None;
    let mut total_bytes = 0usize;
    let mut cursor = (0u64, 0u16);

    loop {
        let page = if member == me {
            serve_evidence(db, run.run, cursor.0, cursor.1).await?
        } else {
            fetch_evidence_page(api, me, signing_key, member, run.run, cursor, max_page_hex).await?
        };

        ensure!(
            seed.is_none_or(|s| s == page.seed),
            "The seed changed between pages"
        );
        let page_total_rounds = usize::try_from(page.total_rounds)?;
        ensure!(
            page_total_rounds <= max_rounds,
            "Evidence declares too many rounds"
        );
        ensure!(
            total_rounds.is_none_or(|n| n == page_total_rounds),
            "Total rounds changed between pages"
        );

        if rounds.is_empty() && page_total_rounds > 0 {
            rounds = vec![vec![None; committee_len]; page_total_rounds];
        }

        let mut page_bytes = 0usize;
        let mut last_seen: Option<(u64, u16)> = None;

        for (round, pos, signed) in page.entries {
            let round_idx = usize::try_from(round)?;
            ensure!(
                round_idx < page_total_rounds && pos < committee_u16,
                "Evidence entry out of bounds"
            );
            ensure!(
                (round, pos) >= cursor && last_seen.is_none_or(|prev| (round, pos) > prev),
                "Evidence entries are out of order"
            );

            let entry_bytes = signed.message.len().saturating_add(80);
            page_bytes = page_bytes.saturating_add(entry_bytes);
            total_bytes = total_bytes.saturating_add(entry_bytes);
            ensure!(
                total_bytes <= max_total_bytes,
                "Evidence exceeds total byte cap"
            );

            rounds[round_idx][usize::from(pos)] = Some(signed);
            last_seen = Some((round, pos));
        }

        if relay.is_none() {
            validate_relay_evidence(&page.relay, committee_len, limits)?;
            relay = Some(page.relay);
        }
        seed = Some(page.seed);
        total_rounds = Some(page_total_rounds);

        match page.next_cursor {
            Some(next) => {
                ensure!(
                    usize::try_from(next.0)? < page_total_rounds && next.1 < committee_u16,
                    "Evidence next_cursor out of bounds"
                );
                ensure!(
                    last_seen.is_some_and(|prev| next > prev),
                    "Evidence next_cursor did not advance"
                );
                ensure!(
                    page_bytes >= EVIDENCE_PAGE_BYTES,
                    "Evidence page made insufficient progress"
                );
                cursor = next;
            }
            None => break,
        }
    }

    Ok((
        seed.context("No evidence")?,
        rounds,
        relay.unwrap_or_default(),
    ))
}

/// Judge abandoned runs whose evidence window has closed according to the
/// consensus clock and that this guardian has not judged yet.
async fn judge_abandoned(
    cfg: &LightningConfig,
    me: PeerId,
    db: &Database,
    api: &DynModuleApi,
) -> Result<()> {
    let now = consensus_unix_time(cfg, db).await;
    if now == 0 {
        return Ok(());
    }

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

        if abandoned.collecting_evidence(now) || abandoned.is_stale(now) {
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
    keys: &BTreeMap<PeerId, PublicKey>,
    run: &PoolRun,
    member: PeerId,
    rounds: &Rounds,
) -> Received {
    rounds
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
        .collect()
}

/// Convict any sender proven to have advertised a fake Round-0 ephemeral key
/// or sent a corrupt, conflicting, equivocating, or improperly-signed
/// transport packet.
fn collect_transport_culprits(
    run: &PoolRun,
    keys: &BTreeMap<PeerId, PublicKey>,
    evidence: &[Option<Evidence>],
    faults_by_member: &[(PeerId, RelayEvidence)],
    max_chunks: u32,
) -> BTreeSet<PeerId> {
    let mut culprits = BTreeSet::new();
    let mut lied_r0_eph: BTreeSet<(PeerId, PeerId)> = BTreeSet::new();

    // First verify every member's advertised Round-0 ephemeral keys against
    // their revealed seeds. A peer that lied about its `recv_ephemeral_pk` is
    // convicted and cannot use Round >= 1 decryption failures to frame the
    // honest sender that encrypted to that fake key.
    for (receiver, relay) in faults_by_member {
        for r0 in &relay.r0_packets {
            let Some(sender_pos) = run.position(r0.sender).map(usize::from) else {
                continue;
            };
            let Some(sender_pk) = keys.get(&r0.sender) else {
                continue;
            };
            let Some(sender_ev) = evidence.get(sender_pos).and_then(Option::as_ref) else {
                continue;
            };

            if verify_r0_ephemeral_fault(
                run.run,
                (r0.sender, sender_pk),
                *receiver,
                &sender_ev.seed,
                r0,
            ) {
                culprits.insert(r0.sender);
                lied_r0_eph.insert((r0.sender, *receiver));
            }
        }
    }

    for (recipient, relay) in faults_by_member {
        let Some(recipient_pk) = keys.get(recipient) else {
            continue;
        };
        let Some(recipient_pos) = run.position(*recipient).map(usize::from) else {
            continue;
        };
        let Some(recipient_ev) = evidence.get(recipient_pos).and_then(Option::as_ref) else {
            continue;
        };

        for fault in &relay.faults {
            let Some(sender) = fault.sender() else {
                continue;
            };
            if lied_r0_eph.contains(&(*recipient, sender)) {
                continue;
            }
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
                &recipient_ev.seed,
                fault,
                max_chunks,
            ) {
                culprits.insert(sender);
            }
        }
    }

    culprits
}

type MemberEvidence = ([u8; 32], Vec<Vec<Option<SignedMessage>>>, RelayEvidence);
type RawFetchedEvidence = Vec<(PeerId, Option<(sha256::Hash, MemberEvidence)>)>;

#[allow(clippy::too_many_arguments)]
fn evaluate_verdict(
    run: &PoolRun,
    keys: &BTreeMap<PeerId, PublicKey>,
    params: mpc::engine::Params,
    batch: usize,
    context: &[u8],
    limits: ChannelLimits,
    raw_fetched: RawFetchedEvidence,
    submitted: &[bool],
) -> Result<(mpc::replay::Verdict, BTreeSet<PeerId>)> {
    let mut evidence = Vec::with_capacity(run.committee.len());
    let mut faults_by_member: Vec<(PeerId, RelayEvidence)> =
        Vec::with_capacity(run.committee.len());

    for (member, entry) in raw_fetched {
        let parsed = match entry {
            Some((digest, (seed, rounds, relay)))
                if evidence_digest(&seed, &rounds, &relay) == digest =>
            {
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

                let received = signed_messages(keys, run, member, &rounds);
                faults_by_member.push((member, relay));

                Some(Evidence {
                    seed,
                    received,
                    relay_missing,
                })
            }
            Some(_) => {
                warn!(target: LOG_MODULE_LNV2, run = run.run, %member, "Evidence does not match its commitment");
                None
            }
            None => None,
        };
        evidence.push(parsed);
    }

    let transport_culprits =
        collect_transport_culprits(run, keys, &evidence, &faults_by_member, limits.chunks);
    let circuit = direct::circuit(params, batch)?;
    let found = runtime::block_on(judge(
        params, batch, &circuit, context, &evidence, submitted,
    ))?;

    Ok((found, transport_culprits))
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
    let private = cfg
        .private
        .bolt12
        .as_ref()
        .context("Missing private BOLT12 configuration")?;
    let signing_key = Keypair::from_secret_key(SECP256K1, &private.transport_secret);
    let (params, batch) = run_params(cfg, run)?;
    let limits = ChannelLimits::for_run(params.parties(), params.degree(), batch);
    let max_rounds = max_rounds_for_run(params, batch)?;

    // Fetch all committee members' evidence in parallel with bounded timeouts.
    let raw_fetched = join_all(run.committee.iter().map(|&member| {
        let digest = abandoned.evidence.get(&member).copied();
        async move {
            let Some(digest) = digest else {
                return (member, None);
            };
            match fetch_evidence(db, api, me, &signing_key, member, run, limits, max_rounds).await {
                Ok(data) => (member, Some((digest, data))),
                Err(err) => {
                    warn!(target: LOG_MODULE_LNV2, run = run.run, %member, err = %format!("{err:#}"), "Could not fetch evidence");
                    (member, None)
                }
            }
        }
    }))
    .await;

    let submitted: Vec<bool> = run
        .committee
        .iter()
        .map(|member| abandoned.submitted.contains(member))
        .collect();

    let context = run_context(cfg, run)?;
    let run_cloned = run.clone();

    // Hashing transcripts, verifying all inner Schnorr signatures, verifying
    // transport faults, and replaying every member are all CPU-intensive: keep
    // all of them off the async executor.
    let (found, transport_culprits) = runtime::spawn_blocking(move || {
        evaluate_verdict(
            &run_cloned,
            &keys,
            params,
            batch,
            &context,
            limits,
            raw_fetched,
            &submitted,
        )
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
