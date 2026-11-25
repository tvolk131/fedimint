//! Consensus rules for the pool of generated preimages.
//!
//! A run starts when the pool is below its target. Its committee of `2f + 1`
//! guardians generates the preimages off consensus (see `worker`) and each
//! member submits its encrypted shares as a consensus item. Once every member
//! has submitted, the hashes a majority of members agree on enter the pool.
//!
//! A run that outlives `POOL_RUN_TIMEOUT` is abandoned and its results are
//! never used. Its members then commit to their evidence, every guardian
//! replays the run from it and votes on who is to blame, and blame that
//! `f + 1` guardians agree on keeps guardians, or pairs of guardians, off
//! committees for a number of runs that doubles with each repeat.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, bail, ensure};
use fedimint_core::PeerId;
use fedimint_core::bitcoin::hashes::sha256;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_lnv2_common::LightningConsensusItem;
use fedimint_lnv2_common::bolt12::{
    AbandonedRun, Blame, Bolt12Config, MAX_POOL_TARGET, POOL_RUN_TIMEOUT, PoolItem, PoolRun,
    PoolShare, PoolVerdict, STICKY_COMMITTEE_RUNS, Sealed, SealedShare, StickyCommittee,
    pool_share_binding, quorum,
};
use fedimint_lnv2_common::config::LightningConfig;
use futures::StreamExt as _;
use tpe::verify_non_identity_ciphertext;

use crate::Lightning;
use crate::db::{
    Bolt12BlameKey, Bolt12BlamePrefix, Bolt12DisputeKey, Bolt12DisputePrefix, Bolt12PaymentHashKey,
    Bolt12PoolAbandonedKey, Bolt12PoolAbandonedPrefix, Bolt12PoolAbortKey,
    Bolt12PoolAbortRunPrefix, Bolt12PoolItemKey, Bolt12PoolItemPrefix, Bolt12PoolLocalRunKey,
    Bolt12PoolLocalVerdictKey, Bolt12PoolNextKey, Bolt12PoolRunCountKey, Bolt12PoolRunKey,
    Bolt12PoolStickyCommitteeKey, Bolt12PoolSubmissionKey, Bolt12PoolSubmissionRunPrefix,
    Bolt12PoolVerdictKey, Bolt12PoolVerdictRunPrefix,
};
use crate::metrics::{BOLT12_POOL_BLAME_TOTAL, BOLT12_POOL_ITEMS, BOLT12_POOL_RUNS_TOTAL};

/// Upper bound on backtracking steps when picking an undisputed committee so
/// large federations (`N >= 25`) can never stall consensus CPU.
const MAX_COMMITTEE_SEARCH_STEPS: usize = 4_096;

fn pool_config(cfg: &LightningConfig) -> Result<&Bolt12Config> {
    let bolt12 = cfg
        .consensus
        .bolt12
        .as_ref()
        .context("federated BOLT12 is disabled")?;

    ensure!(bolt12.pool_target > 0, "preimage generation is disabled");

    Ok(bolt12)
}

/// Generated preimages not yet reserved.
pub async fn pool_len(dbtx: &mut DatabaseTransaction<'_>) -> u64 {
    dbtx.find_by_prefix(&Bolt12PoolItemPrefix)
        .await
        .count()
        .await as u64
}

async fn abandoned_runs(dbtx: &mut DatabaseTransaction<'_>) -> Vec<AbandonedRun> {
    dbtx.find_by_prefix(&Bolt12PoolAbandonedPrefix)
        .await
        .map(|(_, abandoned)| abandoned)
        .collect()
        .await
}

/// The run to start at `now`, if the pool is below target, no run is in
/// progress, and no abandoned run is still being judged.
pub async fn run_to_start(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    now: u64,
) -> Option<u64> {
    let bolt12 = pool_config(cfg).ok()?;

    if dbtx.get_value(&Bolt12PoolRunKey).await.is_some()
        || pool_len(dbtx).await >= bolt12.pool_target.min(MAX_POOL_TARGET)
        || abandoned_runs(dbtx)
            .await
            .iter()
            .any(|abandoned| !abandoned.is_stale(now))
    {
        return None;
    }

    Some(dbtx.get_value(&Bolt12PoolRunCountKey).await.unwrap_or(0))
}

fn dispute_key(a: PeerId, b: PeerId) -> Bolt12DisputeKey {
    Bolt12DisputeKey(a.min(b), a.max(b))
}

fn is_disputed(disputes: &BTreeSet<(PeerId, PeerId)>, a: PeerId, b: PeerId) -> bool {
    disputes.contains(&(a.min(b), a.max(b)))
}

fn search_undisputed(
    start: usize,
    size: usize,
    conflict: &[Vec<bool>],
    chosen: &mut Vec<usize>,
    steps: &mut usize,
) -> bool {
    if chosen.len() == size {
        return true;
    }
    let n = conflict.len();
    if chosen.len() + (n - start) < size || *steps >= MAX_COMMITTEE_SEARCH_STEPS {
        return false;
    }

    for idx in start..n {
        if chosen.len() + (n - idx) < size || *steps >= MAX_COMMITTEE_SEARCH_STEPS {
            break;
        }
        *steps += 1;

        if chosen.iter().all(|&prev| !conflict[prev][idx]) {
            chosen.push(idx);
            if search_undisputed(idx + 1, size, conflict, chosen, steps) {
                return true;
            }
            chosen.pop();
        }
    }

    false
}

fn greedy_undisputed(size: usize, conflict: &[Vec<bool>]) -> Option<Vec<usize>> {
    let n = conflict.len();
    let mut alive = vec![true; n];
    let mut chosen = Vec::with_capacity(size);

    while chosen.len() < size {
        let next = (0..n).filter(|&u| alive[u]).min_by_key(|&u| {
            let residual_degree = (0..n).filter(|&v| alive[v] && conflict[u][v]).count();
            (residual_degree, u)
        })?;

        chosen.push(next);
        alive[next] = false;
        for (v, is_alive) in alive.iter_mut().enumerate() {
            if conflict[next][v] {
                *is_alive = false;
            }
        }
    }

    Some(chosen)
}

/// Pick `size` guardians from `candidates` with no disputed pair, ordering
/// lowest-offence, lowest-dispute-degree guardians first and bounding
/// backtracking so consensus CPU stays polynomial even at `N = 46`.
///
/// The returned committee preserves `candidates`' rotation order.
fn pick_undisputed(
    candidates: &[PeerId],
    size: usize,
    offences: &BTreeMap<PeerId, u32>,
    disputes: &BTreeSet<(PeerId, PeerId)>,
) -> Option<Vec<PeerId>> {
    let n = candidates.len();
    if n < size {
        return None;
    }

    let mut degrees = vec![0usize; n];
    if !disputes.is_empty() {
        for i in 0..n {
            for j in (i + 1)..n {
                if is_disputed(disputes, candidates[i], candidates[j]) {
                    degrees[i] += 1;
                    degrees[j] += 1;
                }
            }
        }
    }

    let mut ordered: Vec<usize> = (0..n).collect();
    ordered.sort_by_key(|&i| {
        (
            offences.get(&candidates[i]).copied().unwrap_or(0),
            degrees[i],
            i,
        )
    });

    if disputes.is_empty() {
        let mut original_indices: Vec<usize> = ordered[..size].to_vec();
        original_indices.sort_unstable();
        return Some(
            original_indices
                .into_iter()
                .map(|i| candidates[i])
                .collect(),
        );
    }

    // Precompute conflict matrix in `ordered` coordinates.
    let mut conflict = vec![vec![false; n]; n];
    for a in 0..n {
        for b in (a + 1)..n {
            if is_disputed(disputes, candidates[ordered[a]], candidates[ordered[b]]) {
                conflict[a][b] = true;
                conflict[b][a] = true;
            }
        }
    }

    let mut chosen: Vec<usize> = Vec::with_capacity(size);
    let mut steps = 0usize;

    if !search_undisputed(0, size, &conflict, &mut chosen, &mut steps) {
        if steps < MAX_COMMITTEE_SEARCH_STEPS {
            return None;
        }
        chosen = greedy_undisputed(size, &conflict)?;
    }

    let mut original_indices: Vec<usize> = chosen.into_iter().map(|i| ordered[i]).collect();
    original_indices.sort_unstable();

    Some(
        original_indices
            .into_iter()
            .map(|i| candidates[i])
            .collect(),
    )
}

/// The committee of run `run`: reuses the last proven-good sticky committee if
/// it still has `remaining > 0`, no blamed members, and no active mutual
/// disputes; otherwise picks `2f + 1` guardians preferring clean peers (lowest
/// accumulated offences, lowest dispute degree) while skipping actively blamed
/// guardians and disputed pairs. Honest guardians are never blamed and never
/// dispute each other, and they number at least `2f + 1`, so such a committee
/// exists unless honest guardians failed; then the committee ignores disputes,
/// and if it must, seats the blamed guardians released soonest.
pub async fn committee(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    run: u64,
) -> Vec<PeerId> {
    let peers: Vec<PeerId> = cfg.consensus.tpe_pks.keys().copied().collect();
    let size = PoolRun::committee_size(peers.len());
    let offset = usize::try_from(run % peers.len() as u64).expect("below the guardian count");

    let order: Vec<PeerId> = peers
        .iter()
        .cycle()
        .skip(offset)
        .take(peers.len())
        .copied()
        .collect();

    let all_blame: BTreeMap<PeerId, Blame> = dbtx
        .find_by_prefix(&Bolt12BlamePrefix)
        .await
        .map(|(key, blame)| (key.0, blame))
        .collect()
        .await;

    let offences: BTreeMap<PeerId, u32> = all_blame
        .iter()
        .map(|(&peer, blame)| (peer, blame.offences))
        .collect();

    let blamed: BTreeMap<PeerId, Blame> = all_blame
        .into_iter()
        .filter(|(_, blame)| blame.applies_to(run))
        .collect();

    let disputes: BTreeSet<(PeerId, PeerId)> = dbtx
        .find_by_prefix(&Bolt12DisputePrefix)
        .await
        .filter(|(_, blame)| std::future::ready(blame.applies_to(run)))
        .map(|(key, _)| (key.0, key.1))
        .collect()
        .await;

    if let Some(sticky) = dbtx.get_value(&Bolt12PoolStickyCommitteeKey).await
        && sticky.remaining > 0
        && sticky.committee.len() == size
        && sticky
            .committee
            .iter()
            .all(|p| peers.contains(p) && !blamed.contains_key(p))
        && sticky.committee.iter().enumerate().all(|(i, a)| {
            sticky.committee[i + 1..]
                .iter()
                .all(|b| !is_disputed(&disputes, *a, *b))
        })
    {
        return sticky.committee;
    }

    let eligible: Vec<PeerId> = order
        .iter()
        .copied()
        .filter(|peer| !blamed.contains_key(peer))
        .collect();

    if let Some(committee) = pick_undisputed(&eligible, size, &offences, &disputes) {
        return committee;
    }

    let mut released_soonest: Vec<PeerId> = order
        .iter()
        .copied()
        .filter(|peer| blamed.contains_key(peer))
        .collect();

    released_soonest.sort_by_key(|peer| blamed[peer].until_run);

    let seated: BTreeSet<PeerId> = eligible
        .into_iter()
        .chain(released_soonest)
        .take(size)
        .collect();

    order
        .into_iter()
        .filter(|peer| seated.contains(peer))
        .collect()
}

pub async fn process_start(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    run: u64,
    now: u64,
) -> Result<()> {
    let bolt12 = pool_config(cfg)?;

    ensure!(now > 0, "the consensus clock is not established yet");

    // Abandoned runs nobody judged in time are dropped unjudged.
    for abandoned in abandoned_runs(dbtx).await {
        if abandoned.is_stale(now) {
            forget_abandoned(dbtx, abandoned.run.run).await;
        }
    }

    ensure!(
        run_to_start(dbtx, cfg, now).await == Some(run),
        "no run is due or the run number is wrong"
    );

    let committee = committee(dbtx, cfg, run).await;

    dbtx.insert_entry(
        &Bolt12PoolRunKey,
        &PoolRun {
            run,
            committee,
            batch: bolt12.pool_batch,
            started_at: now,
        },
    )
    .await;

    dbtx.insert_entry(&Bolt12PoolRunCountKey, &(run + 1)).await;

    Ok(())
}

pub async fn process_shares(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    peer: PeerId,
    run: u64,
    shares: Vec<PoolShare>,
) -> Result<()> {
    pool_config(cfg)?;

    let active = dbtx
        .get_value(&Bolt12PoolRunKey)
        .await
        .filter(|active| active.run == run)
        .context("the run is not in progress")?;

    let position = active
        .position(peer)
        .context("the guardian is not on the run's committee")?;

    ensure!(
        shares.len() as u64 == active.batch,
        "the submission does not match the batch"
    );

    for share in &shares {
        ensure!(
            verify_non_identity_ciphertext(
                &share.ciphertext,
                &pool_share_binding(run, position, share.payment_hash)
            ),
            "a share ciphertext is invalid"
        );
    }

    ensure!(
        dbtx.insert_entry(&Bolt12PoolSubmissionKey(run, peer), &shares)
            .await
            .is_none(),
        "the guardian already submitted"
    );

    let submissions: Vec<(PeerId, Vec<PoolShare>)> = dbtx
        .find_by_prefix(&Bolt12PoolSubmissionRunPrefix(run))
        .await
        .map(|(key, shares)| (key.1, shares))
        .collect()
        .await;

    if submissions.len() == active.committee.len() {
        finish(dbtx, &active, submissions).await;
    }

    Ok(())
}

/// Decay a guardian's or pair's blame record by one completed clean run.
async fn decay_blame(dbtx: &mut DatabaseTransaction<'_>, peer: PeerId) {
    if let Some(blame) = dbtx.get_value(&Bolt12BlameKey(peer)).await {
        match blame.record_clean_run() {
            Some(updated) => {
                dbtx.insert_entry(&Bolt12BlameKey(peer), &updated).await;
            }
            None => {
                dbtx.remove_entry(&Bolt12BlameKey(peer)).await;
            }
        }
    }
}

async fn decay_dispute(dbtx: &mut DatabaseTransaction<'_>, a: PeerId, b: PeerId) {
    let key = dispute_key(a, b);
    if let Some(blame) = dbtx.get_value(&key).await {
        match blame.record_clean_run() {
            Some(updated) => {
                dbtx.insert_entry(&key, &updated).await;
            }
            None => {
                dbtx.remove_entry(&key).await;
            }
        }
    }
}

/// Keep a unanimously agreeing committee sticky for `STICKY_COMMITTEE_RUNS`
/// total runs before rotating; drop stickiness if anyone disagreed.
async fn update_sticky_committee(
    dbtx: &mut DatabaseTransaction<'_>,
    committee: &[PeerId],
    unanimous: bool,
) {
    if !unanimous {
        dbtx.remove_entry(&Bolt12PoolStickyCommitteeKey).await;
        return;
    }

    let existing = dbtx.get_value(&Bolt12PoolStickyCommitteeKey).await;
    match existing {
        Some(sticky) if sticky.committee == committee => {
            if sticky.remaining > 1 {
                dbtx.insert_entry(
                    &Bolt12PoolStickyCommitteeKey,
                    &StickyCommittee {
                        committee: sticky.committee,
                        remaining: sticky.remaining - 1,
                    },
                )
                .await;
            } else {
                dbtx.remove_entry(&Bolt12PoolStickyCommitteeKey).await;
            }
        }
        _ => {
            if STICKY_COMMITTEE_RUNS > 1 {
                dbtx.insert_entry(
                    &Bolt12PoolStickyCommitteeKey,
                    &StickyCommittee {
                        committee: committee.to_vec(),
                        remaining: STICKY_COMMITTEE_RUNS - 1,
                    },
                )
                .await;
            }
        }
    }
}

/// Add the run's preimages to the pool and end it.
async fn finish(
    dbtx: &mut DatabaseTransaction<'_>,
    active: &PoolRun,
    submissions: Vec<(PeerId, Vec<PoolShare>)>,
) {
    clear(dbtx, active.run).await;

    // Honest members end a run with the same hashes and are a majority, so
    // the hashes a majority submitted are the run's output. Members that
    // disagree are not honest; their shares are dropped and they are blamed.
    let hashes = |shares: &[PoolShare]| shares.iter().map(|s| s.payment_hash).collect::<Vec<_>>();

    let Some(agreed) = submissions
        .iter()
        .map(|(_, s)| hashes(s))
        .find(|candidate| {
            submissions
                .iter()
                .filter(|(_, s)| hashes(s) == *candidate)
                .count()
                >= active.threshold()
        })
    else {
        dbtx.remove_entry(&Bolt12PoolStickyCommitteeKey).await;
        dbtx.on_commit(|| {
            BOLT12_POOL_RUNS_TOTAL
                .with_label_values(&["no_majority"])
                .inc();
        });
        return;
    };

    let agreeing: Vec<(PeerId, u16, &Vec<PoolShare>)> = submissions
        .iter()
        .filter(|(_, s)| hashes(s) == agreed)
        .filter_map(|(peer, s)| Some((*peer, active.position(*peer)?, s)))
        .collect();

    let next_run = dbtx.get_value(&Bolt12PoolRunCountKey).await.unwrap_or(0);
    let agreeing_peers: BTreeSet<PeerId> = agreeing.iter().map(|(peer, _, _)| *peer).collect();

    // Blame any member whose submitted hash list disagreed with the majority.
    let mut disagreeing_count = 0u64;
    for member in &active.committee {
        if !agreeing_peers.contains(member) {
            let previous = dbtx.get_value(&Bolt12BlameKey(*member)).await;
            dbtx.insert_entry(
                &Bolt12BlameKey(*member),
                &Blame::repeat(previous.as_ref(), next_run),
            )
            .await;
            disagreeing_count += 1;
        }
    }

    // Completed clean runs slowly decay blame and mutual disputes rather than
    // wiping accumulated offences in a single run.
    for member in &agreeing_peers {
        decay_blame(dbtx, *member).await;

        for other in &agreeing_peers {
            if member < other {
                decay_dispute(dbtx, *member, *other).await;
            }
        }
    }

    update_sticky_committee(
        dbtx,
        &active.committee,
        agreeing.len() == active.committee.len(),
    )
    .await;

    let threshold = u16::try_from(active.threshold()).expect("committees are small");

    let mut next = dbtx.get_value(&Bolt12PoolNextKey).await.unwrap_or(0);

    for (item, payment_hash) in agreed.into_iter().enumerate() {
        // A hash is never issued twice, however unlikely a repeat is.
        if dbtx
            .insert_entry(&Bolt12PaymentHashKey(payment_hash), &())
            .await
            .is_some()
        {
            continue;
        }

        let shares = agreeing
            .iter()
            .map(|(peer, position, shares)| SealedShare {
                position: *position,
                peer: *peer,
                ciphertext: shares[item].ciphertext,
            })
            .collect();

        dbtx.insert_new_entry(
            &Bolt12PoolItemKey(next),
            &PoolItem {
                payment_hash,
                sealed: Sealed::Shares {
                    run: active.run,
                    threshold,
                    shares,
                },
            },
        )
        .await;

        next += 1;
    }

    dbtx.insert_entry(&Bolt12PoolNextKey, &next).await;
    observe_pool_finish(dbtx, disagreeing_count).await;
}

async fn observe_pool_finish(dbtx: &mut DatabaseTransaction<'_>, disagreeing_count: u64) {
    let ready = pool_len(dbtx).await;
    dbtx.on_commit(move || {
        BOLT12_POOL_ITEMS.set(i64::try_from(ready).unwrap_or(i64::MAX));
        BOLT12_POOL_RUNS_TOTAL
            .with_label_values(&["completed"])
            .inc();
        if disagreeing_count > 0 {
            BOLT12_POOL_BLAME_TOTAL
                .with_label_values(&["disagreeing_submission"])
                .inc_by(disagreeing_count);
        }
    });
}

/// Delete the run, its submissions and any abort reports.
async fn clear(dbtx: &mut DatabaseTransaction<'_>, run: u64) {
    dbtx.remove_entry(&Bolt12PoolRunKey).await;
    dbtx.remove_by_prefix(&Bolt12PoolSubmissionRunPrefix(run))
        .await;
    dbtx.remove_by_prefix(&Bolt12PoolAbortRunPrefix(run)).await;
}

/// Transition an active run into `AbandonedRun` for judging and clear any
/// sticky committee so the next run rotates past faulty members.
async fn abandon_active(dbtx: &mut DatabaseTransaction<'_>, active: PoolRun, now: u64) {
    let run = active.run;
    let submitted = dbtx
        .find_by_prefix(&Bolt12PoolSubmissionRunPrefix(run))
        .await
        .map(|(key, _)| key.1)
        .collect()
        .await;

    clear(dbtx, run).await;
    dbtx.remove_entry(&Bolt12PoolStickyCommitteeKey).await;

    dbtx.insert_new_entry(
        &Bolt12PoolAbandonedKey(run),
        &AbandonedRun {
            run: active,
            abandoned_at: now,
            submitted,
            evidence: BTreeMap::new(),
        },
    )
    .await;
}

/// Whether the run in progress has outlived its timeout at `now`.
pub fn is_overdue(active: &PoolRun, now: u64) -> bool {
    now >= active.started_at.saturating_add(POOL_RUN_TIMEOUT)
}

pub async fn process_abandon(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    run: u64,
    now: u64,
) -> Result<()> {
    pool_config(cfg)?;

    let Some(active) = dbtx
        .get_value(&Bolt12PoolRunKey)
        .await
        .filter(|active| active.run == run)
    else {
        bail!("the run is not in progress");
    };

    ensure!(is_overdue(&active, now), "the run has not timed out");

    abandon_active(dbtx, active, now).await;
    dbtx.on_commit(|| {
        BOLT12_POOL_RUNS_TOTAL
            .with_label_values(&["abandoned_timeout"])
            .inc();
    });

    Ok(())
}

/// A committee member reports that its local execution of `run` aborted. Once
/// `f + 1` members report an abort, consensus abandons the run immediately
/// without waiting for `POOL_RUN_TIMEOUT`.
pub async fn process_abort(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    peer: PeerId,
    run: u64,
    now: u64,
) -> Result<()> {
    pool_config(cfg)?;

    let Some(active) = dbtx
        .get_value(&Bolt12PoolRunKey)
        .await
        .filter(|active| active.run == run)
    else {
        bail!("the run is not in progress");
    };

    ensure!(
        active.position(peer).is_some(),
        "the guardian is not on the run's committee"
    );
    ensure!(
        dbtx.insert_entry(&Bolt12PoolAbortKey(run, peer), &())
            .await
            .is_none(),
        "the guardian already reported an abort"
    );

    let aborts = dbtx
        .find_by_prefix(&Bolt12PoolAbortRunPrefix(run))
        .await
        .count()
        .await;

    if aborts >= active.threshold() {
        abandon_active(dbtx, active, now).await;
        dbtx.on_commit(|| {
            BOLT12_POOL_RUNS_TOTAL
                .with_label_values(&["abandoned_abort"])
                .inc();
        });
    }

    Ok(())
}

async fn forget_abandoned(dbtx: &mut DatabaseTransaction<'_>, run: u64) {
    dbtx.remove_entry(&Bolt12PoolAbandonedKey(run)).await;
    dbtx.remove_by_prefix(&Bolt12PoolVerdictRunPrefix(run))
        .await;
}

/// A member commits to the evidence it will reveal about an abandoned run.
pub async fn process_evidence(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    peer: PeerId,
    run: u64,
    digest: sha256::Hash,
    now: u64,
) -> Result<()> {
    pool_config(cfg)?;

    let mut abandoned = dbtx
        .get_value(&Bolt12PoolAbandonedKey(run))
        .await
        .context("the run is not being judged")?;

    ensure!(
        abandoned.collecting_evidence(now),
        "evidence for the run is closed"
    );
    ensure!(
        abandoned.run.position(peer).is_some(),
        "the guardian was not on the run's committee"
    );
    ensure!(
        abandoned.evidence.insert(peer, digest).is_none(),
        "the guardian already committed to evidence"
    );

    dbtx.insert_entry(&Bolt12PoolAbandonedKey(run), &abandoned)
        .await;

    Ok(())
}

/// A guardian's verdict about an abandoned run. Once a quorum has voted,
/// blame that `f + 1` of them agree on is applied.
pub async fn process_verdict(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    peer: PeerId,
    run: u64,
    verdict: PoolVerdict,
    now: u64,
) -> Result<()> {
    pool_config(cfg)?;

    let abandoned = dbtx
        .get_value(&Bolt12PoolAbandonedKey(run))
        .await
        .context("the run is not being judged")?;

    ensure!(
        !abandoned.collecting_evidence(now),
        "evidence for the run is still being collected"
    );
    ensure!(!abandoned.is_stale(now), "the run is no longer judged");

    let member = |p: &PeerId| abandoned.run.position(*p).is_some();

    ensure!(
        (verdict.culprits.is_empty() || verdict.disputes.is_empty())
            && verdict.culprits.iter().all(member)
            && verdict.culprits.windows(2).all(|w| w[0] < w[1])
            && verdict
                .disputes
                .iter()
                .all(|(a, b)| a < b && member(a) && member(b))
            && verdict.disputes.windows(2).all(|w| w[0] < w[1]),
        "the verdict names non-members, mixes culprits with disputes, or is not in canonical order"
    );
    ensure!(
        dbtx.insert_entry(&Bolt12PoolVerdictKey(run, peer), &verdict)
            .await
            .is_none(),
        "the guardian already voted"
    );

    let verdicts: Vec<PoolVerdict> = dbtx
        .find_by_prefix(&Bolt12PoolVerdictRunPrefix(run))
        .await
        .map(|(_, verdict)| verdict)
        .collect()
        .await;

    let guardians = cfg.consensus.tpe_pks.len();

    if verdicts.len() >= quorum(guardians) {
        apply_blame(dbtx, &verdicts, PoolRun::degree(guardians) + 1).await;
        forget_abandoned(dbtx, run).await;
    }

    Ok(())
}

/// Blame committee members whose sealed shares did not lie on the recovered
/// polynomial when a pool receive was spent, and drop sticky reuse if any of
/// them is on the current sticky committee.
pub async fn blame_poisoned_shares(dbtx: &mut DatabaseTransaction<'_>, peers: &[PeerId]) {
    let next_run = dbtx.get_value(&Bolt12PoolRunCountKey).await.unwrap_or(0);

    for &peer in peers {
        let previous = dbtx.get_value(&Bolt12BlameKey(peer)).await;

        dbtx.insert_entry(
            &Bolt12BlameKey(peer),
            &Blame::repeat(previous.as_ref(), next_run),
        )
        .await;
    }

    if let Some(sticky) = dbtx.get_value(&Bolt12PoolStickyCommitteeKey).await
        && sticky.committee.iter().any(|peer| peers.contains(peer))
    {
        dbtx.remove_entry(&Bolt12PoolStickyCommitteeKey).await;
    }

    let count = peers.len() as u64;
    if count > 0 {
        dbtx.on_commit(move || {
            BOLT12_POOL_BLAME_TOTAL
                .with_label_values(&["poisoned_share"])
                .inc_by(count);
        });
    }
}

/// Blame every guardian and pair at least `threshold` verdicts name.
async fn apply_blame(
    dbtx: &mut DatabaseTransaction<'_>,
    verdicts: &[PoolVerdict],
    threshold: usize,
) {
    let mut culprits: BTreeMap<PeerId, usize> = BTreeMap::new();
    let mut disputes: BTreeMap<(PeerId, PeerId), usize> = BTreeMap::new();

    for verdict in verdicts {
        for culprit in &verdict.culprits {
            *culprits.entry(*culprit).or_default() += 1;
        }

        for dispute in &verdict.disputes {
            *disputes.entry(*dispute).or_default() += 1;
        }
    }

    let next_run = dbtx.get_value(&Bolt12PoolRunCountKey).await.unwrap_or(0);
    let mut blamed_culprits = 0u64;
    let mut blamed_disputes = 0u64;

    for (culprit, _) in culprits
        .into_iter()
        .filter(|(_, votes)| *votes >= threshold)
    {
        let previous = dbtx.get_value(&Bolt12BlameKey(culprit)).await;

        dbtx.insert_entry(
            &Bolt12BlameKey(culprit),
            &Blame::repeat(previous.as_ref(), next_run),
        )
        .await;
        blamed_culprits += 1;
    }

    for ((a, b), _) in disputes
        .into_iter()
        .filter(|(_, votes)| *votes >= threshold)
    {
        let previous = dbtx.get_value(&dispute_key(a, b)).await;

        dbtx.insert_entry(
            &dispute_key(a, b),
            &Blame::repeat(previous.as_ref(), next_run),
        )
        .await;
        blamed_disputes += 1;
    }

    if blamed_culprits > 0 || blamed_disputes > 0 {
        dbtx.on_commit(move || {
            if blamed_culprits > 0 {
                BOLT12_POOL_BLAME_TOTAL
                    .with_label_values(&["culprit"])
                    .inc_by(blamed_culprits);
            }
            if blamed_disputes > 0 {
                BOLT12_POOL_BLAME_TOTAL
                    .with_label_values(&["dispute"])
                    .inc_by(blamed_disputes);
            }
        });
    }
}

impl Lightning {
    /// Items that move generation forward: start a due run, submit this
    /// guardian's shares from a finished one, abandon one that is overdue, and
    /// commit to evidence about and judge abandoned ones.
    pub(crate) async fn bolt12_pool_proposals(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<LightningConsensusItem> {
        if self.bolt12_worker.is_none() {
            return vec![];
        }

        let ready = pool_len(dbtx).await;
        BOLT12_POOL_ITEMS.set(i64::try_from(ready).unwrap_or(i64::MAX));

        let now = self.consensus_unix_time(dbtx).await;
        let me = self.our_peer_id;
        let mut items = vec![];

        if let Some(run) = run_to_start(dbtx, &self.cfg, now).await {
            items.push(LightningConsensusItem::Bolt12PoolStart { run });
        }

        if let Some(active) = dbtx.get_value(&Bolt12PoolRunKey).await {
            if is_overdue(&active, now) {
                items.push(LightningConsensusItem::Bolt12PoolAbandon { run: active.run });
            } else if let Some(local) = dbtx.get_value(&Bolt12PoolLocalRunKey(active.run)).await {
                if dbtx
                    .get_value(&Bolt12PoolSubmissionKey(active.run, me))
                    .await
                    .is_none()
                    && let Some(shares) = local.submission
                {
                    items.push(LightningConsensusItem::Bolt12PoolShares {
                        run: active.run,
                        shares,
                    });
                } else if local.submission.is_none()
                    && local.evidence.is_some()
                    && active.position(me).is_some()
                    && dbtx
                        .get_value(&Bolt12PoolAbortKey(active.run, me))
                        .await
                        .is_none()
                {
                    items.push(LightningConsensusItem::Bolt12PoolAbort { run: active.run });
                }
            }
        }

        for abandoned in abandoned_runs(dbtx).await {
            let run = abandoned.run.run;

            if abandoned.is_stale(now) {
                continue;
            }

            if abandoned.collecting_evidence(now) {
                if abandoned.run.position(me).is_some()
                    && !abandoned.evidence.contains_key(&me)
                    && let Some(digest) = dbtx
                        .get_value(&Bolt12PoolLocalRunKey(run))
                        .await
                        .and_then(|local| local.evidence)
                {
                    items.push(LightningConsensusItem::Bolt12PoolEvidence { run, digest });
                }
            } else if dbtx
                .get_value(&Bolt12PoolVerdictKey(run, me))
                .await
                .is_none()
                && let Some(verdict) = dbtx.get_value(&Bolt12PoolLocalVerdictKey(run)).await
            {
                items.push(LightningConsensusItem::Bolt12PoolVerdict { run, verdict });
            }
        }

        items
    }
}
