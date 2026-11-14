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
    PoolShare, PoolVerdict, Sealed, SealedShare, pool_share_binding, quorum,
};
use fedimint_lnv2_common::config::LightningConfig;
use futures::StreamExt as _;
use tpe::verify_ciphertext;

use crate::Lightning;
use crate::db::{
    Bolt12BlameKey, Bolt12BlamePrefix, Bolt12DisputeKey, Bolt12DisputePrefix, Bolt12PaymentHashKey,
    Bolt12PoolAbandonedKey, Bolt12PoolAbandonedPrefix, Bolt12PoolItemKey, Bolt12PoolItemPrefix,
    Bolt12PoolLocalRunKey, Bolt12PoolLocalVerdictKey, Bolt12PoolNextKey, Bolt12PoolRunCountKey,
    Bolt12PoolRunKey, Bolt12PoolSubmissionKey, Bolt12PoolSubmissionRunPrefix, Bolt12PoolVerdictKey,
    Bolt12PoolVerdictRunPrefix,
};

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

/// The first `size` of `candidates`, in order, no two of which are disputed.
fn first_undisputed(
    candidates: &[PeerId],
    size: usize,
    disputes: &BTreeSet<(PeerId, PeerId)>,
) -> Option<Vec<PeerId>> {
    if candidates.len() < size {
        return None;
    }

    let mut choice: Vec<usize> = (0..size).collect();

    loop {
        let chosen: Vec<PeerId> = choice.iter().map(|&i| candidates[i]).collect();

        let undisputed = chosen.iter().enumerate().all(|(i, a)| {
            chosen[i + 1..]
                .iter()
                .all(|b| !disputes.contains(&((*a).min(*b), (*a).max(*b))))
        });

        if undisputed {
            return Some(chosen);
        }

        let i = (0..size)
            .rev()
            .find(|&i| choice[i] != i + candidates.len() - size)?;

        choice[i] += 1;

        for j in i + 1..size {
            choice[j] = choice[j - 1] + 1;
        }
    }
}

/// The committee of run `run`: `2f + 1` guardians in an order that rotates
/// with the run number, leaving out blamed guardians and never seating both
/// guardians of a disputed pair. Honest guardians are never blamed and never
/// dispute each other, and they number at least `2f + 1`, so such a committee
/// exists unless honest guardians failed; then the committee ignores
/// disputes, and if it must, seats the blamed guardians released soonest.
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

    let blamed: BTreeMap<PeerId, Blame> = dbtx
        .find_by_prefix(&Bolt12BlamePrefix)
        .await
        .filter(|(_, blame)| std::future::ready(blame.applies_to(run)))
        .map(|(key, blame)| (key.0, blame))
        .collect()
        .await;

    let disputes: BTreeSet<(PeerId, PeerId)> = dbtx
        .find_by_prefix(&Bolt12DisputePrefix)
        .await
        .filter(|(_, blame)| std::future::ready(blame.applies_to(run)))
        .map(|(key, _)| (key.0, key.1))
        .collect()
        .await;

    let eligible: Vec<PeerId> = order
        .iter()
        .copied()
        .filter(|peer| !blamed.contains_key(peer))
        .collect();

    if let Some(committee) = first_undisputed(&eligible, size, &disputes) {
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
            verify_ciphertext(
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

/// Add the run's preimages to the pool and end it.
async fn finish(
    dbtx: &mut DatabaseTransaction<'_>,
    active: &PoolRun,
    submissions: Vec<(PeerId, Vec<PoolShare>)>,
) {
    clear(dbtx, active.run).await;

    // A completed run clears its members' records.
    for member in &active.committee {
        dbtx.remove_entry(&Bolt12BlameKey(*member)).await;

        for other in &active.committee {
            if member < other {
                dbtx.remove_entry(&dispute_key(*member, *other)).await;
            }
        }
    }

    // Honest members end a run with the same hashes and are a majority, so
    // the hashes a majority submitted are the run's output. Members that
    // disagree are not honest; their shares are dropped.
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
        return;
    };

    let agreeing: Vec<(u16, &Vec<PoolShare>)> = submissions
        .iter()
        .filter(|(_, s)| hashes(s) == agreed)
        .filter_map(|(peer, s)| Some((active.position(*peer)?, s)))
        .collect();

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
            .map(|(position, shares)| SealedShare {
                position: *position,
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
}

/// Delete the run and its submissions.
async fn clear(dbtx: &mut DatabaseTransaction<'_>, run: u64) {
    dbtx.remove_entry(&Bolt12PoolRunKey).await;
    dbtx.remove_by_prefix(&Bolt12PoolSubmissionRunPrefix(run))
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

    let submitted = dbtx
        .find_by_prefix(&Bolt12PoolSubmissionRunPrefix(run))
        .await
        .map(|(key, _)| key.1)
        .collect()
        .await;

    clear(dbtx, run).await;

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
        verdict.culprits.iter().all(member)
            && verdict.culprits.windows(2).all(|w| w[0] < w[1])
            && verdict
                .disputes
                .iter()
                .all(|(a, b)| a < b && member(a) && member(b))
            && verdict.disputes.windows(2).all(|w| w[0] < w[1]),
        "the verdict names non-members or is not in canonical order"
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

        let now = self.consensus_unix_time(dbtx).await;
        let me = self.our_peer_id;
        let mut items = vec![];

        if let Some(run) = run_to_start(dbtx, &self.cfg, now).await {
            items.push(LightningConsensusItem::Bolt12PoolStart { run });
        }

        if let Some(active) = dbtx.get_value(&Bolt12PoolRunKey).await {
            if is_overdue(&active, now) {
                items.push(LightningConsensusItem::Bolt12PoolAbandon { run: active.run });
            } else if dbtx
                .get_value(&Bolt12PoolSubmissionKey(active.run, me))
                .await
                .is_none()
                && let Some(shares) = dbtx
                    .get_value(&Bolt12PoolLocalRunKey(active.run))
                    .await
                    .and_then(|local| local.submission)
            {
                items.push(LightningConsensusItem::Bolt12PoolShares {
                    run: active.run,
                    shares,
                });
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
