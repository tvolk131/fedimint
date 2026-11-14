//! Consensus rules for the pool of generated preimages.
//!
//! A run starts when the pool is below its target. Its committee, the first
//! `2f + 1` guardians in an order that rotates with the run number, generates
//! the preimages off consensus (see `worker`) and each member submits its
//! encrypted shares as a consensus item. Once every member has submitted, the
//! hashes a majority of members agree on enter the pool. A run that outlives
//! `POOL_RUN_TIMEOUT` is abandoned and its results are never used.

use anyhow::{Context as _, Result, bail, ensure};
use fedimint_core::PeerId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_lnv2_common::LightningConsensusItem;
use fedimint_lnv2_common::bolt12::{
    Bolt12Config, MAX_POOL_TARGET, POOL_RUN_TIMEOUT, PoolItem, PoolRun, PoolShare, Sealed,
    SealedShare, pool_share_binding,
};
use fedimint_lnv2_common::config::LightningConfig;
use futures::StreamExt as _;
use tpe::verify_ciphertext;

use crate::Lightning;
use crate::db::{
    Bolt12PaymentHashKey, Bolt12PoolItemKey, Bolt12PoolItemPrefix, Bolt12PoolLocalRunKey,
    Bolt12PoolNextKey, Bolt12PoolRunCountKey, Bolt12PoolRunKey, Bolt12PoolSubmissionKey,
    Bolt12PoolSubmissionRunPrefix,
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

/// The run to start, if the pool is below target and no run is in progress.
pub async fn run_to_start(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
) -> Option<u64> {
    let bolt12 = pool_config(cfg).ok()?;

    if dbtx.get_value(&Bolt12PoolRunKey).await.is_some()
        || pool_len(dbtx).await >= bolt12.pool_target.min(MAX_POOL_TARGET)
    {
        return None;
    }

    Some(dbtx.get_value(&Bolt12PoolRunCountKey).await.unwrap_or(0))
}

/// The committee of run `run`: `2f + 1` guardians, starting at an offset that
/// moves with every run so an unresponsive guardian does not stall every run.
pub fn committee(cfg: &LightningConfig, run: u64) -> Vec<PeerId> {
    let peers: Vec<PeerId> = cfg.consensus.tpe_pks.keys().copied().collect();
    let size = PoolRun::committee_size(peers.len());
    let offset = usize::try_from(run % peers.len() as u64).expect("below the guardian count");

    peers
        .iter()
        .cycle()
        .skip(offset)
        .take(size)
        .copied()
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
    ensure!(
        run_to_start(dbtx, cfg).await == Some(run),
        "no run is due or the run number is wrong"
    );

    dbtx.insert_entry(
        &Bolt12PoolRunKey,
        &PoolRun {
            run,
            committee: committee(cfg, run),
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

    clear(dbtx, run).await;

    Ok(())
}

impl Lightning {
    /// Items that move generation forward: start a due run, submit this
    /// guardian's shares from a finished one, or abandon one that is overdue.
    pub(crate) async fn bolt12_pool_proposals(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<LightningConsensusItem> {
        if self.bolt12_worker.is_none() {
            return vec![];
        }

        if let Some(run) = run_to_start(dbtx, &self.cfg).await {
            return vec![LightningConsensusItem::Bolt12PoolStart { run }];
        }

        let Some(active) = dbtx.get_value(&Bolt12PoolRunKey).await else {
            return vec![];
        };

        if is_overdue(&active, self.consensus_unix_time(dbtx).await) {
            return vec![LightningConsensusItem::Bolt12PoolAbandon { run: active.run }];
        }

        if dbtx
            .get_value(&Bolt12PoolSubmissionKey(active.run, self.our_peer_id))
            .await
            .is_some()
        {
            return vec![];
        }

        dbtx.get_value(&Bolt12PoolLocalRunKey(active.run))
            .await
            .and_then(|local| local.submission)
            .map(|shares| LightningConsensusItem::Bolt12PoolShares {
                run: active.run,
                shares,
            })
            .into_iter()
            .collect()
    }
}
