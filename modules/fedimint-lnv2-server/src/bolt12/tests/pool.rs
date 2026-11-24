//! Consensus rules for generation runs and pool-backed receives. Shares are
//! dealt directly here; `fedimint-mpc` has its own tests of generating them.

use std::collections::BTreeMap;

use anyhow::Result;
use fedimint_core::bitcoin::hashes::{Hash, sha256};
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_core::{Amount, PeerId};
use fedimint_lnv2_common::bolt12::{
    BLAME_DECAY_RUNS, Blame, Bolt12Output, EVIDENCE_WINDOW, JUDGE_TIMEOUT, POOL_RUN_TIMEOUT,
    PoolShare, PoolVerdict, Register, Reserve, STICKY_COMMITTEE_RUNS, Sealed, Source,
    pool_share_binding, quorum, terms_hash,
};
use mpc::field::{F, point};
use rand::rngs::OsRng;

use super::{Federation, NOW, Offer, gateway, policy, register};
use crate::bolt12::pool::{self, pool_len};
use crate::db::{
    Bolt12BlameKey, Bolt12DisputeKey, Bolt12PoolAbandonedKey, Bolt12PoolRunKey,
    Bolt12ReservationKey,
};

/// Preimages dealt as threshold-two shares to a three-member committee, and
/// each member's submission.
struct Dealt {
    preimages: Vec<[u8; 32]>,
    submissions: BTreeMap<PeerId, Vec<PoolShare>>,
}

fn share(preimage: &[u8; 32], coefficient: &[u8; 32], position: usize) -> [u8; 32] {
    let x = point(position + 1);

    std::array::from_fn(|b| (F(preimage[b]) + F(coefficient[b]) * x).0)
}

fn seal(
    fed: &Federation,
    run: u64,
    position: u16,
    payment_hash: [u8; 32],
    value: &[u8; 32],
) -> PoolShare {
    PoolShare {
        payment_hash,
        ciphertext: tpe::encrypt_preimage(
            &fed.cfg.consensus.tpe_agg_pk,
            &rand::random(),
            value,
            &pool_share_binding(run, position, payment_hash),
        ),
    }
}

fn deal(fed: &Federation, run: u64, committee: &[PeerId], batch: usize) -> Dealt {
    let preimages: Vec<[u8; 32]> = (0..batch).map(|_| rand::random()).collect();
    let coefficients: Vec<[u8; 32]> = (0..batch).map(|_| rand::random()).collect();

    let submissions = committee
        .iter()
        .enumerate()
        .map(|(position, peer)| {
            let shares = preimages
                .iter()
                .zip(&coefficients)
                .map(|(preimage, coefficient)| {
                    seal(
                        fed,
                        run,
                        u16::try_from(position).expect("small"),
                        sha256::Hash::hash(preimage).to_byte_array(),
                        &share(preimage, coefficient, position),
                    )
                })
                .collect();

            (*peer, shares)
        })
        .collect();

    Dealt {
        preimages,
        submissions,
    }
}

fn peers(ids: &[u16]) -> Vec<PeerId> {
    ids.iter().copied().map(PeerId::from).collect()
}

impl Federation {
    async fn start(&self, run: u64, now: u64) -> Result<()> {
        let mut dbtx = self.db.begin_transaction().await;

        pool::process_start(&mut dbtx.to_ref_nc(), &self.cfg, run, now).await?;

        dbtx.commit_tx().await;

        Ok(())
    }

    async fn submit(&self, peer: PeerId, run: u64, shares: Vec<PoolShare>) -> Result<()> {
        let mut dbtx = self.db.begin_transaction().await;

        pool::process_shares(&mut dbtx.to_ref_nc(), &self.cfg, peer, run, shares).await?;

        dbtx.commit_tx().await;

        Ok(())
    }

    async fn abandon(&self, run: u64, now: u64) -> Result<()> {
        let mut dbtx = self.db.begin_transaction().await;

        pool::process_abandon(&mut dbtx.to_ref_nc(), &self.cfg, run, now).await?;

        dbtx.commit_tx().await;

        Ok(())
    }

    async fn abort(&self, peer: PeerId, run: u64, now: u64) -> Result<()> {
        let mut dbtx = self.db.begin_transaction().await;

        pool::process_abort(&mut dbtx.to_ref_nc(), &self.cfg, peer, run, now).await?;

        dbtx.commit_tx().await;

        Ok(())
    }

    async fn evidence(&self, peer: u16, run: u64, now: u64) -> Result<()> {
        let mut dbtx = self.db.begin_transaction().await;

        pool::process_evidence(
            &mut dbtx.to_ref_nc(),
            &self.cfg,
            PeerId::from(peer),
            run,
            sha256::Hash::hash(&peer.to_be_bytes()),
            now,
        )
        .await?;

        dbtx.commit_tx().await;

        Ok(())
    }

    async fn verdict(&self, peer: u16, run: u64, verdict: PoolVerdict, now: u64) -> Result<()> {
        let mut dbtx = self.db.begin_transaction().await;

        pool::process_verdict(
            &mut dbtx.to_ref_nc(),
            &self.cfg,
            PeerId::from(peer),
            run,
            verdict,
            now,
        )
        .await?;

        dbtx.commit_tx().await;

        Ok(())
    }

    async fn blame(&self, peer: u16) -> Option<Blame> {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12BlameKey(PeerId::from(peer)))
            .await
    }

    async fn dispute(&self, a: u16, b: u16) -> Option<Blame> {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12DisputeKey(PeerId::from(a), PeerId::from(b)))
            .await
    }

    async fn is_judging(&self, run: u64) -> bool {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12PoolAbandonedKey(run))
            .await
            .is_some()
    }

    /// Start `run` and let it time out.
    async fn abandon_run(&self, run: u64, now: u64) {
        self.start(run, now).await.expect("run is due");
        self.abandon(run, now + POOL_RUN_TIMEOUT)
            .await
            .expect("run is overdue");
    }

    /// Have a quorum of guardians return `verdict` on `run`, abandoned at `at`.
    async fn judge(&self, run: u64, at: u64, verdict: &PoolVerdict) {
        let count = u16::try_from(quorum(self.cfg.consensus.tpe_pks.len())).expect("small");
        for peer in 0..count {
            self.verdict(peer, run, verdict.clone(), at + EVIDENCE_WINDOW)
                .await
                .expect("verdict is valid");
        }
    }

    async fn pool_len(&self) -> u64 {
        pool_len(&mut self.db.begin_transaction_nc().await.to_ref_nc()).await
    }

    async fn committee(&self) -> Option<Vec<PeerId>> {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12PoolRunKey)
            .await
            .map(|run| run.committee)
    }

    /// Run a generation round with every member submitting honestly.
    async fn fill(&self, run: u64) -> Dealt {
        self.start(run, NOW).await.expect("run is due");

        let committee = self.committee().await.expect("run started");
        let dealt = deal(self, run, &committee, 2);

        for (peer, shares) in &dealt.submissions {
            self.submit(*peer, run, shares.clone())
                .await
                .expect("submission is valid");
        }

        dealt
    }
}

/// An offer that accepts generated preimages and has no stock.
async fn pooled_offer(fed: &mut Federation) -> Offer {
    let key = Keypair::new(SECP256K1, &mut OsRng);
    let mut policy = policy(&key, NOW + 86_400);

    policy.allow_pool = true;

    fed.apply(
        Bolt12Output::Register(Register::new(policy.clone(), &key)),
        NOW,
    )
    .await
    .expect("registration is valid");

    Offer {
        key,
        id: policy.id(),
        policy,
    }
}

fn reserve_pool(offer: &Offer, index: u64, amount: Amount, gateway: &Keypair) -> Reserve {
    Reserve::new(
        offer.id,
        Source::Pool { index },
        amount,
        Amount::from_sats(60),
        terms_hash(b"request", b"path"),
        gateway,
    )
}

#[tokio::test]
async fn generated_preimages_fill_the_pool_and_pay_out() -> Result<()> {
    let mut fed = Federation::new();

    fed.start(0, NOW).await?;

    // One run at a time, numbered in order.
    assert_eq!(fed.committee().await, Some(peers(&[0, 1, 2])));
    assert!(fed.start(0, NOW).await.is_err());
    assert!(fed.start(1, NOW).await.is_err());

    let dealt = deal(&fed, 0, &peers(&[0, 1, 2]), 2);

    // Only members submit, once each, and nothing enters the pool until
    // every member has.
    assert!(
        fed.submit(
            PeerId::from(3),
            0,
            dealt.submissions[&PeerId::from(0)].clone()
        )
        .await
        .is_err()
    );

    fed.submit(
        PeerId::from(0),
        0,
        dealt.submissions[&PeerId::from(0)].clone(),
    )
    .await?;

    assert!(
        fed.submit(
            PeerId::from(0),
            0,
            dealt.submissions[&PeerId::from(0)].clone()
        )
        .await
        .is_err()
    );

    fed.submit(
        PeerId::from(1),
        0,
        dealt.submissions[&PeerId::from(1)].clone(),
    )
    .await?;

    assert_eq!(fed.pool_len().await, 0);

    fed.submit(
        PeerId::from(2),
        0,
        dealt.submissions[&PeerId::from(2)].clone(),
    )
    .await?;

    assert_eq!(fed.pool_len().await, 2);
    assert_eq!(fed.committee().await, None);

    // A pooled offer without stock reserves the first item.
    let gateway = gateway();
    let offer = pooled_offer(&mut fed).await;

    fed.approve(&gateway).await;

    let request = reserve_pool(&offer, 0, Amount::from_sats(10_000), &gateway);
    let id = request.reservation_id();

    fed.apply(Bolt12Output::Reserve(request), NOW).await?;

    let reservation = fed
        .db
        .begin_transaction_nc()
        .await
        .get_value(&Bolt12ReservationKey(id))
        .await
        .expect("reservation is stored");

    assert_eq!(
        reservation.payment_hash,
        sha256::Hash::hash(&dealt.preimages[0]).to_byte_array()
    );
    assert!(matches!(
        &reservation.sealed,
        Sealed::Shares { threshold: 2, shares, .. } if shares.len() == 3
    ));
    assert_eq!(fed.pool_len().await, 1);

    // The item is gone for everyone else.
    assert!(
        fed.apply(
            Bolt12Output::Reserve(reserve_pool(&offer, 0, Amount::from_sats(10_000), &gateway)),
            NOW
        )
        .await
        .is_err()
    );

    let (outpoint, _) = fed.apply(Bolt12Output::Receive(id), NOW + 30).await?;
    let unlock = fed.unlock(outpoint).await;

    assert!(unlock.is_pool());
    assert_eq!(
        fed.contract(outpoint).await.release(unlock.keys()),
        Some(dealt.preimages[0])
    );

    // The recipient claims and pays the pool fee for it.
    assert_eq!(
        fed.spend(outpoint, &unlock).await,
        Ok((
            offer.policy.claim_pk,
            Amount::from_sats(10_000 - 60),
            Amount::from_sats(20)
        ))
    );

    Ok(())
}

#[tokio::test]
async fn pool_reservations_need_consent_no_stock_and_room_for_the_fee() -> Result<()> {
    let mut fed = Federation::new();
    let gateway = gateway();

    fed.approve(&gateway).await;
    fed.fill(0).await;

    // The recipient did not opt in.
    let plain = register(&mut fed, NOW + 86_400, NOW).await;

    assert!(
        fed.rejection(
            Bolt12Output::Reserve(reserve_pool(&plain, 0, Amount::from_sats(10_000), &gateway)),
            NOW
        )
        .await
        .is_some_and(|e| e.contains("generated preimages"))
    );

    // The recipient opted in but still has stock, which is cheaper.
    let key = Keypair::new(SECP256K1, &mut OsRng);
    let mut stocked_policy = policy(&key, NOW + 86_400);

    stocked_policy.allow_pool = true;

    let stocked = Offer {
        id: stocked_policy.id(),
        policy: stocked_policy.clone(),
        key,
    };

    fed.apply(
        Bolt12Output::Register(Register::new(stocked_policy, &stocked.key)),
        NOW,
    )
    .await?;
    fed.apply(
        Bolt12Output::AddStock(fedimint_lnv2_common::bolt12::AddStock::new(
            stocked.id,
            0,
            super::stock(&fed, &stocked, 0, 1),
            &stocked.key,
        )),
        NOW,
    )
    .await?;

    assert!(
        fed.rejection(
            Bolt12Output::Reserve(reserve_pool(
                &stocked,
                0,
                Amount::from_sats(10_000),
                &gateway
            )),
            NOW
        )
        .await
        .is_some_and(|e| e.contains("still has stock"))
    );

    // An amount that would net the recipient something from stock does not
    // once the pool fee is added.
    let pooled = pooled_offer(&mut fed).await;

    assert!(
        fed.rejection(
            Bolt12Output::Reserve(reserve_pool(&pooled, 0, Amount::from_sats(80), &gateway)),
            NOW
        )
        .await
        .is_some_and(|e| e.contains("does not cover fees"))
    );

    assert_eq!(fed.pool_len().await, 2);

    Ok(())
}

#[tokio::test]
async fn more_than_f_faulty_members_leave_the_gateway_a_refund() -> Result<()> {
    let mut fed = Federation::new();
    let gateway = gateway();
    let offer = pooled_offer(&mut fed).await;

    fed.approve(&gateway).await;
    fed.start(0, NOW).await?;

    let committee = peers(&[0, 1, 2]);
    let dealt = deal(&fed, 0, &committee, 2);

    // Two of three members misbehave, more than the one a four-guardian
    // federation tolerates: member 2 submits other hashes, member 1 the
    // right hashes over garbage.
    let other = deal(&fed, 0, &committee, 2);

    let garbage: Vec<PoolShare> = dealt.submissions[&committee[1]]
        .iter()
        .map(|share| seal(&fed, 0, 1, share.payment_hash, &rand::random()))
        .collect();

    fed.submit(committee[0], 0, dealt.submissions[&committee[0]].clone())
        .await?;
    fed.submit(committee[1], 0, garbage).await?;
    fed.submit(committee[2], 0, other.submissions[&committee[2]].clone())
        .await?;

    // The majority's hashes enter the pool, sealed by the two members that
    // submitted them.
    assert_eq!(fed.pool_len().await, 2);

    let request = reserve_pool(&offer, 0, Amount::from_sats(10_000), &gateway);
    let id = request.reservation_id();

    fed.apply(Bolt12Output::Reserve(request), NOW).await?;

    let (outpoint, _) = fed.apply(Bolt12Output::Receive(id), NOW).await?;
    let contract = fed.contract(outpoint).await;

    assert!(matches!(&contract.sealed, Sealed::Shares { shares, .. } if shares.len() == 2));

    // One correct share is too few; the funding goes back to the gateway.
    let unlock = fed.unlock(outpoint).await;

    assert_eq!(contract.release(unlock.keys()), None);
    assert_eq!(
        fed.spend(outpoint, &unlock).await,
        Ok((
            gateway.public_key(),
            Amount::from_sats(10_000 - 60),
            Amount::from_sats(20)
        ))
    );

    Ok(())
}

#[tokio::test]
async fn a_wrong_share_is_outvoted_by_the_correct_ones() -> Result<()> {
    let mut fed = Federation::new();
    let gateway = gateway();
    let offer = pooled_offer(&mut fed).await;

    fed.approve(&gateway).await;
    fed.start(0, NOW).await?;

    let committee = peers(&[0, 1, 2]);
    let dealt = deal(&fed, 0, &committee, 2);

    let garbage: Vec<PoolShare> = dealt.submissions[&committee[2]]
        .iter()
        .map(|share| seal(&fed, 0, 2, share.payment_hash, &rand::random()))
        .collect();

    fed.submit(committee[0], 0, dealt.submissions[&committee[0]].clone())
        .await?;
    fed.submit(committee[1], 0, dealt.submissions[&committee[1]].clone())
        .await?;
    fed.submit(committee[2], 0, garbage).await?;

    let request = reserve_pool(&offer, 1, Amount::from_sats(10_000), &gateway);
    let id = request.reservation_id();

    fed.apply(Bolt12Output::Reserve(request), NOW).await?;

    let (outpoint, _) = fed.apply(Bolt12Output::Receive(id), NOW).await?;
    let unlock = fed.unlock(outpoint).await;

    assert_eq!(
        fed.contract(outpoint).await.release(unlock.keys()),
        Some(dealt.preimages[1])
    );
    assert_eq!(
        fed.spend(outpoint, &unlock).await.map(|(key, ..)| key),
        Ok(offer.policy.claim_pk)
    );

    Ok(())
}

#[tokio::test]
async fn submissions_must_match_the_run() -> Result<()> {
    let fed = Federation::new();

    fed.start(0, NOW).await?;

    let committee = peers(&[0, 1, 2]);
    let dealt = deal(&fed, 0, &committee, 2);
    let own = dealt.submissions[&committee[0]].clone();

    // Wrong run, wrong batch size, and another member's shares, whose
    // ciphertexts are bound to that member's position.
    assert!(fed.submit(committee[0], 1, own.clone()).await.is_err());
    assert!(
        fed.submit(committee[0], 0, own[..1].to_vec())
            .await
            .is_err()
    );
    assert!(
        fed.submit(committee[0], 0, dealt.submissions[&committee[1]].clone())
            .await
            .is_err()
    );

    fed.submit(committee[0], 0, own).await?;

    Ok(())
}

#[tokio::test]
async fn overdue_runs_are_abandoned_and_the_committee_rotates() -> Result<()> {
    let fed = Federation::new();

    fed.start(0, NOW).await?;

    let dealt = deal(&fed, 0, &peers(&[0, 1, 2]), 2);

    fed.submit(
        PeerId::from(0),
        0,
        dealt.submissions[&PeerId::from(0)].clone(),
    )
    .await?;

    assert!(fed.abandon(0, NOW + POOL_RUN_TIMEOUT - 1).await.is_err());
    assert!(fed.abandon(1, NOW + POOL_RUN_TIMEOUT).await.is_err());

    fed.abandon(0, NOW + POOL_RUN_TIMEOUT).await?;

    // Late submissions for the abandoned run are refused and its partial
    // results never enter the pool.
    assert!(
        fed.submit(
            PeerId::from(1),
            0,
            dealt.submissions[&PeerId::from(1)].clone()
        )
        .await
        .is_err()
    );
    assert_eq!(fed.pool_len().await, 0);

    // Once the abandoned run is judged, here blaming nobody, the next one
    // starts with the next committee.
    fed.judge(0, NOW + POOL_RUN_TIMEOUT, &culprits(&[])).await;
    fed.start(1, NOW + POOL_RUN_TIMEOUT + EVIDENCE_WINDOW)
        .await?;

    assert_eq!(fed.committee().await, Some(peers(&[1, 2, 3])));

    Ok(())
}

#[tokio::test]
async fn runs_stop_at_the_target_and_need_the_clock() -> Result<()> {
    let mut fed = Federation::new();

    // Target four, two per run.
    assert!(fed.start(0, 0).await.is_err());

    fed.fill(0).await;
    fed.fill(1).await;

    assert_eq!(fed.pool_len().await, 4);
    assert!(fed.start(2, NOW).await.is_err());

    fed.cfg
        .consensus
        .bolt12
        .as_mut()
        .expect("enabled")
        .pool_target = 0;

    assert!(
        pool::run_to_start(
            &mut fed.db.begin_transaction_nc().await.to_ref_nc(),
            &fed.cfg,
            NOW
        )
        .await
        .is_none()
    );

    Ok(())
}

fn culprits(peers: &[u16]) -> PoolVerdict {
    PoolVerdict {
        culprits: peers.iter().copied().map(PeerId::from).collect(),
        disputes: vec![],
    }
}

#[tokio::test]
async fn abandoned_runs_are_judged_before_the_next_run() -> Result<()> {
    let fed = Federation::new();
    let abandoned_at = NOW + POOL_RUN_TIMEOUT;

    fed.abandon_run(0, NOW).await;

    assert!(fed.is_judging(0).await);

    // No run starts while one is being judged.
    assert!(fed.start(1, abandoned_at).await.is_err());

    // Members commit to evidence once, within the window.
    fed.evidence(0, 0, abandoned_at + 10).await?;

    assert!(fed.evidence(0, 0, abandoned_at + 20).await.is_err());
    assert!(fed.evidence(3, 0, abandoned_at + 20).await.is_err());
    assert!(
        fed.evidence(1, 0, abandoned_at + EVIDENCE_WINDOW)
            .await
            .is_err()
    );

    // Verdicts come after the window, name members only, in order, once.
    let at = abandoned_at + EVIDENCE_WINDOW;

    assert!(
        fed.verdict(0, 0, culprits(&[2]), abandoned_at + 10)
            .await
            .is_err()
    );
    assert!(fed.verdict(0, 0, culprits(&[3]), at).await.is_err());
    assert!(fed.verdict(0, 0, culprits(&[2, 1]), at).await.is_err());

    fed.verdict(0, 0, culprits(&[2]), at).await?;

    assert!(fed.verdict(0, 0, culprits(&[2]), at).await.is_err());

    fed.verdict(1, 0, culprits(&[2]), at).await?;

    assert!(fed.is_judging(0).await);

    // A quorum of verdicts settles it.
    fed.verdict(3, 0, culprits(&[]), at).await?;

    assert!(!fed.is_judging(0).await);
    assert_eq!(
        fed.blame(2).await,
        Some(Blame {
            offences: 1,
            until_run: 1 + 8,
            clean_runs: 0,
        })
    );

    // The next committee rotates past the blamed guardian.
    fed.start(1, at).await?;

    assert_eq!(fed.committee().await, Some(peers(&[1, 3, 0])));

    Ok(())
}

#[tokio::test]
async fn blame_needs_f_plus_one_verdicts() -> Result<()> {
    let fed = Federation::new();
    let at = NOW + POOL_RUN_TIMEOUT + EVIDENCE_WINDOW;

    fed.abandon_run(0, NOW).await;

    fed.verdict(0, 0, culprits(&[1]), at).await?;
    fed.verdict(1, 0, culprits(&[]), at).await?;
    fed.verdict(2, 0, culprits(&[]), at).await?;

    assert!(!fed.is_judging(0).await);
    assert_eq!(fed.blame(1).await, None);

    Ok(())
}

#[tokio::test]
async fn disputed_pairs_never_share_a_committee() -> Result<()> {
    let fed = Federation::new();
    let at = NOW + POOL_RUN_TIMEOUT + EVIDENCE_WINDOW;

    fed.abandon_run(0, NOW).await;
    fed.judge(
        0,
        NOW + POOL_RUN_TIMEOUT,
        &PoolVerdict {
            culprits: vec![],
            disputes: vec![(PeerId::from(1), PeerId::from(2))],
        },
    )
    .await;

    assert!(fed.dispute(1, 2).await.is_some());

    // Rotation would seat 1, 2 and 3; the first undisputed choice is 1, 3, 0.
    fed.start(1, at).await?;

    assert_eq!(fed.committee().await, Some(peers(&[1, 3, 0])));

    // A completed run clears records among its members only; guardian 2
    // sat it out, so the dispute stands.
    let committee = fed.committee().await.expect("run started");
    let dealt = deal(&fed, 1, &committee, 2);

    for (peer, shares) in &dealt.submissions {
        fed.submit(*peer, 1, shares.clone()).await?;
    }

    assert!(fed.dispute(1, 2).await.is_some());

    Ok(())
}

#[tokio::test]
async fn repeat_offences_double_and_decay_slowly() -> Result<()> {
    let mut fed = Federation::new();
    fed.cfg
        .consensus
        .bolt12
        .as_mut()
        .expect("enabled")
        .pool_target = 256;

    // Penalties start at eight runs and double per offence, up to 64.
    let first = Blame::repeat(None, 5);
    let second = Blame::repeat(Some(&first), 5);

    assert_eq!(
        (first.offences, first.until_run, first.clean_runs),
        (1, 13, 0)
    );
    assert_eq!(
        (second.offences, second.until_run, second.clean_runs),
        (2, 21, 0)
    );
    assert_eq!(
        Blame::repeat(
            Some(&Blame {
                offences: 10,
                until_run: 0,
                clean_runs: 0,
            }),
            5
        )
        .until_run,
        69
    );

    // Guardian 2's blame has expired by run 0 (guardian 3 has higher offences,
    // so guardian 2 is seated on [0, 1, 2]). One completed run must NOT wipe
    // guardian 2's accumulated offences (preventing the sleeper-reset attack).
    let mut dbtx = fed.db.begin_transaction().await;
    dbtx.insert_entry(
        &Bolt12BlameKey(PeerId::from(2)),
        &Blame {
            offences: 2,
            until_run: 0,
            clean_runs: 0,
        },
    )
    .await;
    dbtx.insert_entry(
        &Bolt12BlameKey(PeerId::from(3)),
        &Blame {
            offences: 3,
            until_run: 0,
            clean_runs: 0,
        },
    )
    .await;
    dbtx.commit_tx().await;

    fed.fill(0).await;

    assert_eq!(
        fed.blame(2).await,
        Some(Blame {
            offences: 2,
            until_run: 0,
            clean_runs: 1,
        })
    );

    // Completing BLAME_DECAY_RUNS clean runs decays one offence level; another
    // BLAME_DECAY_RUNS clears the record completely.
    for run in 1..u64::from(BLAME_DECAY_RUNS) {
        fed.fill(run).await;
    }

    assert_eq!(
        fed.blame(2).await,
        Some(Blame {
            offences: 1,
            until_run: 0,
            clean_runs: 0,
        })
    );

    for run in u64::from(BLAME_DECAY_RUNS)..u64::from(2 * BLAME_DECAY_RUNS) {
        fed.fill(run).await;
    }

    assert_eq!(fed.blame(2).await, None);

    Ok(())
}

#[tokio::test]
async fn committees_never_shrink_below_2f_plus_1() -> Result<()> {
    let fed = Federation::new();
    let at = NOW + POOL_RUN_TIMEOUT + EVIDENCE_WINDOW;

    fed.abandon_run(0, NOW).await;
    fed.judge(0, NOW + POOL_RUN_TIMEOUT, &culprits(&[1, 2]))
        .await;

    // Two of four guardians are blamed, one more than a committee can do
    // without; the guardian released soonest is seated again.
    fed.start(1, at).await?;

    let committee = fed.committee().await.expect("run started");

    assert_eq!(committee.len(), 3);
    assert!(committee.contains(&PeerId::from(3)) && committee.contains(&PeerId::from(0)));

    Ok(())
}

#[tokio::test]
async fn unjudged_runs_go_stale_and_stop_blocking() -> Result<()> {
    let fed = Federation::new();
    let abandoned_at = NOW + POOL_RUN_TIMEOUT;

    fed.abandon_run(0, NOW).await;

    assert!(
        fed.start(1, abandoned_at + JUDGE_TIMEOUT - 1)
            .await
            .is_err()
    );

    fed.start(1, abandoned_at + JUDGE_TIMEOUT).await?;

    assert!(!fed.is_judging(0).await);
    assert!(
        fed.verdict(0, 0, culprits(&[]), abandoned_at + JUDGE_TIMEOUT)
            .await
            .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn evidence_is_revealed_only_for_abandoned_runs_and_only_signed_messages_count() -> Result<()>
{
    use fedimint_core::secp256k1::SecretKey;

    use crate::bolt12::transport::message_digest;
    use crate::bolt12::worker::{evidence_digest, serve_evidence, signed_messages};
    use crate::db::{
        Bolt12PoolLocalRunKey, Bolt12PoolTranscriptKey, LocalRun, RelayEvidence, SignedMessage,
    };

    let mut fed = Federation::new();
    let secrets: Vec<SecretKey> = (0..4).map(|_| SecretKey::new(&mut OsRng)).collect();

    fed.cfg
        .consensus
        .bolt12
        .as_mut()
        .expect("enabled")
        .transport_keys = (0..4u16)
        .map(|peer| {
            (
                PeerId::from(peer),
                secrets[usize::from(peer)].public_key(SECP256K1),
            )
        })
        .collect();

    fed.start(0, NOW).await?;

    let run = fed
        .db
        .begin_transaction_nc()
        .await
        .get_value(&Bolt12PoolRunKey)
        .await
        .expect("run started");

    let sign = |sender: u16, recipient: u16, round: u64, message: &[u8]| SignedMessage {
        message: message.to_vec(),
        signature: SECP256K1.sign_schnorr(
            &message_digest(
                0,
                PeerId::from(sender),
                PeerId::from(recipient),
                round,
                message,
            ),
            &Keypair::from_secret_key(SECP256K1, &secrets[usize::from(sender)]),
        ),
    };

    // What member 0 received: a good message from 1, and one from 2 signed
    // for another recipient.
    let rounds = vec![vec![
        None,
        Some(sign(1, 0, 0, b"from one")),
        Some(sign(2, 1, 0, b"from two")),
    ]];

    let transport_keys = &fed
        .cfg
        .consensus
        .bolt12
        .as_ref()
        .expect("enabled")
        .transport_keys;

    assert_eq!(
        signed_messages(transport_keys, &run, PeerId::from(0), &rounds),
        vec![vec![None, Some(b"from one".to_vec()), None]]
    );

    let mut dbtx = fed.db.begin_transaction().await;

    let relay = RelayEvidence::default();

    dbtx.insert_entry(
        &Bolt12PoolLocalRunKey(0),
        &LocalRun {
            seed: [7; 32],
            submission: None,
            evidence: Some(evidence_digest(&[7; 32], &rounds, &relay)),
            transcript_rounds: u64::try_from(rounds.len()).expect("small"),
        },
    )
    .await;
    dbtx.insert_entry(&Bolt12PoolTranscriptKey(0, 0), &rounds[0])
        .await;
    dbtx.commit_tx().await;

    // While the run could still finish, the seed stays secret.
    assert!(serve_evidence(&fed.db, 0, 0, 0).await.is_err());

    fed.abandon(0, NOW + POOL_RUN_TIMEOUT).await?;

    let page = serve_evidence(&fed.db, 0, 0, 0).await?;

    assert_eq!(page.seed, [7; 32]);
    assert!(page.next_cursor.is_none());
    let mut reconstructed =
        vec![vec![None; run.committee.len()]; usize::try_from(page.total_rounds)?];
    for (round, pos, msg) in page.entries {
        reconstructed[usize::try_from(round)?][usize::from(pos)] = Some(msg);
    }
    assert_eq!(
        evidence_digest(&page.seed, &reconstructed, &page.relay),
        evidence_digest(&[7; 32], &rounds, &relay)
    );

    Ok(())
}

#[tokio::test]
async fn early_abort_by_f_plus_one_abandons_without_waiting_for_timeout() -> Result<()> {
    let fed = Federation::new();

    fed.start(0, NOW).await?;

    // Non-members cannot abort; f = 1 malicious member alone cannot abandon.
    assert!(fed.abort(PeerId::from(3), 0, NOW + 5).await.is_err());
    fed.abort(PeerId::from(0), 0, NOW + 5).await?;
    assert!(fed.abort(PeerId::from(0), 0, NOW + 6).await.is_err());
    assert!(!fed.is_judging(0).await);
    assert!(fed.committee().await.is_some());

    // A second member reaches f + 1 = 2 and abandons immediately at t = 10 s.
    fed.abort(PeerId::from(1), 0, NOW + 10).await?;
    assert!(fed.is_judging(0).await);
    assert_eq!(fed.committee().await, None);

    // Once all 3 committee members commit evidence, judging opens immediately
    // without waiting for EVIDENCE_WINDOW.
    for peer in 0..3u16 {
        fed.evidence(peer, 0, NOW + 12).await?;
    }

    for peer in 0..3u16 {
        fed.verdict(peer, 0, culprits(&[2]), NOW + 13).await?;
    }

    assert!(!fed.is_judging(0).await);
    assert!(fed.blame(2).await.is_some());

    Ok(())
}

#[tokio::test]
async fn sticky_committee_reuses_proven_good_set_and_clears_on_abandon() -> Result<()> {
    let mut fed = Federation::new();
    fed.cfg
        .consensus
        .bolt12
        .as_mut()
        .expect("enabled")
        .pool_target = 256;

    // Run 0 succeeds with [0, 1, 2]; runs 1..STICKY_COMMITTEE_RUNS reuse it.
    fed.fill(0).await;

    for run in 1..STICKY_COMMITTEE_RUNS {
        fed.start(run, NOW + run).await?;
        assert_eq!(fed.committee().await, Some(peers(&[0, 1, 2])));
        let dealt = deal(&fed, run, &peers(&[0, 1, 2]), 2);
        for (peer, shares) in &dealt.submissions {
            fed.submit(*peer, run, shares.clone()).await?;
        }
    }

    // After STICKY_COMMITTEE_RUNS total runs, the committee rotates.
    let rotated_run = STICKY_COMMITTEE_RUNS;
    fed.start(rotated_run, NOW + rotated_run).await?;
    // offset = 32 % 4 = 0 would pick [0, 1, 2] on N=4, so check abandonment
    // also clears stickiness immediately on run 33.
    fed.abandon(rotated_run, NOW + rotated_run + POOL_RUN_TIMEOUT)
        .await?;
    fed.judge(
        rotated_run,
        NOW + rotated_run + POOL_RUN_TIMEOUT,
        &culprits(&[]),
    )
    .await;
    fed.start(
        rotated_run + 1,
        NOW + rotated_run + POOL_RUN_TIMEOUT + EVIDENCE_WINDOW,
    )
    .await?;
    assert_eq!(fed.committee().await, Some(peers(&[1, 2, 3])));

    Ok(())
}

#[tokio::test]
async fn committee_selection_scales_to_large_federations_with_heavy_disputes() -> Result<()> {
    // N = 31 (f = 10, m = 21): previously C(31, 21) = 44.3M combinations.
    // Even with 100 adversarial bipartite disputes (every malicious guardian
    // 21..31 disputed with 10 honest guardians 0..10), selection must find an
    // undisputed committee of size 21 in milliseconds.
    let fed = Federation::with_guardians(31);
    let mut dbtx = fed.db.begin_transaction().await;

    for m in 21..31u16 {
        for h in 0..10u16 {
            dbtx.insert_entry(
                &Bolt12DisputeKey(PeerId::from(h), PeerId::from(m)),
                &Blame {
                    offences: 1,
                    until_run: 100,
                    clean_runs: 0,
                },
            )
            .await;
        }
    }
    dbtx.commit_tx().await;

    let started = std::time::Instant::now();
    let chosen = pool::committee(
        &mut fed.db.begin_transaction_nc().await.to_ref_nc(),
        &fed.cfg,
        5,
    )
    .await;
    let elapsed = started.elapsed();

    assert_eq!(chosen.len(), 21);
    assert!(
        elapsed.as_millis() < 200,
        "committee selection took too long: {elapsed:?}"
    );
    // Verify no disputed pair was seated together.
    for (i, a) in chosen.iter().enumerate() {
        for b in &chosen[i + 1..] {
            assert!(
                fed.dispute(u16::from(*a.min(b)), u16::from(*a.max(b)))
                    .await
                    .is_none(),
                "disputed pair ({a}, {b}) seated together"
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn adversarial_federation_throughput_under_k_equals_f() -> Result<()> {
    // Simulate consecutive runs against the real consensus DB for N = 10, 16,
    // 22, and 31 with k = f coordinated attackers. With relay-backed
    // conviction + sticky committees + offence-prioritized selection + slow
    // offence decay:
    // - Worst-case consecutive failures stay <= f
    // - Once all f attackers are caught, every subsequent run succeeds cleanly
    //   (even across sticky-committee rotations).
    for (guardians, runs) in [(10u16, 60u64), (16, 60), (22, 60), (31, 40)] {
        let f = usize::from(guardians - 1) / 3;
        let attackers: std::collections::BTreeSet<PeerId> = (0..f)
            .map(|i| PeerId::from(u16::try_from(i).expect("small")))
            .collect();

        let mut fed = Federation::with_guardians(guardians);
        let bolt12 = fed.cfg.consensus.bolt12.as_mut().expect("enabled");
        bolt12.pool_target = 10_000;
        bolt12.pool_batch = 1;

        let mut now = NOW;
        let mut successes = 0usize;
        let mut cur_streak = 0usize;
        let mut max_streak = 0usize;

        for run in 0..runs {
            fed.start(run, now).await?;
            let committee = fed.committee().await.expect("run started");
            let present_attackers: Vec<PeerId> = committee
                .iter()
                .copied()
                .filter(|p| attackers.contains(p))
                .collect();

            if present_attackers.is_empty() {
                // Clean honest run.
                let dealt = deal(&fed, run, &committee, 1);
                for (peer, shares) in &dealt.submissions {
                    fed.submit(*peer, run, shares.clone()).await?;
                }
                successes += 1;
                cur_streak = 0;
                now += 165;
            } else {
                // One attacker sabotages (early f+1 abort + relay witness
                // convicts that attacker).
                let saboteur = present_attackers[0];
                let honest_members: Vec<PeerId> = committee
                    .iter()
                    .copied()
                    .filter(|p| !attackers.contains(p))
                    .collect();

                for &honest in honest_members.iter().take(committee.len() / 2 + 1) {
                    fed.abort(honest, run, now + 15).await?;
                }
                assert!(fed.is_judging(run).await);

                fed.judge(run, now + 15, &culprits(&[u16::from(saboteur)]))
                    .await;
                cur_streak += 1;
                max_streak = max_streak.max(cur_streak);
                now += 15 + EVIDENCE_WINDOW;
            }
        }

        assert!(
            max_streak <= f,
            "N={guardians} (f={f}): max consecutive fails {max_streak} exceeded f"
        );
        // Every run after at most f initial detections must succeed cleanly.
        let expected_min = usize::try_from(runs).expect("small") - f;
        assert_eq!(
            successes, expected_min,
            "N={guardians} (f={f}): expected exactly {expected_min}/{runs} successes, got {successes}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn transport_relay_recovers_blocked_link() -> Result<()> {
    use fedimint_core::secp256k1::SecretKey;

    use crate::bolt12::transport::{ChannelLimits, Channels, FetchRequest, verify_packet_envelope};

    let committee = peers(&[0, 1, 2]);
    let limits = ChannelLimits::for_run(3, 1, 4);
    let secrets: Vec<SecretKey> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
    let keys: BTreeMap<PeerId, _> = (0..3u16)
        .map(|p| {
            (
                PeerId::from(p),
                secrets[usize::from(p)].public_key(SECP256K1),
            )
        })
        .collect();
    let seeds = [[11u8; 32], [22u8; 32], [33u8; 32]];

    let ch0 = Channels::new(
        0,
        PeerId::from(0),
        committee.clone(),
        limits,
        &seeds[0],
        &secrets[0],
        &keys,
    )?;
    let ch1 = Channels::new(
        0,
        PeerId::from(1),
        committee,
        limits,
        &seeds[1],
        &secrets[1],
        &keys,
    )?;

    // Peer 0 produces encrypted, envelope-signed packets for peer 1; peer 2
    // (acting as an authenticated committee relay) pulls them via a signed
    // FetchRequest and verifies the outer signature without peer 1's key.
    let msg = b"round-0-share-bytes";
    let _sent = ch0.packets(PeerId::from(1), 0, msg)?;

    // Unauthenticated / forged, outsider, or wrong-sender fetch requests must
    // be rejected.
    let outsider_key = Keypair::new(SECP256K1, &mut OsRng);
    let forged = FetchRequest::new(
        0,
        PeerId::from(0),
        PeerId::from(2),
        PeerId::from(1),
        0,
        0,
        &outsider_key,
    );
    assert!(ch0.serve_packets(&forged).is_err());
    let outsider = FetchRequest::new(
        0,
        PeerId::from(0),
        PeerId::from(3),
        PeerId::from(1),
        0,
        0,
        &outsider_key,
    );
    assert!(ch0.serve_packets(&outsider).is_err());

    let relay_signer = Keypair::from_secret_key(SECP256K1, &secrets[2]);
    let wrong_sender = FetchRequest::new(
        0,
        PeerId::from(2),
        PeerId::from(2),
        PeerId::from(1),
        0,
        0,
        &relay_signer,
    );
    assert!(ch0.serve_packets(&wrong_sender).is_err());

    let valid_fetch = FetchRequest::new(
        0,
        PeerId::from(0),
        PeerId::from(2),
        PeerId::from(1),
        0,
        0,
        &relay_signer,
    );
    let (total_chunks, relayed) = ch0.serve_packets(&valid_fetch)?;

    assert_eq!(total_chunks, 1);
    assert_eq!(relayed.len(), 1);
    assert!(verify_packet_envelope(
        0,
        (PeerId::from(0), &keys[&PeerId::from(0)]),
        PeerId::from(1),
        &relayed[0]
    ));

    // Peer 1 receives the relayed packet cleanly.
    ch1.receive(&relayed[0])?;
    assert_eq!(
        ch1.transcript()[0][0]
            .as_ref()
            .map(|s| s.message.as_slice()),
        Some(msg.as_slice())
    );

    Ok(())
}

fn encrypt_test_packet(
    seed: &[u8; 32],
    signer: &Keypair,
    recipient_pk: &fedimint_core::secp256k1::PublicKey,
    round: u64,
    chunk: u32,
    chunks: u32,
    plaintext: &[u8],
) -> crate::bolt12::transport::MpcPacket {
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use fedimint_core::encoding::Encodable as _;

    use crate::bolt12::keys::transport_key;
    use crate::bolt12::transport::{
        MpcPacket, ephemeral_secret, packet_digest, recipient_ephemeral_secret,
    };

    let eph = ephemeral_secret(seed, 0, PeerId::from(0), PeerId::from(1));
    let eph_pk = eph.public_key(SECP256K1);
    let recv_eph_pk =
        recipient_ephemeral_secret(seed, 0, PeerId::from(0), PeerId::from(1)).public_key(SECP256K1);
    let domain = (
        "fedimint/bolt12/mpc-channel/v2",
        0u64,
        PeerId::from(0),
        PeerId::from(1),
    )
        .consensus_encode_to_vec();
    let key = transport_key(&eph, recipient_pk, &domain);
    let aad = (domain, round, chunks).consensus_encode_to_vec();
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&round.to_be_bytes());
    nonce[8..].copy_from_slice(&chunk.to_be_bytes());
    let ciphertext = ChaCha20Poly1305::new((&key).into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .expect("encrypts");
    let envelope_sig = SECP256K1.sign_schnorr(
        &packet_digest(
            0,
            PeerId::from(0),
            PeerId::from(1),
            round,
            chunk,
            chunks,
            eph_pk,
            recv_eph_pk,
            &ciphertext,
        ),
        signer,
    );
    MpcPacket {
        run: 0,
        sender: PeerId::from(0),
        round,
        chunk,
        chunks,
        ephemeral_pk: eph_pk,
        recv_ephemeral_pk: recv_eph_pk,
        ciphertext,
        envelope_sig,
    }
}

#[tokio::test]
async fn transport_faults_convict_malicious_sender() -> Result<()> {
    use fedimint_core::secp256k1::SecretKey;

    use crate::bolt12::transport::{
        ChannelLimits, Channels, MpcPacket, packet_digest, verify_transport_fault_convicts,
    };
    use crate::db::TransportFault;

    let committee = peers(&[0, 1, 2]);
    // Batch 32 permits multiple chunks so multi-chunk and 2-vs-3 conflict tests
    // stay within the run's per-run chunk cap.
    let limits = ChannelLimits::for_run(3, 1, 32);
    assert!(limits.chunks >= 3);
    let secrets: Vec<SecretKey> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
    let keys: BTreeMap<PeerId, _> = (0..3u16)
        .map(|p| {
            (
                PeerId::from(p),
                secrets[usize::from(p)].public_key(SECP256K1),
            )
        })
        .collect();
    let seeds = [[11u8; 32], [22u8; 32], [33u8; 32]];
    let signer0 = Keypair::from_secret_key(SECP256K1, &secrets[0]);
    let sender = (PeerId::from(0), &keys[&PeerId::from(0)]);
    let recipient = (PeerId::from(1), &keys[&PeerId::from(1)]);
    let new_ch1 = || {
        Channels::new(
            0,
            PeerId::from(1),
            committee.clone(),
            limits,
            &seeds[1],
            &secrets[1],
            &keys,
        )
    };
    let convicts = |fault: &TransportFault| {
        verify_transport_fault_convicts(
            0,
            sender,
            recipient,
            &seeds[0],
            &seeds[1],
            fault,
            limits.chunks,
        )
    };

    let enc = |chunk: u32, chunks: u32, pt: &[u8]| {
        encrypt_test_packet(&seeds[0], &signer0, recipient.1, 0, chunk, chunks, pt)
    };

    // 1. Bad AEAD ciphertext convicts sender.
    let ch1 = new_ch1()?;
    let bad_ct = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33];
    let bad_eph = secrets[0].public_key(SECP256K1);
    let digest = packet_digest(0, sender.0, recipient.0, 1, 0, 1, bad_eph, bad_eph, &bad_ct);
    let forged = MpcPacket {
        run: 0,
        sender: sender.0,
        round: 1,
        chunk: 0,
        chunks: 1,
        ephemeral_pk: bad_eph,
        recv_ephemeral_pk: bad_eph,
        ciphertext: bad_ct,
        envelope_sig: SECP256K1.sign_schnorr(&digest, &signer0),
    };
    assert!(ch1.receive(&forged).is_err());
    assert!(convicts(&ch1.relay_evidence().faults[0]));

    // 2. Valid AEAD + invalid inner Schnorr signature (single-chunk) convicts.
    let ch1_inner = new_ch1()?;
    assert!(ch1_inner.receive(&enc(0, 1, &[0x42u8; 80])).is_err());
    assert!(convicts(&ch1_inner.relay_evidence().faults[0]));

    // 3. Valid AEAD + invalid inner signature (multi-chunk) convicts via
    // BadMultiChunk.
    let ch1_multi = new_ch1()?;
    ch1_multi.receive(&enc(0, 2, &[0x11u8; 64]))?;
    assert!(ch1_multi.receive(&enc(1, 2, &[0x22u8; 64])).is_err());
    let ev_multi = ch1_multi.relay_evidence();
    assert!(matches!(
        ev_multi.faults.as_slice(),
        [TransportFault::BadMultiChunk(pkts)] if pkts.len() == 2
    ));
    assert!(convicts(&ev_multi.faults[0]));

    // 4. Conflicting chunk counts for the same round convict via
    // ChunkCountConflict.
    let ch1_conflict = new_ch1()?;
    ch1_conflict.receive(&enc(0, 2, b"chunk-zero"))?;
    assert!(ch1_conflict.receive(&enc(1, 3, b"wrong-total")).is_err());
    let ev_conflict = ch1_conflict.relay_evidence();
    assert!(matches!(
        ev_conflict.faults.as_slice(),
        [TransportFault::ChunkCountConflict(_, _)]
    ));
    assert!(convicts(&ev_conflict.faults[0]));

    Ok(())
}

#[tokio::test]
async fn transport_honest_packets_resist_framing() -> Result<()> {
    use fedimint_core::secp256k1::SecretKey;

    use crate::bolt12::transport::{
        CHUNK, ChannelLimits, Channels, MpcPacket, verify_transport_fault_convicts,
    };
    use crate::db::{BadPacket, TransportFault};

    let committee = peers(&[0, 1, 2]);
    let limits = ChannelLimits::for_run(3, 1, 16);
    assert!(limits.chunks >= 2);
    let secrets: Vec<SecretKey> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
    let keys: BTreeMap<PeerId, _> = (0..3u16)
        .map(|p| {
            (
                PeerId::from(p),
                secrets[usize::from(p)].public_key(SECP256K1),
            )
        })
        .collect();
    let seeds = [[11u8; 32], [22u8; 32], [33u8; 32]];
    let sender = (PeerId::from(0), &keys[&PeerId::from(0)]);
    let recipient = (PeerId::from(1), &keys[&PeerId::from(1)]);
    let ch0 = Channels::new(
        0,
        PeerId::from(0),
        committee.clone(),
        limits,
        &seeds[0],
        &secrets[0],
        &keys,
    )?;
    let ch1 = Channels::new(
        0,
        PeerId::from(1),
        committee,
        limits,
        &seeds[1],
        &secrets[1],
        &keys,
    )?;
    let to_bad = |p: &MpcPacket| BadPacket {
        sender: p.sender,
        round: p.round,
        chunk: p.chunk,
        chunks: p.chunks,
        ephemeral_pk: p.ephemeral_pk,
        recv_ephemeral_pk: p.recv_ephemeral_pk,
        ciphertext: p.ciphertext.clone(),
        envelope_sig: p.envelope_sig,
    };

    let honest_single = ch0.packets(PeerId::from(1), 0, b"honest")?;
    assert!(
        !verify_transport_fault_convicts(
            0,
            sender,
            recipient,
            &seeds[0],
            &seeds[1],
            &TransportFault::BadPacket(to_bad(&honest_single[0])),
            limits.chunks,
        ),
        "honest single-chunk packet must never convict sender"
    );

    // Deliver peer 1's Round-0 packet to ch0 so ch0 learns peer 1's ephemeral
    // receive key for mutual forward secrecy on rounds >= 1.
    for pkt in ch1.packets(PeerId::from(0), 0, b"peer1-r0")? {
        ch0.receive(&pkt)?;
    }

    let honest_multi = ch0.packets(PeerId::from(1), 1, &vec![0x55u8; CHUNK + 128])?;
    assert_eq!(honest_multi.len(), 2);
    assert!(
        !verify_transport_fault_convicts(
            0,
            sender,
            recipient,
            &seeds[0],
            &seeds[1],
            &TransportFault::BadMultiChunk(honest_multi.iter().map(to_bad).collect()),
            limits.chunks,
        ),
        "honest multi-chunk packet must never convict sender"
    );

    Ok(())
}

#[tokio::test]
async fn per_run_limits_block_oversized_messages_and_cover_max_faults() -> Result<()> {
    use fedimint_core::secp256k1::SecretKey;

    use crate::bolt12::transport::{CHUNK, ChannelLimits, Channels};
    use crate::bolt12::worker::max_evidence_page_hex;

    let committee = peers(&[0, 1, 2]);
    let limits = ChannelLimits::for_run(3, 1, 4);

    let secrets: Vec<SecretKey> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
    let keys: BTreeMap<PeerId, _> = (0..3u16)
        .map(|p| {
            (
                PeerId::from(p),
                secrets[usize::from(p)].public_key(SECP256K1),
            )
        })
        .collect();
    let seeds = [[11u8; 32], [22u8; 32], [33u8; 32]];
    let signer0 = Keypair::from_secret_key(SECP256K1, &secrets[0]);
    let ch1 = Channels::new(
        0,
        PeerId::from(1),
        committee,
        limits,
        &seeds[1],
        &secrets[1],
        &keys,
    )?;

    // A packet exceeding the run's per-run `limits.chunks` must be rejected
    // immediately without entering transcript or faults.
    let oversized = encrypt_test_packet(
        &seeds[0],
        &signer0,
        &keys[&PeerId::from(1)],
        0,
        0,
        limits.chunks + 1,
        &[0xaa; 64],
    );
    assert!(ch1.receive(&oversized).is_err());
    assert_eq!(ch1.transcript(), vec![] as Vec<Vec<Option<_>>>);
    assert_eq!(ch1.relay_evidence().faults, vec![]);

    // Across every valid federation size (degree <= MAX_POOL_DEGREE) and batch
    // up to MAX_POOL_BATCH, `fault_bytes` must cover a full `chunks`
    // bad-inner-sig message from every possible malicious sender, and
    // `max_evidence_page_hex` must strictly exceed the largest possible encoded
    // Page 0 while staying under the 10 MiB WebSocket response cap.
    for (n, t, batch) in [(3, 1, 4), (3, 1, 32), (7, 3, 32), (15, 7, 32)] {
        let lim = ChannelLimits::for_run(n, t, batch);
        let one_max_multi = usize::try_from(lim.chunks).expect("small") * (CHUNK + 16);
        assert!(lim.fault_bytes >= one_max_multi * t);
        let max_single_msg = usize::try_from(lim.chunks).expect("small") * CHUNK + 128;
        let worst_page_hex = 2 * (512 * 1024 + max_single_msg + lim.fault_bytes + 8192);
        let page_cap = max_evidence_page_hex(n, lim);
        assert!(page_cap > worst_page_hex);
        assert!(
            page_cap < 10 * 1024 * 1024,
            "n={n} t={t} batch={batch}: page_cap={page_cap} exceeds 10 MiB WS cap"
        );
    }

    Ok(())
}

#[tokio::test]
async fn poisoned_pool_share_blames_culprit_and_rejects_bad_subset_witness() -> Result<()> {
    use fedimint_lnv2_common::LightningInputError;
    use fedimint_lnv2_common::bolt12::Bolt12Unlock;

    let mut fed = Federation::new();
    fed.start(0, NOW).await?;
    let committee = fed.committee().await.expect("run started");
    let mut dealt = deal(&fed, 0, &committee, 2);

    // Peer 2 (position 2 in committee [0, 1, 2]) submits a corrupted share for
    // item 0 while peers 0 and 1 submit honest shares.
    let bad_peer = committee[2];
    let bad_hash = dealt.submissions[&bad_peer][0].payment_hash;
    dealt.submissions.get_mut(&bad_peer).expect("present")[0] =
        seal(&fed, 0, 2, bad_hash, &[0xde; 32]);

    for (peer, shares) in &dealt.submissions {
        fed.submit(*peer, 0, shares.clone()).await?;
    }

    let offer = pooled_offer(&mut fed).await;
    let gw = gateway();
    fed.approve(&gw).await;

    let request = reserve_pool(&offer, 0, Amount::from_sats(10_000), &gw);
    let reservation_id = request.reservation_id();
    let (_, _) = fed.apply(Bolt12Output::Reserve(request), NOW).await?;

    let (outpoint, _) = fed
        .apply(Bolt12Output::Receive(reservation_id), NOW + 30)
        .await?;

    let Bolt12Unlock::Pool { keys, .. } = fed.unlock(outpoint).await else {
        panic!("expected pool unlock");
    };

    // An invalid witness subset (referencing the corrupted share at index 2)
    // must be rejected immediately.
    let bad_unlock = Bolt12Unlock::new_pool(keys.clone(), Some(vec![0, 2]));
    assert!(matches!(
        fed.spend(outpoint, &bad_unlock).await,
        Err(LightningInputError::InvalidDecryptionKey)
    ));

    // A valid witness subset [0, 1] succeeds, blames peer 2, and clears the
    // sticky committee.
    let good_unlock = Bolt12Unlock::new_pool(keys, Some(vec![0, 1]));
    fed.spend(outpoint, &good_unlock).await?;

    assert!(
        fed.blame(u16::from(bad_peer)).await.is_some(),
        "poisoned pool share submitter must be blamed on spend"
    );
    assert!(fed.blame(u16::from(committee[0])).await.is_none());
    assert!(fed.blame(u16::from(committee[1])).await.is_none());

    Ok(())
}

#[tokio::test]
async fn post_take_equivocation_does_not_overwrite_and_convicts() -> Result<()> {
    use fedimint_core::secp256k1::SecretKey;

    use crate::bolt12::transport::{ChannelLimits, Channels, verify_transport_fault_convicts};
    use crate::db::TransportFault;

    let committee = peers(&[0, 1, 2]);
    let limits = ChannelLimits::for_run(3, 1, 4);
    let secrets: Vec<SecretKey> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
    let keys: BTreeMap<PeerId, _> = (0..3u16)
        .map(|p| {
            (
                PeerId::from(p),
                secrets[usize::from(p)].public_key(SECP256K1),
            )
        })
        .collect();
    let seeds = [[11u8; 32], [22u8; 32], [33u8; 32]];

    let ch0_first = Channels::new(
        0,
        PeerId::from(0),
        committee.clone(),
        limits,
        &seeds[0],
        &secrets[0],
        &keys,
    )?;
    let ch0_second = Channels::new(
        0,
        PeerId::from(0),
        committee.clone(),
        limits,
        &seeds[0],
        &secrets[0],
        &keys,
    )?;
    let ch1 = Channels::new(
        0,
        PeerId::from(1),
        committee,
        limits,
        &seeds[1],
        &secrets[1],
        &keys,
    )?;

    let first_pkts = ch0_first.packets(PeerId::from(1), 0, b"message-A")?;
    for pkt in &first_pkts {
        ch1.receive(pkt)?;
    }

    // Consume peer 0's round-0 message from inbox (simulating normal MPC
    // execution).
    let taken = ch1.take(PeerId::from(0), 0).await;
    assert_eq!(taken, b"message-A");
    assert_eq!(
        ch1.transcript()[0][0]
            .as_ref()
            .map(|m| m.message.as_slice()),
        Some(b"message-A".as_slice())
    );

    // Peer 0 now sends a DIFFERENT validly signed message for the same round 0.
    let second_pkts = ch0_second.packets(PeerId::from(1), 0, b"message-B")?;
    for pkt in &second_pkts {
        let _ = ch1.receive(pkt);
    }

    // Transcript must keep the original message immutably and record a
    // MessageEquivocation fault that convicts peer 0.
    assert_eq!(
        ch1.transcript()[0][0]
            .as_ref()
            .map(|m| m.message.as_slice()),
        Some(b"message-A".as_slice())
    );
    let ev = ch1.relay_evidence();
    assert!(matches!(
        ev.faults.as_slice(),
        [TransportFault::MessageEquivocation { .. }]
    ));
    assert!(verify_transport_fault_convicts(
        0,
        (PeerId::from(0), &keys[&PeerId::from(0)]),
        (PeerId::from(1), &keys[&PeerId::from(1)]),
        &seeds[0],
        &seeds[1],
        &ev.faults[0],
        limits.chunks,
    ));

    Ok(())
}

#[tokio::test]
async fn fake_round0_ephemeral_key_convicts_sender_and_protects_honest() -> Result<()> {
    use fedimint_core::secp256k1::SecretKey;

    use crate::bolt12::transport::{
        ChannelLimits, Channels, MpcPacket, packet_digest, verify_r0_ephemeral_fault,
    };
    use crate::db::BadPacket;

    let committee = peers(&[0, 1, 2]);
    let limits = ChannelLimits::for_run(3, 1, 4);
    let secrets: Vec<SecretKey> = (0..3).map(|_| SecretKey::new(&mut OsRng)).collect();
    let keys: BTreeMap<PeerId, _> = (0..3u16)
        .map(|p| {
            (
                PeerId::from(p),
                secrets[usize::from(p)].public_key(SECP256K1),
            )
        })
        .collect();
    let seeds = [[11u8; 32], [22u8; 32], [33u8; 32]];
    let signer0 = Keypair::from_secret_key(SECP256K1, &secrets[0]);
    let ch0 = Channels::new(
        0,
        PeerId::from(0),
        committee,
        limits,
        &seeds[0],
        &secrets[0],
        &keys,
    )?;

    let to_bad = |p: &MpcPacket| BadPacket {
        sender: p.sender,
        round: p.round,
        chunk: p.chunk,
        chunks: p.chunks,
        ephemeral_pk: p.ephemeral_pk,
        recv_ephemeral_pk: p.recv_ephemeral_pk,
        ciphertext: p.ciphertext.clone(),
        envelope_sig: p.envelope_sig,
    };

    let honest_r0 = ch0.packets(PeerId::from(1), 0, b"r0")?;
    assert!(!verify_r0_ephemeral_fault(
        0,
        (PeerId::from(0), &keys[&PeerId::from(0)]),
        PeerId::from(1),
        &seeds[0],
        &to_bad(&honest_r0[0]),
    ));

    // Forge a Round-0 packet carrying a wrong recv_ephemeral_pk signed by peer 0.
    let fake_recv_eph = secrets[2].public_key(SECP256K1);
    let digest = packet_digest(
        0,
        PeerId::from(0),
        PeerId::from(1),
        0,
        0,
        1,
        honest_r0[0].ephemeral_pk,
        fake_recv_eph,
        &honest_r0[0].ciphertext,
    );
    let fake_bad = BadPacket {
        recv_ephemeral_pk: fake_recv_eph,
        envelope_sig: SECP256K1.sign_schnorr(&digest, &signer0),
        ..to_bad(&honest_r0[0])
    };
    assert!(verify_r0_ephemeral_fault(
        0,
        (PeerId::from(0), &keys[&PeerId::from(0)]),
        PeerId::from(1),
        &seeds[0],
        &fake_bad,
    ));

    Ok(())
}

#[tokio::test]
async fn verdict_rejects_mixed_culprits_and_disputes() -> Result<()> {
    let fed = Federation::new();
    fed.abandon_run(0, NOW).await;

    let mixed = PoolVerdict {
        culprits: vec![PeerId::from(0)],
        disputes: vec![(PeerId::from(1), PeerId::from(2))],
    };
    assert!(
        fed.verdict(0, 0, mixed, NOW + POOL_RUN_TIMEOUT + EVIDENCE_WINDOW)
            .await
            .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn keys_validate_rejects_duplicate_xonly_and_high_degree() -> Result<()> {
    use crate::bolt12::keys;

    let make_cfg = |guardians: u16, public, private| {
        let mut fed = Federation::with_guardians(guardians);
        fed.cfg.consensus.bolt12 = Some(public);
        fed.cfg.private.bolt12 = Some(private);
        fed.cfg
    };

    let peer_ids = peers(&[0, 1, 2, 3]);
    let (mut public, privates) = keys::fixture(&peer_ids)?;
    let cfg = make_cfg(4, public.clone(), privates[&PeerId::from(0)].clone());
    keys::validate(PeerId::from(0), &cfg)?;

    // Duplicate x-only transport key (negated secret key -> opposite parity,
    // same x-only coordinate) must be rejected.
    let pk0 = public.transport_keys[&PeerId::from(0)];
    let negated = pk0.negate(SECP256K1);
    assert_ne!(pk0, negated);
    public.transport_keys.insert(PeerId::from(1), negated);
    let bad_xonly = make_cfg(4, public, privates[&PeerId::from(0)].clone());
    assert!(keys::validate(PeerId::from(0), &bad_xonly).is_err());

    // pool_batch exceeding MAX_POOL_BATCH must be rejected.
    let (mut public2, privates2) = keys::fixture(&peer_ids)?;
    public2.pool_batch = fedimint_lnv2_common::bolt12::MAX_POOL_BATCH + 1;
    let bad_batch = make_cfg(4, public2, privates2[&PeerId::from(0)].clone());
    assert!(keys::validate(PeerId::from(0), &bad_batch).is_err());

    // Degree > MAX_POOL_DEGREE with pool_target > 0 must be rejected.
    let big_peers: Vec<PeerId> = (0..25u16).map(PeerId::from).collect();
    let (mut big_pub, big_privs) = keys::fixture(&big_peers)?;
    assert_eq!(big_pub.pool_target, 0, "high degree auto-disables pool");
    let big_ok = make_cfg(25, big_pub.clone(), big_privs[&PeerId::from(0)].clone());
    keys::validate(PeerId::from(0), &big_ok)?;
    big_pub.pool_target = 4;
    let big_bad = make_cfg(25, big_pub, big_privs[&PeerId::from(0)].clone());
    assert!(keys::validate(PeerId::from(0), &big_bad).is_err());

    Ok(())
}

#[tokio::test]
async fn serve_evidence_streams_multiple_pages_by_entry() -> Result<()> {
    use crate::bolt12::worker::{evidence_digest, serve_evidence};
    use crate::db::{
        Bolt12PoolLocalRunKey, Bolt12PoolTranscriptKey, LocalRun, RelayEvidence, SignedMessage,
    };

    let fed = Federation::new();
    fed.start(0, NOW).await?;
    fed.abandon(0, NOW + POOL_RUN_TIMEOUT).await?;

    let dummy_sig = SECP256K1.sign_schnorr(
        &fedimint_core::secp256k1::Message::from_digest([1; 32]),
        &Keypair::new(SECP256K1, &mut OsRng),
    );
    // 2 rounds * 3 entries * 300 KiB = 1.8 MiB > 512 KiB page budget -> spans
    // multiple pages cleanly.
    let rounds: Vec<Vec<Option<SignedMessage>>> = (0..2)
        .map(|r| {
            (0..3)
                .map(|p| {
                    Some(SignedMessage {
                        message: vec![u8::try_from(r * 10 + p).expect("small"); 300 * 1024],
                        signature: dummy_sig,
                    })
                })
                .collect()
        })
        .collect();

    let relay = RelayEvidence::default();
    let expected_digest = evidence_digest(&[9; 32], &rounds, &relay);

    let mut dbtx = fed.db.begin_transaction().await;
    dbtx.insert_entry(
        &Bolt12PoolLocalRunKey(0),
        &LocalRun {
            seed: [9; 32],
            submission: None,
            evidence: Some(expected_digest),
            transcript_rounds: 2,
        },
    )
    .await;
    for (r, row) in rounds.iter().enumerate() {
        dbtx.insert_entry(&Bolt12PoolTranscriptKey(0, r as u64), row)
            .await;
    }
    dbtx.commit_tx().await;

    let mut from_round = 0u64;
    let mut from_peer = 0u16;
    let mut pages = 0usize;
    let mut reconstructed = vec![vec![None; 3]; 2];

    loop {
        let page = serve_evidence(&fed.db, 0, from_round, from_peer).await?;
        pages += 1;
        assert_eq!(page.total_rounds, 2);
        for (r, p, msg) in page.entries {
            reconstructed[usize::try_from(r)?][usize::from(p)] = Some(msg);
        }
        match page.next_cursor {
            Some((nr, np)) => {
                assert!((nr, np) > (from_round, from_peer));
                from_round = nr;
                from_peer = np;
            }
            None => break,
        }
    }

    assert!(pages >= 3, "expected >= 3 streamed pages, got {pages}");
    assert_eq!(
        evidence_digest(&[9; 32], &reconstructed, &relay),
        expected_digest
    );

    Ok(())
}

#[tokio::test]
async fn funding_reservation_prunes_local_nonce_keys() -> Result<()> {
    use crate::db::{Bolt12NonceCountKey, Bolt12NonceKey};

    let mut fed = Federation::new();
    fed.fill(0).await;
    let offer = pooled_offer(&mut fed).await;
    let gw = gateway();
    fed.approve(&gw).await;

    let request = reserve_pool(&offer, 0, Amount::from_sats(10_000), &gw);
    let reservation_id = request.reservation_id();
    let (_, _) = fed.apply(Bolt12Output::Reserve(request), NOW).await?;

    // Seed local FROST nonce tracking rows for this reservation.
    let mut dbtx = fed.db.begin_transaction().await;
    dbtx.insert_entry(&Bolt12NonceKey(reservation_id, [1; 32]), &true)
        .await;
    dbtx.insert_entry(&Bolt12NonceKey(reservation_id, [2; 32]), &true)
        .await;
    dbtx.insert_entry(&Bolt12NonceCountKey(reservation_id), &2u16)
        .await;
    dbtx.commit_tx().await;

    // Funding consumes the reservation and must prune all local nonce rows.
    let _ = fed
        .apply(Bolt12Output::Receive(reservation_id), NOW + 30)
        .await?;

    let mut dbtx = fed.db.begin_transaction_nc().await;
    assert!(
        dbtx.get_value(&Bolt12NonceCountKey(reservation_id))
            .await
            .is_none()
    );
    assert!(
        dbtx.get_value(&Bolt12NonceKey(reservation_id, [1; 32]))
            .await
            .is_none()
    );
    assert!(
        dbtx.get_value(&Bolt12NonceKey(reservation_id, [2; 32]))
            .await
            .is_none()
    );

    Ok(())
}
