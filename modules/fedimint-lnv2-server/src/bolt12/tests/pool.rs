//! Consensus rules for generation runs and pool-backed receives. Shares are
//! dealt directly here; `fedimint-mpc` has its own tests of generating them.

use std::collections::BTreeMap;

use anyhow::Result;
use fedimint_core::bitcoin::hashes::{Hash, sha256};
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::secp256k1::{Keypair, SECP256K1};
use fedimint_core::{Amount, PeerId};
use fedimint_lnv2_common::bolt12::{
    Bolt12Output, POOL_RUN_TIMEOUT, PoolShare, Register, Reserve, Sealed, Source,
    pool_share_binding, terms_hash,
};
use mpc::field::{F, point};
use rand::rngs::OsRng;

use super::{Federation, NOW, Offer, gateway, policy, register};
use crate::bolt12::pool::{self, pool_len};
use crate::db::{Bolt12PoolRunKey, Bolt12ReservationKey};

/// Preimages dealt as threshold-two shares to a three-member committee, and
/// each member's submission.
struct Dealt {
    preimages: Vec<[u8; 32]>,
    submissions: BTreeMap<PeerId, Vec<PoolShare>>,
}

fn words(value: &[u8; 32]) -> [F; 4] {
    std::array::from_fn(|w| {
        F(u64::from_be_bytes(
            value[w * 8..w * 8 + 8].try_into().expect("eight bytes"),
        ))
    })
}

fn share(preimage: &[u8; 32], coefficient: &[u8; 32], position: usize) -> [u8; 32] {
    let mut out = [0; 32];
    let x = point(position + 1);

    for (w, (r, c)) in words(preimage)
        .into_iter()
        .zip(words(coefficient))
        .enumerate()
    {
        out[w * 8..w * 8 + 8].copy_from_slice(&(r + c * x).0.to_be_bytes());
    }

    out
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

    fed.start(1, NOW + POOL_RUN_TIMEOUT).await?;

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
            &fed.cfg
        )
        .await
        .is_none()
    );

    Ok(())
}
