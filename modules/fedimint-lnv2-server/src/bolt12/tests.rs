use std::collections::BTreeMap;

use anyhow::Result;
use fedimint_core::bitcoin::hashes::{Hash, sha256};
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::secp256k1::{Keypair, PublicKey, SECP256K1};
use fedimint_core::{Amount, NumPeersExt, OutPoint, PeerId, TransactionId};
use fedimint_lnv2_common::LightningInputError;
use fedimint_lnv2_common::bolt12::{
    AddStock, Bolt12Config, Bolt12Output, INVOICE_LIFETIME, MAX_PENDING_PER_GATEWAY,
    MAX_PENDING_PER_OFFER, MAX_REGISTRATION_LIFETIME, MAX_STOCK_BATCH, ReceivePolicy, Register,
    RegistrationId, Reservation, ReservationId, Reserve, Source, StockItem, terms_hash,
};
use fedimint_lnv2_common::config::{
    FeeConsensus, LightningConfig, LightningConfigConsensus, LightningConfigPrivate,
};
use fedimint_lnv2_common::gateway_api::PaymentFee;
use rand::rngs::OsRng;
use tpe::{AggregateDecryptionKey, SecretKeyShare, aggregate_dk_shares};

use super::{
    OutputEffect, gateway_is_approved, process_gateway_vote, process_input, process_output,
};
use crate::db::{
    Bolt12ContractKey, Bolt12GatewayPendingKey, Bolt12OfferPendingKey, Bolt12RegistrationCountKey,
    Bolt12RegistrationKey, Bolt12ReservationKey, Bolt12StreamIndexKey, Bolt12StreamKey,
    DecryptionKeyShareKey,
};
use crate::{dealer_agg_pk, dealer_pk, dealer_polynomial, dealer_sk};

const NOW: u64 = 1_700_000_000;
const GUARDIANS: u16 = 4;

struct Federation {
    db: Database,
    /// Guardian 0's view; consensus rules only read its private key share when
    /// funding a receive.
    cfg: LightningConfig,
    sks: BTreeMap<PeerId, SecretKeyShare>,
    outputs: u64,
}

impl Federation {
    fn new() -> Self {
        let peers: Vec<PeerId> = (0..GUARDIANS).map(PeerId::from).collect();
        let polynomial = dealer_polynomial(peers.to_num_peers());
        let sks: BTreeMap<_, _> = peers
            .iter()
            .map(|peer| (*peer, dealer_sk(&polynomial, *peer)))
            .collect();

        let cfg = LightningConfig {
            consensus: LightningConfigConsensus {
                tpe_agg_pk: dealer_agg_pk(&polynomial),
                tpe_pks: peers
                    .iter()
                    .map(|peer| (*peer, dealer_pk(&polynomial, *peer)))
                    .collect(),
                fee_consensus: FeeConsensus::new(1_000).expect("fee is within range"),
                network: fedimint_core::bitcoin::Network::Regtest,
                bolt12: Some(Bolt12Config {
                    public_package: vec![],
                    transport_keys: BTreeMap::new(),
                    registration_fee: Bolt12Config::DEFAULT_REGISTRATION_FEE,
                    stock_item_fee: Bolt12Config::DEFAULT_STOCK_ITEM_FEE,
                    receive_fee: Amount::from_sats(3),
                }),
            },
            private: LightningConfigPrivate {
                sk: sks[&PeerId::from(0)],
                bolt12: None,
            },
        };

        Self {
            db: Database::new(MemDatabase::new(), ModuleRegistry::default()),
            cfg,
            sks,
            outputs: 0,
        }
    }

    fn next_outpoint(&mut self) -> OutPoint {
        self.outputs += 1;

        OutPoint {
            txid: TransactionId::from_byte_array(
                sha256::Hash::hash(&self.outputs.to_be_bytes()).to_byte_array(),
            ),
            out_idx: 0,
        }
    }

    /// Apply an output the way the server does: keep its writes only if it
    /// was accepted.
    async fn apply(&mut self, output: Bolt12Output, now: u64) -> Result<(OutPoint, OutputEffect)> {
        let outpoint = self.next_outpoint();
        let mut dbtx = self.db.begin_transaction().await;

        let effect =
            process_output(&mut dbtx.to_ref_nc(), &self.cfg, &output, outpoint, now).await?;

        dbtx.commit_tx().await;

        Ok((outpoint, effect))
    }

    /// Why an output is rejected, or `None` if it is accepted and applied.
    async fn rejection(&mut self, output: Bolt12Output, now: u64) -> Option<String> {
        self.apply(output, now).await.err().map(|e| e.to_string())
    }

    async fn vote(&self, peer: u16, gateway: PublicKey, approve: bool) -> Result<()> {
        let mut dbtx = self.db.begin_transaction().await;

        process_gateway_vote(
            &mut dbtx.to_ref_nc(),
            &self.cfg,
            PeerId::from(peer),
            gateway,
            approve,
        )
        .await?;

        dbtx.commit_tx().await;

        Ok(())
    }

    async fn approve(&self, gateway: &Keypair) {
        for peer in 0..3 {
            self.vote(peer, gateway.public_key(), true)
                .await
                .expect("first vote is not redundant");
        }
    }

    async fn spend(
        &self,
        outpoint: OutPoint,
        key: &AggregateDecryptionKey,
    ) -> Result<(PublicKey, Amount), LightningInputError> {
        let mut dbtx = self.db.begin_transaction().await;

        let result = process_input(&mut dbtx.to_ref_nc(), &self.cfg, outpoint, key).await?;

        dbtx.commit_tx().await;

        Ok(result)
    }

    /// Aggregate decryption shares from a quorum that includes guardian 0's
    /// share as stored by the funding output.
    async fn aggregate_key(&self, outpoint: OutPoint) -> AggregateDecryptionKey {
        let mut dbtx = self.db.begin_transaction_nc().await;

        let contract = dbtx
            .get_value(&Bolt12ContractKey(outpoint))
            .await
            .expect("receive is funded");
        let stored = dbtx
            .get_value(&DecryptionKeyShareKey(outpoint))
            .await
            .expect("funding stored our share");

        let mut shares = BTreeMap::new();

        for peer in 0..3u16 {
            let share = tpe::create_dk_share(&self.sks[&PeerId::from(peer)], &contract.ciphertext);

            assert!(
                contract.verify_decryption_share(
                    &self.cfg.consensus.tpe_pks[&PeerId::from(peer)],
                    &share
                )
            );

            shares.insert(u64::from(peer), share);
        }

        assert_eq!(shares[&0], stored);

        aggregate_dk_shares(&shares)
    }

    async fn reservation(&self, id: ReservationId) -> Option<Reservation> {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12ReservationKey(id))
            .await
    }
}

struct Offer {
    key: Keypair,
    id: RegistrationId,
    policy: ReceivePolicy,
}

fn policy(key: &Keypair, expires_at: u64) -> ReceivePolicy {
    ReceivePolicy {
        handle: rand::random(),
        claim_pk: key.public_key(),
        offer_hash: sha256::Hash::hash(b"offer"),
        max_gateway_fee: PaymentFee {
            base: Amount::from_sats(50),
            parts_per_million: 5_000,
        },
        expires_at,
        allow_pool: false,
    }
}

fn preimage(offer: &Offer, index: u64) -> [u8; 32] {
    sha256::Hash::hash(&[&offer.key.secret_bytes()[..], &index.to_be_bytes()[..]].concat())
        .to_byte_array()
}

fn stock(fed: &Federation, offer: &Offer, start: u64, count: u64) -> Vec<StockItem> {
    (start..start + count)
        .map(|index| {
            StockItem::new(
                &fed.cfg.consensus.tpe_agg_pk,
                offer.id,
                index,
                &preimage(offer, index),
                &rand::random(),
            )
        })
        .collect()
}

async fn register(fed: &mut Federation, expires_at: u64, now: u64) -> Offer {
    let key = Keypair::new(SECP256K1, &mut OsRng);
    let policy = policy(&key, expires_at);

    fed.apply(
        Bolt12Output::Register(Register::new(policy.clone(), &key)),
        now,
    )
    .await
    .expect("registration is valid");

    Offer {
        key,
        id: policy.id(),
        policy,
    }
}

async fn offer_with_stock(fed: &mut Federation, count: u64) -> Offer {
    let offer = register(fed, NOW + 86_400, NOW).await;
    let items = stock(fed, &offer, 0, count);

    fed.apply(
        Bolt12Output::AddStock(AddStock::new(offer.id, 0, items, &offer.key)),
        NOW,
    )
    .await
    .expect("stock is valid");

    offer
}

fn reserve(offer: &Offer, index: u64, gateway: &Keypair) -> Reserve {
    Reserve::new(
        offer.id,
        Source::Stock { index },
        Amount::from_sats(10_000),
        Amount::from_sats(60),
        terms_hash(b"request", b"path"),
        gateway,
    )
}

fn gateway() -> Keypair {
    Keypair::new(SECP256K1, &mut OsRng)
}

#[tokio::test]
async fn funded_receive_is_claimable_by_the_recipient() -> Result<()> {
    let mut fed = Federation::new();
    let gateway = gateway();
    let offer = offer_with_stock(&mut fed, 2).await;

    fed.approve(&gateway).await;

    let request = reserve(&offer, 0, &gateway);
    let id = request.reservation_id();

    let (_, effect) = fed.apply(Bolt12Output::Reserve(request), NOW).await?;

    // Reservations move nothing and cost nothing.
    assert_eq!((effect.amount, effect.fee), (Amount::ZERO, Amount::ZERO));
    assert!(!effect.funded);

    let reservation = fed.reservation(id).await.expect("reservation is stored");

    assert_eq!(reservation.claim_pk, offer.policy.claim_pk);
    assert_eq!(
        reservation.payment_hash,
        sha256::Hash::hash(&preimage(&offer, 0)).to_byte_array()
    );

    let (outpoint, effect) = fed.apply(Bolt12Output::Receive(id), NOW + 30).await?;
    let net = Amount::from_sats(10_000 - 60);

    assert!(effect.funded);
    assert_eq!(effect.amount, net);
    assert_eq!(
        effect.fee,
        fed.cfg.consensus.fee_consensus.fee(net) + Amount::from_sats(3)
    );

    // Funding consumes the reservation, so it cannot be funded twice.
    assert!(fed.reservation(id).await.is_none());
    assert!(
        fed.apply(Bolt12Output::Receive(id), NOW + 31)
            .await
            .is_err()
    );

    let mut dbtx = fed.db.begin_transaction_nc().await;

    assert_eq!(dbtx.get_value(&Bolt12StreamIndexKey).await, Some(1));
    assert_eq!(
        dbtx.get_value(&Bolt12StreamKey(0))
            .await
            .expect("receive is streamed")
            .outpoint,
        outpoint
    );
    assert!(
        dbtx.get_value(&Bolt12OfferPendingKey(offer.id))
            .await
            .is_none()
    );
    assert!(
        dbtx.get_value(&Bolt12GatewayPendingKey(gateway.public_key()))
            .await
            .is_none()
    );

    drop(dbtx);

    let key = fed.aggregate_key(outpoint).await;
    let contract = fed
        .db
        .begin_transaction_nc()
        .await
        .get_value(&Bolt12ContractKey(outpoint))
        .await
        .expect("receive is funded");

    assert_eq!(contract.decrypt_preimage(&key), Some(preimage(&offer, 0)));
    assert_eq!(
        fed.spend(outpoint, &key).await,
        Ok((offer.policy.claim_pk, net))
    );

    // Spending removes the contract and its stream entry.
    assert_eq!(
        fed.spend(outpoint, &key).await,
        Err(LightningInputError::UnknownContract)
    );
    assert!(
        fed.db
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12StreamKey(0))
            .await
            .is_none()
    );

    Ok(())
}

#[tokio::test]
async fn wrong_decryption_key_cannot_spend() -> Result<()> {
    let mut fed = Federation::new();
    let gateway = gateway();
    let offer = offer_with_stock(&mut fed, 2).await;

    fed.approve(&gateway).await;

    let first = reserve(&offer, 0, &gateway);
    let second = reserve(&offer, 1, &gateway);
    let (first_id, second_id) = (first.reservation_id(), second.reservation_id());

    fed.apply(Bolt12Output::Reserve(first), NOW).await?;
    fed.apply(Bolt12Output::Reserve(second), NOW).await?;

    let (first_outpoint, _) = fed.apply(Bolt12Output::Receive(first_id), NOW).await?;
    let (second_outpoint, _) = fed.apply(Bolt12Output::Receive(second_id), NOW).await?;

    // A valid key for one receive is not a valid key for another.
    let other_key = fed.aggregate_key(second_outpoint).await;

    assert_eq!(
        fed.spend(first_outpoint, &other_key).await,
        Err(LightningInputError::InvalidDecryptionKey)
    );

    // The rejected attempt left the contract in place.
    let key = fed.aggregate_key(first_outpoint).await;

    assert!(fed.spend(first_outpoint, &key).await.is_ok());

    Ok(())
}

#[tokio::test]
async fn stock_without_the_preimage_refunds_the_gateway_and_voids_the_offer() -> Result<()> {
    let mut fed = Federation::new();
    let gateway = gateway();
    let offer = register(&mut fed, NOW + 86_400, NOW).await;

    // A well-formed ciphertext whose plaintext does not hash to the payment
    // hash. Guardians cannot tell until it is decrypted.
    let payment_hash = sha256::Hash::hash(b"some other preimage").to_byte_array();
    let bad = StockItem {
        payment_hash,
        ciphertext: tpe::encrypt_preimage(
            &fed.cfg.consensus.tpe_agg_pk,
            &rand::random(),
            &[7; 32],
            &Source::Stock { index: 0 }.binding(offer.id, payment_hash),
        ),
    };
    let good = stock(&fed, &offer, 1, 1).remove(0);

    fed.apply(
        Bolt12Output::AddStock(AddStock::new(offer.id, 0, vec![bad, good], &offer.key)),
        NOW,
    )
    .await?;
    fed.approve(&gateway).await;

    let request = reserve(&offer, 0, &gateway);
    let id = request.reservation_id();

    fed.apply(Bolt12Output::Reserve(request), NOW).await?;

    let (outpoint, _) = fed.apply(Bolt12Output::Receive(id), NOW).await?;
    let key = fed.aggregate_key(outpoint).await;

    assert_eq!(
        fed.spend(outpoint, &key).await,
        Ok((gateway.public_key(), Amount::from_sats(10_000 - 60)))
    );

    // The remaining, valid stock can no longer be reserved.
    let error = fed
        .apply(Bolt12Output::Reserve(reserve(&offer, 1, &gateway)), NOW)
        .await
        .err()
        .expect("voided offer rejects reservations");

    assert!(error.to_string().contains("voided"));

    Ok(())
}

#[tokio::test]
async fn reservation_requires_an_approved_gateway_and_policy_compliant_terms() -> Result<()> {
    let mut fed = Federation::new();
    let gateway = gateway();
    let offer = offer_with_stock(&mut fed, 4).await;

    // Two approvals are below the quorum of three.
    fed.vote(0, gateway.public_key(), true).await?;
    fed.vote(1, gateway.public_key(), true).await?;

    assert!(
        fed.rejection(Bolt12Output::Reserve(reserve(&offer, 0, &gateway)), NOW)
            .await
            .expect("unapproved gateway is rejected")
            .contains("not approved")
    );

    fed.vote(2, gateway.public_key(), true).await?;

    // The signature covers every field.
    let mut tampered = reserve(&offer, 0, &gateway);
    tampered.amount = Amount::from_sats(20_000);

    assert!(
        fed.rejection(Bolt12Output::Reserve(tampered), NOW)
            .await
            .expect("tampered reservation is rejected")
            .contains("signature")
    );

    // 50 sats + 0.5% of 10,000 sats is the most the policy allows.
    let greedy = Reserve::new(
        offer.id,
        Source::Stock { index: 0 },
        Amount::from_sats(10_000),
        Amount::from_sats(101),
        terms_hash(b"request", b"path"),
        &gateway,
    );

    assert!(
        fed.rejection(Bolt12Output::Reserve(greedy), NOW)
            .await
            .is_some()
    );

    // One sat cannot cover the fee the recipient pays to claim it.
    let dust = Reserve::new(
        offer.id,
        Source::Stock { index: 0 },
        Amount::from_sats(1),
        Amount::ZERO,
        terms_hash(b"request", b"path"),
        &gateway,
    );

    assert!(
        fed.rejection(Bolt12Output::Reserve(dust), NOW)
            .await
            .is_some()
    );

    assert!(
        fed.rejection(Bolt12Output::Reserve(reserve(&offer, 9, &gateway)), NOW)
            .await
            .expect("missing stock is rejected")
            .contains("stock item")
    );

    assert!(
        fed.rejection(
            Bolt12Output::Reserve(reserve(&offer, 0, &gateway)),
            NOW + 86_400
        )
        .await
        .expect("expired offer is rejected")
        .contains("expired")
    );

    // None of the rejected attempts consumed the stock item.
    fed.apply(Bolt12Output::Reserve(reserve(&offer, 0, &gateway)), NOW)
        .await?;

    // A stock item is single use, even after its invoice expires unpaid.
    assert!(
        fed.rejection(
            Bolt12Output::Reserve(reserve(&offer, 0, &gateway)),
            NOW + INVOICE_LIFETIME + 1
        )
        .await
        .is_some()
    );

    // Withdrawing one approval drops the gateway below quorum.
    fed.vote(1, gateway.public_key(), false).await?;

    assert!(
        fed.rejection(Bolt12Output::Reserve(reserve(&offer, 1, &gateway)), NOW)
            .await
            .expect("revoked gateway is rejected")
            .contains("not approved")
    );

    Ok(())
}

#[tokio::test]
async fn gateway_votes_reject_repeats_and_count_per_guardian() -> Result<()> {
    let fed = Federation::new();
    let gateway = gateway().public_key();

    let approved = |fed: &Federation| {
        let db = fed.db.clone();
        let cfg = fed.cfg.clone();

        async move { gateway_is_approved(&mut db.begin_transaction_nc().await, &cfg, gateway).await }
    };

    // An absent vote is a rejection, so rejecting first is redundant.
    assert!(fed.vote(0, gateway, false).await.is_err());

    fed.vote(0, gateway, true).await?;

    assert!(fed.vote(0, gateway, true).await.is_err());

    // One guardian voting repeatedly never reaches quorum.
    fed.vote(0, gateway, false).await?;
    fed.vote(0, gateway, true).await?;

    assert!(!approved(&fed).await);

    fed.vote(1, gateway, true).await?;
    fed.vote(2, gateway, true).await?;

    assert!(approved(&fed).await);

    Ok(())
}

#[tokio::test]
async fn unpaid_reservations_are_bounded_per_offer_and_free_up_on_expiry_or_payment() -> Result<()>
{
    let mut fed = Federation::new();
    let gateway = gateway();
    let offer = offer_with_stock(&mut fed, 32).await;

    fed.approve(&gateway).await;

    let mut ids = vec![];

    for index in 0..MAX_PENDING_PER_OFFER as u64 {
        let request = reserve(&offer, index, &gateway);

        ids.push(request.reservation_id());

        fed.apply(Bolt12Output::Reserve(request), NOW).await?;
    }

    let over = fed
        .apply(Bolt12Output::Reserve(reserve(&offer, 8, &gateway)), NOW + 1)
        .await
        .err()
        .expect("ninth unpaid invoice is rejected");

    assert!(over.to_string().contains("this offer"));

    // Paying one invoice frees its slot immediately.
    fed.apply(Bolt12Output::Receive(ids[0]), NOW + 1).await?;
    fed.apply(Bolt12Output::Reserve(reserve(&offer, 8, &gateway)), NOW + 1)
        .await?;

    assert!(
        fed.apply(Bolt12Output::Reserve(reserve(&offer, 9, &gateway)), NOW + 1)
            .await
            .is_err()
    );

    // Once the first batch expires its slots free up and its rows are deleted;
    // the reservation made at NOW + 1 is still pending.
    let later = NOW + INVOICE_LIFETIME;

    fed.apply(Bolt12Output::Reserve(reserve(&offer, 9, &gateway)), later)
        .await?;

    for id in &ids[1..] {
        assert!(fed.reservation(*id).await.is_none());
    }

    let pending = fed
        .db
        .begin_transaction_nc()
        .await
        .get_value(&Bolt12OfferPendingKey(offer.id))
        .await
        .expect("two reservations are pending");

    assert_eq!(pending.len(), 2);

    // An expired reservation cannot be funded.
    assert!(
        fed.apply(Bolt12Output::Receive(ids[1]), later)
            .await
            .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn expired_invoice_cannot_be_funded() -> Result<()> {
    let mut fed = Federation::new();
    let gateway = gateway();
    let offer = offer_with_stock(&mut fed, 1).await;

    fed.approve(&gateway).await;

    let request = reserve(&offer, 0, &gateway);
    let id = request.reservation_id();

    fed.apply(Bolt12Output::Reserve(request), NOW).await?;

    let error = fed
        .apply(Bolt12Output::Receive(id), NOW + INVOICE_LIFETIME)
        .await
        .err()
        .expect("funding at expiry is rejected");

    assert!(error.to_string().contains("expired"));

    // The rejection rolled back, so funding one second earlier still works.
    fed.apply(Bolt12Output::Receive(id), NOW + INVOICE_LIFETIME - 1)
        .await?;

    Ok(())
}

#[tokio::test]
async fn unpaid_reservations_are_bounded_per_gateway_across_offers() -> Result<()> {
    let mut fed = Federation::new();
    let gateway = gateway();
    let other_gateway = self::gateway();

    fed.approve(&gateway).await;
    fed.approve(&other_gateway).await;

    let mut offers = vec![];

    for _ in 0..=MAX_PENDING_PER_GATEWAY / MAX_PENDING_PER_OFFER {
        offers.push(offer_with_stock(&mut fed, MAX_PENDING_PER_OFFER as u64).await);
    }

    let mut reserved = 0;

    'fill: for offer in &offers {
        for index in 0..MAX_PENDING_PER_OFFER as u64 {
            if reserved == MAX_PENDING_PER_GATEWAY {
                break 'fill;
            }

            fed.apply(Bolt12Output::Reserve(reserve(offer, index, &gateway)), NOW)
                .await?;

            reserved += 1;
        }
    }

    let last = offers.last().expect("offers exist");

    let over = fed
        .apply(Bolt12Output::Reserve(reserve(last, 0, &gateway)), NOW)
        .await
        .err()
        .expect("gateway allowance is exhausted");

    assert!(over.to_string().contains("this gateway"));

    // Another gateway has its own allowance for the same offer.
    fed.apply(Bolt12Output::Reserve(reserve(last, 0, &other_gateway)), NOW)
        .await?;

    Ok(())
}

#[tokio::test]
async fn stock_uploads_are_validated() -> Result<()> {
    let mut fed = Federation::new();
    let offer = register(&mut fed, NOW + 86_400, NOW).await;
    let other = register(&mut fed, NOW + 86_400, NOW).await;

    let items = stock(&fed, &offer, 0, 2);

    // Wrong signer.
    let add = AddStock::new(offer.id, 0, items.clone(), &other.key);
    assert!(
        fed.rejection(Bolt12Output::AddStock(add), NOW)
            .await
            .is_some()
    );

    // Wrong start index: the ciphertexts are bound to indices 0 and 1.
    let add = AddStock::new(offer.id, 1, items.clone(), &offer.key);
    assert!(
        fed.rejection(Bolt12Output::AddStock(add), NOW)
            .await
            .is_some()
    );

    // A ciphertext bound to another registration.
    let foreign = stock(&fed, &other, 0, 1);
    let add = AddStock::new(offer.id, 0, foreign, &offer.key);
    assert!(
        fed.rejection(Bolt12Output::AddStock(add), NOW)
            .await
            .is_some()
    );

    // The same payment hash twice in one batch.
    let mut repeated = stock(&fed, &offer, 0, 1);
    let payment_hash = repeated[0].payment_hash;
    repeated.push(StockItem {
        payment_hash,
        ciphertext: tpe::encrypt_preimage(
            &fed.cfg.consensus.tpe_agg_pk,
            &rand::random(),
            &preimage(&offer, 0),
            &Source::Stock { index: 1 }.binding(offer.id, payment_hash),
        ),
    });
    let add = AddStock::new(offer.id, 0, repeated, &offer.key);
    assert!(
        fed.rejection(Bolt12Output::AddStock(add), NOW)
            .await
            .is_some()
    );

    // Empty and oversized batches.
    let add = AddStock::new(offer.id, 0, vec![], &offer.key);
    assert!(
        fed.rejection(Bolt12Output::AddStock(add), NOW)
            .await
            .is_some()
    );

    let oversized = stock(&fed, &offer, 0, MAX_STOCK_BATCH as u64 + 1);
    let add = AddStock::new(offer.id, 0, oversized, &offer.key);
    assert!(
        fed.rejection(Bolt12Output::AddStock(add), NOW)
            .await
            .is_some()
    );

    let (_, effect) = fed
        .apply(
            Bolt12Output::AddStock(AddStock::new(offer.id, 0, items.clone(), &offer.key)),
            NOW,
        )
        .await?;

    assert_eq!(effect.amount, Amount::ZERO);
    assert_eq!(effect.fee, Amount::from_sats(2));

    // The same hashes cannot be uploaded again, by anyone.
    let add = AddStock::new(offer.id, 2, items, &offer.key);
    assert!(
        fed.rejection(Bolt12Output::AddStock(add), NOW)
            .await
            .is_some()
    );

    let registration = fed
        .db
        .begin_transaction_nc()
        .await
        .get_value(&Bolt12RegistrationKey(offer.id))
        .await
        .expect("registration exists");

    assert_eq!((registration.stock_len, registration.stock_unused), (2, 2));

    Ok(())
}

#[tokio::test]
async fn registrations_are_validated() -> Result<()> {
    let mut fed = Federation::new();

    let key = Keypair::new(SECP256K1, &mut OsRng);
    let other_key = Keypair::new(SECP256K1, &mut OsRng);

    // Signed by a key other than the claim key.
    let register = Register::new(policy(&key, NOW + 100), &other_key);
    assert!(
        fed.rejection(Bolt12Output::Register(register), NOW)
            .await
            .is_some()
    );

    // Already expired, and expiring too far ahead.
    let register = Register::new(policy(&key, NOW), &key);
    assert!(
        fed.rejection(Bolt12Output::Register(register), NOW)
            .await
            .is_some()
    );

    let register = Register::new(policy(&key, NOW + MAX_REGISTRATION_LIFETIME + 1), &key);
    assert!(
        fed.rejection(Bolt12Output::Register(register), NOW)
            .await
            .is_some()
    );

    let short_lived = policy(&key, NOW + 100);
    let (_, effect) = fed
        .apply(
            Bolt12Output::Register(Register::new(short_lived.clone(), &key)),
            NOW,
        )
        .await?;

    assert_eq!(effect.fee, Bolt12Config::DEFAULT_REGISTRATION_FEE);

    // The claim key and the handle are each unique among live registrations.
    let register = Register::new(policy(&key, NOW + 200), &key);
    assert!(
        fed.rejection(Bolt12Output::Register(register), NOW)
            .await
            .is_some()
    );

    let mut same_handle = policy(&other_key, NOW + 200);
    same_handle.handle = short_lived.handle;
    let register = Register::new(same_handle, &other_key);
    assert!(
        fed.rejection(Bolt12Output::Register(register), NOW)
            .await
            .is_some()
    );

    Ok(())
}

#[tokio::test]
async fn expired_registrations_are_pruned_with_their_unused_stock() -> Result<()> {
    let mut fed = Federation::new();
    let key = Keypair::new(SECP256K1, &mut OsRng);
    let short_lived = policy(&key, NOW + 100);

    fed.apply(
        Bolt12Output::Register(Register::new(short_lived.clone(), &key)),
        NOW,
    )
    .await?;

    let offer = Offer {
        key,
        id: short_lived.id(),
        policy: short_lived,
    };
    let items = stock(&fed, &offer, 0, 2);

    fed.apply(
        Bolt12Output::AddStock(AddStock::new(offer.id, 0, items.clone(), &offer.key)),
        NOW,
    )
    .await?;

    let gateway = gateway();

    fed.approve(&gateway).await;

    let request = reserve(&offer, 0, &gateway);
    let reservation = request.reservation_id();

    fed.apply(Bolt12Output::Reserve(request), NOW + 99).await?;

    // Expired but still inside the window in which its last invoice could be
    // funded: a new registration does not prune it yet.
    let before = NOW + 100 + INVOICE_LIFETIME - 1;

    register_at(&mut fed, before).await;

    assert!(
        fed.db
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12RegistrationKey(offer.id))
            .await
            .is_some()
    );

    let after = NOW + 100 + INVOICE_LIFETIME;

    register_at(&mut fed, after).await;

    let mut dbtx = fed.db.begin_transaction_nc().await;

    assert!(
        dbtx.get_value(&Bolt12RegistrationKey(offer.id))
            .await
            .is_none()
    );
    assert!(
        dbtx.get_value(&Bolt12ReservationKey(reservation))
            .await
            .is_none()
    );
    assert!(
        dbtx.get_value(&Bolt12OfferPendingKey(offer.id))
            .await
            .is_none()
    );
    // Two registrations made by `register_at` remain.
    assert_eq!(dbtx.get_value(&Bolt12RegistrationCountKey).await, Some(2));

    drop(dbtx);

    // The pruned offer's key and handle can be registered again. Its unused
    // hash can be uploaded again; the one that reached a reservation cannot.
    let renewed = policy(&offer.key, after + 1_000);
    let renewed_id = renewed.id();

    fed.apply(
        Bolt12Output::Register(Register::new(renewed, &offer.key)),
        after,
    )
    .await?;

    let reissue = |index: u64, item: &StockItem| StockItem {
        payment_hash: item.payment_hash,
        ciphertext: tpe::encrypt_preimage(
            &fed.cfg.consensus.tpe_agg_pk,
            &rand::random(),
            &preimage(&offer, index),
            &Source::Stock { index: 0 }.binding(renewed_id, item.payment_hash),
        ),
    };
    let reserved_hash = reissue(0, &items[0]);
    let unused_hash = reissue(1, &items[1]);

    assert!(
        fed.apply(
            Bolt12Output::AddStock(AddStock::new(
                renewed_id,
                0,
                vec![reserved_hash],
                &offer.key
            )),
            after,
        )
        .await
        .is_err()
    );

    fed.apply(
        Bolt12Output::AddStock(AddStock::new(renewed_id, 0, vec![unused_hash], &offer.key)),
        after,
    )
    .await?;

    Ok(())
}

async fn register_at(fed: &mut Federation, now: u64) {
    register(fed, now + 86_400, now).await;
}

#[tokio::test]
async fn outputs_are_rejected_when_the_feature_is_disabled() {
    let mut fed = Federation::new();

    fed.cfg.consensus.bolt12 = None;

    let key = Keypair::new(SECP256K1, &mut OsRng);
    let output = Bolt12Output::Register(Register::new(policy(&key, NOW + 100), &key));

    assert!(fed.apply(output, NOW).await.is_err());
    assert!(fed.vote(0, key.public_key(), true).await.is_err());
}
