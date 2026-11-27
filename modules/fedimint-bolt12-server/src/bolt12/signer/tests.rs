use std::collections::BTreeMap;

use anyhow::Result;
use bls12_381::Scalar;
use fedimint_bolt12_common::bolt12::invoice::{
    Issuer, Terms, encode_payment_path, offer_hash, routing_metadata, sign, unsigned_invoice,
};
use fedimint_bolt12_common::bolt12::{
    INVOICE_LIFETIME, NonceRequest, ReceivePolicy, Registration, RegistrationId, Reservation,
    ReservationId, Sealed, SignRequest, Source, terms_hash,
};
use fedimint_bolt12_common::config::{
    Bolt12ConfigConsensus, Bolt12ConfigPrivate, Bolt12ModuleConfig, FeeConsensus,
};
use fedimint_bolt12_common::gateway_api::PaymentFee;
use fedimint_core::bitcoin::Network;
use fedimint_core::bitcoin::hashes::{Hash, sha256};
use fedimint_core::config::FederationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, PublicKey, SECP256K1, SecretKey};
use fedimint_core::{Amount, PeerId};
use frost_secp256k1_tr as frost;
use lightning::blinded_path::payment::{
    BlindedPaymentPath, Bolt12OfferContext, PaymentConstraints, PaymentContext,
    UnauthenticatedReceiveTlvs,
};
use lightning::ln::channelmanager::PaymentId;
use lightning::ln::inbound_payment::ExpandedKey;
use lightning::offers::invoice_request::{InvoiceRequest, InvoiceRequestFields};
use lightning::offers::nonce::Nonce;
use lightning::offers::offer::{Offer, OfferBuilder};
use lightning::sign::EntropySource;
use lightning::types::payment::PaymentSecret;
use lightning::util::ser::Writeable;
use rand::rngs::OsRng;

use super::{Approval, MAX_ATTEMPTS, Signer, approve};
use crate::bolt12::keys;
use crate::db::{Bolt12RegistrationKey, Bolt12ReservationKey};

const NOW: u64 = 1_700_000_000;
const AMOUNT_MSATS: u64 = 50_000;

struct Entropy;

impl EntropySource for Entropy {
    fn get_secure_random_bytes(&self) -> [u8; 32] {
        rand::random()
    }
}

fn configs() -> Result<BTreeMap<PeerId, Bolt12ModuleConfig>> {
    configs_for(4)
}

fn configs_for(n: u16) -> Result<BTreeMap<PeerId, Bolt12ModuleConfig>> {
    let peers = (0..n).map(PeerId::from).collect::<Vec<_>>();
    let (public, private) = keys::fixture(&peers)?;

    // Signing never touches the encryption keys, so one dummy share serves all.
    let secret = tpe::SecretKeyShare(Scalar::from(1));
    let pk = tpe::derive_pk_share(&secret);

    Ok(peers
        .iter()
        .map(|peer| {
            (
                *peer,
                Bolt12ModuleConfig {
                    consensus: Bolt12ConfigConsensus {
                        tpe_agg_pk: tpe::AggregatePublicKey(pk.0),
                        tpe_pks: peers.iter().map(|peer| (*peer, pk)).collect(),
                        fee_consensus: FeeConsensus::zero(),
                        network: Network::Regtest,
                        bolt12: public.clone(),
                    },
                    private: Bolt12ConfigPrivate {
                        sk: secret,
                        bolt12: private[peer].clone(),
                    },
                },
            )
        })
        .collect())
}

fn database() -> Database {
    Database::new(MemDatabase::new(), ModuleRegistry::default())
}

fn offer(issuer: PublicKey, handle: [u8; 32]) -> Offer {
    OfferBuilder::new(issuer)
        .chain(Network::Regtest)
        .description("federated receive".to_string())
        .metadata(routing_metadata(FederationId::dummy(), handle))
        .expect("metadata fits")
        .build()
        .expect("offer is valid")
}

fn invoice_request(offer: &Offer, amount_msats: u64) -> InvoiceRequest {
    offer
        .request_invoice(
            &ExpandedKey::new(rand::random()),
            Nonce::from_entropy_source(&Entropy),
            SECP256K1,
            PaymentId(rand::random()),
        )
        .expect("offer accepts requests")
        .chain(Network::Regtest)
        .expect("offer supports regtest")
        .amount_msats(amount_msats)
        .expect("amount is acceptable")
        .build_and_sign()
        .expect("payer can sign")
}

fn payment_path(offer: &Offer, request: &InvoiceRequest) -> BlindedPaymentPath {
    let node = SecretKey::new(&mut OsRng).public_key(SECP256K1);

    let tlvs = UnauthenticatedReceiveTlvs {
        payment_secret: PaymentSecret(rand::random()),
        payment_constraints: PaymentConstraints {
            max_cltv_expiry: 10_000,
            htlc_minimum_msat: 1,
        },
        payment_context: PaymentContext::Bolt12Offer(Bolt12OfferContext {
            offer_id: offer.id(),
            invoice_request: InvoiceRequestFields {
                payer_signing_pubkey: request.payer_signing_pubkey(),
                quantity: request.quantity(),
                payer_note_truncated: None,
                human_readable_name: None,
            },
        }),
    }
    .authenticate(
        Nonce::from_entropy_source(&Entropy),
        &ExpandedKey::new(rand::random()),
    );

    BlindedPaymentPath::one_hop(node, tlvs, 72, &Entropy, SECP256K1).expect("one-hop path is valid")
}

/// A registered offer with one reserved invoice, as consensus would store it.
struct Scenario {
    cfgs: BTreeMap<PeerId, Bolt12ModuleConfig>,
    gateway: Keypair,
    policy: ReceivePolicy,
    reservation: Reservation,
    id: ReservationId,
    invoice_request: Vec<u8>,
    payment_path: Vec<u8>,
}

impl Scenario {
    fn new() -> Result<Self> {
        let cfgs = configs()?;
        let bolt12 = &cfgs[&PeerId::from(0)].consensus.bolt12;

        let handle = rand::random();
        let offer = offer(bolt12.signing_key, handle);
        let request = invoice_request(&offer, AMOUNT_MSATS);
        let path = payment_path(&offer, &request);

        let recipient = Keypair::new(SECP256K1, &mut OsRng);
        let gateway = Keypair::new(SECP256K1, &mut OsRng);

        let policy = ReceivePolicy {
            handle,
            claim_pk: recipient.public_key(),
            offer_hash: offer_hash(&offer),
            max_gateway_fee: PaymentFee::RECEIVE_FEE_LIMIT,
            expires_at: NOW + 86_400,
            allow_pool: false,
        };

        let invoice_request = request.encode();
        let payment_path = encode_payment_path(&path)?;
        let source = Source::Stock { index: 0 };
        let payment_hash = [9; 32];

        let reservation = Reservation {
            registration: policy.id(),
            source,
            payment_hash,
            sealed: Sealed::Preimage(tpe::encrypt_preimage(
                &cfgs[&PeerId::from(0)].consensus.tpe_agg_pk,
                &[1; 32],
                &[2; 32],
                &Source::stock_binding(policy.id(), 0, payment_hash),
            )),
            claim_pk: policy.claim_pk,
            gateway: gateway.public_key(),
            amount: Amount::from_msats(AMOUNT_MSATS),
            gateway_fee: Amount::from_msats(100),
            terms: terms_hash(&invoice_request, &payment_path),
            created_at: NOW,
        };

        Ok(Self {
            id: Reservation::id(policy.id(), source),
            cfgs,
            gateway,
            policy,
            reservation,
            invoice_request,
            payment_path,
        })
    }

    fn registration_id(&self) -> RegistrationId {
        self.policy.id()
    }

    /// A guardian database holding the scenario's consensus state.
    async fn database(&self) -> Database {
        let db = database();
        let mut dbtx = db.begin_transaction().await;

        dbtx.insert_entry(
            &Bolt12RegistrationKey(self.registration_id()),
            &Registration {
                policy: self.policy.clone(),
                stock_len: 1,
                stock_unused: 0,
                voided: false,
            },
        )
        .await;
        dbtx.insert_entry(&Bolt12ReservationKey(self.id), &self.reservation)
            .await;
        dbtx.commit_tx().await;

        db
    }

    fn nonce_request(&self, attempt: [u8; 32]) -> NonceRequest {
        NonceRequest::new(
            self.id,
            attempt,
            self.invoice_request.clone(),
            self.payment_path.clone(),
            &self.gateway,
        )
    }

    async fn approve(&self, db: &Database, request: &NonceRequest, now: u64) -> Result<Approval> {
        approve(
            &mut db.begin_transaction_nc().await,
            &self.cfgs[&PeerId::from(0)],
            request,
            now,
        )
        .await
    }
}

#[tokio::test]
async fn a_quorum_signs_an_invoice_that_lightning_software_accepts() -> Result<()> {
    let scenario = Scenario::new()?;
    let attempt = [4; 32];
    let request = scenario.nonce_request(attempt);

    let mut signers = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    let mut digest = None;

    // Guardian 3 stays offline: three of four is the quorum.
    for peer in (0..3).map(PeerId::from) {
        let db = scenario.database().await;
        let approval = approve(
            &mut db.begin_transaction_nc().await,
            &scenario.cfgs[&peer],
            &request,
            NOW + 1,
        )
        .await?;

        // Every guardian derives the same digest independently.
        assert_eq!(*digest.get_or_insert(approval.digest), approval.digest);

        let mut signer = Signer::default();
        let response = signer
            .prepare(
                &scenario.cfgs[&peer],
                &db,
                (scenario.id, attempt),
                approval,
                NOW + 1,
            )
            .await?;

        commitments.insert(
            keys::identifier(peer)?,
            frost::round1::SigningCommitments::deserialize(&response.commitments)?,
        );
        signers.insert(peer, (signer, db));
    }

    let digest = digest.expect("three guardians approved");
    let package = frost::SigningPackage::new(commitments, &digest);
    let sign_request = SignRequest::new(
        scenario.id,
        attempt,
        package.serialize()?,
        &scenario.gateway,
    );

    assert!(sign_request.verify(&scenario.gateway.public_key()));

    let mut shares = BTreeMap::new();

    for (peer, (signer, db)) in &mut signers {
        let share = signer.sign(&scenario.cfgs[peer], db, &sign_request).await?;

        shares.insert(
            keys::identifier(*peer)?,
            frost::round2::SignatureShare::deserialize(&share)?,
        );
    }

    let bolt12 = &scenario.cfgs[&PeerId::from(0)].consensus.bolt12;
    let public = frost::keys::PublicKeyPackage::deserialize(&bolt12.public_package)?;
    let signature = frost::aggregate(&package, &shares, &public)?;

    // The gateway rebuilds the same invoice and attaches the signature;
    // LDK verifies it against the offer's issuer key.
    let unsigned = unsigned_invoice(
        Issuer {
            signing_key: bolt12.signing_key,
            network: Network::Regtest,
        },
        &scenario.policy,
        &scenario.reservation,
        Terms {
            invoice_request: &scenario.invoice_request,
            payment_path: &scenario.payment_path,
        },
    )?;
    let invoice = sign(unsigned, Signature::from_slice(&signature.serialize()?)?)?;

    assert_eq!(invoice.payment_hash().0, scenario.reservation.payment_hash);
    assert_eq!(invoice.amount_msats(), AMOUNT_MSATS);
    assert_eq!(invoice.signing_pubkey(), bolt12.signing_key);
    assert_eq!(invoice.created_at().as_secs(), NOW);
    assert_eq!(invoice.relative_expiry().as_secs(), INVOICE_LIFETIME);

    Ok(())
}

#[tokio::test]
async fn guardians_refuse_terms_that_differ_from_consensus() -> Result<()> {
    let scenario = Scenario::new()?;
    let db = scenario.database().await;
    let request = scenario.nonce_request([1; 32]);

    assert!(scenario.approve(&db, &request, NOW + 1).await.is_ok());

    let rejection = |request: NonceRequest, now: u64| {
        let scenario = &scenario;
        let db = &db;

        async move {
            scenario
                .approve(db, &request, now)
                .await
                .err()
                .map(|e| e.to_string())
        }
    };

    // Another gateway cannot ask for signatures on this reservation.
    let stranger = Keypair::new(SECP256K1, &mut OsRng);
    let forged = NonceRequest::new(
        scenario.id,
        [1; 32],
        scenario.invoice_request.clone(),
        scenario.payment_path.clone(),
        &stranger,
    );

    assert!(
        rejection(forged, NOW + 1)
            .await
            .expect("stranger is rejected")
            .contains("gateway signature")
    );

    // A different payment path, for example one leading to another node.
    let bolt12 = &scenario.cfgs[&PeerId::from(0)].consensus.bolt12;
    let issuer = bolt12.signing_key;
    let offer = offer(issuer, scenario.policy.handle);
    let other_request = invoice_request(&offer, AMOUNT_MSATS);
    let other_path = encode_payment_path(&payment_path(&offer, &other_request))?;

    let mut swapped = scenario.nonce_request([1; 32]);
    swapped.payment_path = other_path;

    assert!(
        rejection(swapped, NOW + 1)
            .await
            .expect("swapped path is rejected")
            .contains("terms differ")
    );

    assert!(
        rejection(scenario.nonce_request([1; 32]), NOW + INVOICE_LIFETIME)
            .await
            .expect("expired reservation is rejected")
            .contains("expired")
    );

    let unknown = NonceRequest::new(
        ReservationId(sha256::Hash::hash(b"unknown")),
        [1; 32],
        scenario.invoice_request.clone(),
        scenario.payment_path.clone(),
        &scenario.gateway,
    );

    assert!(rejection(unknown, NOW + 1).await.is_some());

    Ok(())
}

/// Store a reservation whose pinned terms are internally consistent but
/// disagree with the registration or reservation in one respect.
async fn approve_altered(
    scenario: &Scenario,
    alter: impl FnOnce(&mut Reservation, &mut Vec<u8>, &mut Vec<u8>) -> Result<()>,
) -> Result<Option<String>> {
    let mut reservation = scenario.reservation.clone();
    let mut invoice_request = scenario.invoice_request.clone();
    let mut payment_path = scenario.payment_path.clone();

    alter(&mut reservation, &mut invoice_request, &mut payment_path)?;

    // A dishonest gateway can pin any terms it likes in its reservation.
    reservation.terms = terms_hash(&invoice_request, &payment_path);

    let db = scenario.database().await;
    let mut dbtx = db.begin_transaction().await;

    dbtx.insert_entry(&Bolt12ReservationKey(scenario.id), &reservation)
        .await;
    dbtx.commit_tx().await;

    let request = NonceRequest::new(
        scenario.id,
        [1; 32],
        invoice_request,
        payment_path,
        &scenario.gateway,
    );

    Ok(scenario
        .approve(&db, &request, NOW + 1)
        .await
        .err()
        .map(|e| e.to_string()))
}

#[tokio::test]
async fn guardians_refuse_invoices_the_recipient_did_not_register() -> Result<()> {
    let scenario = Scenario::new()?;
    let bolt12 = &scenario.cfgs[&PeerId::from(0)].consensus.bolt12;
    let issuer = bolt12.signing_key;

    // Unaltered terms pass through the helper.
    assert_eq!(approve_altered(&scenario, |_, _, _| Ok(())).await?, None);

    // A request for a different offer under the same federation key. Offers
    // are unsigned, so only the registered hash tells them apart.
    let other_offer = OfferBuilder::new(issuer)
        .chain(Network::Regtest)
        .description("an offer the recipient never registered".to_string())
        .build()
        .expect("offer is valid");

    let rejection = approve_altered(&scenario, |_, request, path| {
        let other = invoice_request(&other_offer, AMOUNT_MSATS);

        *path = encode_payment_path(&payment_path(&other_offer, &other))?;
        *request = other.encode();

        Ok(())
    })
    .await?
    .expect("unregistered offer is rejected");

    assert!(rejection.contains("unregistered offer"));

    // The gateway reserved a different amount than the payer asked for.
    let rejection = approve_altered(&scenario, |reservation, _, _| {
        reservation.amount = Amount::from_msats(AMOUNT_MSATS + 1);

        Ok(())
    })
    .await?
    .expect("amount mismatch is rejected");

    assert!(rejection.contains("amount differs"));

    // A payer-signed request that was modified afterwards.
    let rejection = approve_altered(&scenario, |_, request, _| {
        let last = request.len() - 1;

        request[last] ^= 1;

        Ok(())
    })
    .await?;

    assert!(rejection.is_some());

    // Bytes that are not a payment path at all.
    let rejection = approve_altered(&scenario, |_, _, path| {
        *path = vec![0; 64];

        Ok(())
    })
    .await?;

    assert!(rejection.is_some());

    Ok(())
}

fn approval(digest: [u8; 32]) -> Approval {
    approval_for(
        PublicKey::from_secret_key(SECP256K1, &SecretKey::from_slice(&[1; 32]).expect("valid")),
        digest,
    )
}

fn approval_for(gateway: PublicKey, digest: [u8; 32]) -> Approval {
    Approval {
        gateway,
        digest,
        expires_at: NOW + INVOICE_LIFETIME,
    }
}

async fn database_with_reservations(ids: &[ReservationId]) -> Database {
    let db = database();
    let scenario = Scenario::new().expect("scenario");
    let mut dbtx = db.begin_transaction().await;
    for &id in ids {
        dbtx.insert_entry(&Bolt12ReservationKey(id), &scenario.reservation)
            .await;
    }
    dbtx.commit_tx().await;
    db
}

#[tokio::test]
async fn a_nonce_signs_only_the_approved_digest_and_only_once() -> Result<()> {
    let cfgs = configs()?;
    let gateway = Keypair::new(SECP256K1, &mut OsRng);
    let reservation = ReservationId(sha256::Hash::hash(b"reservation"));
    let attempt = [4; 32];
    let id = (reservation, attempt);
    let digest = [7; 32];

    let mut signers = BTreeMap::new();
    let mut commitments = BTreeMap::new();

    for peer in (0..3).map(PeerId::from) {
        let db = database_with_reservations(&[reservation]).await;
        let mut signer = Signer::default();

        let response = signer
            .prepare(&cfgs[&peer], &db, id, approval(digest), NOW)
            .await?;

        // Asking again returns the same commitment and spends no new attempt.
        let repeated = signer
            .prepare(&cfgs[&peer], &db, id, approval(digest), NOW)
            .await?;

        assert_eq!(response.commitments, repeated.commitments);

        // The same attempt cannot be rebound to another invoice.
        assert!(
            signer
                .prepare(&cfgs[&peer], &db, id, approval([8; 32]), NOW)
                .await
                .is_err()
        );

        commitments.insert(
            keys::identifier(peer)?,
            frost::round1::SigningCommitments::deserialize(&response.commitments)?,
        );
        signers.insert(peer, (signer, db));
    }

    let sign_request = |digest: [u8; 32]| -> Result<SignRequest> {
        let package = frost::SigningPackage::new(commitments.clone(), &digest);

        Ok(SignRequest::new(
            reservation,
            attempt,
            package.serialize()?,
            &gateway,
        ))
    };

    // A coordinator that swaps the message burns the nonce and gets nothing.
    let peer = PeerId::from(0);
    let (signer, db) = signers.get_mut(&peer).expect("guardian 0 prepared");

    assert!(
        signer
            .sign(&cfgs[&peer], db, &sign_request([8; 32])?)
            .await
            .is_err()
    );
    assert!(
        signer
            .sign(&cfgs[&peer], db, &sign_request(digest)?)
            .await
            .is_err()
    );

    // A guardian signs once and refuses a second request for the same nonce.
    let peer = PeerId::from(1);
    let (signer, db) = signers.get_mut(&peer).expect("guardian 1 prepared");

    let share = signer
        .sign(&cfgs[&peer], db, &sign_request(digest)?)
        .await?;

    assert!(frost::round2::SignatureShare::deserialize(&share).is_ok());
    assert!(
        signer
            .sign(&cfgs[&peer], db, &sign_request(digest)?)
            .await
            .is_err()
    );

    // A restarted guardian has lost its nonces. It neither signs nor reissues
    // a commitment for an attempt it already started.
    let peer = PeerId::from(2);
    let (_, db) = signers.get_mut(&peer).expect("guardian 2 prepared");
    let mut restarted = Signer::default();

    assert!(
        restarted
            .sign(&cfgs[&peer], db, &sign_request(digest)?)
            .await
            .is_err()
    );
    assert!(
        restarted
            .prepare(&cfgs[&peer], db, id, approval(digest), NOW)
            .await
            .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn signing_packages_must_contain_a_quorum_including_our_commitment() -> Result<()> {
    let cfgs = configs()?;
    let gateway = Keypair::new(SECP256K1, &mut OsRng);
    let reservation = ReservationId(sha256::Hash::hash(b"reservation"));
    let digest = [7; 32];

    let mut commitments = BTreeMap::new();
    let mut signers = BTreeMap::new();

    for (index, peer) in (0..3).map(PeerId::from).enumerate() {
        let db = database_with_reservations(&[reservation]).await;
        let mut signer = Signer::default();

        // Two attempts each: one per case below.
        for attempt in [[1; 32], [2; 32]] {
            let response = signer
                .prepare(
                    &cfgs[&peer],
                    &db,
                    (reservation, attempt),
                    approval(digest),
                    NOW,
                )
                .await?;

            commitments.insert(
                (attempt, index),
                (
                    keys::identifier(peer)?,
                    frost::round1::SigningCommitments::deserialize(&response.commitments)?,
                ),
            );
        }

        signers.insert(peer, (signer, db));
    }

    let peer = PeerId::from(0);
    let (signer, db) = signers.get_mut(&peer).expect("guardian 0 prepared");

    // Two participants are below the quorum of three.
    let too_few: BTreeMap<_, _> = (0..2).map(|index| commitments[&([1; 32], index)]).collect();
    let package = frost::SigningPackage::new(too_few, &digest);
    let request = SignRequest::new(reservation, [1; 32], package.serialize()?, &gateway);

    assert!(signer.sign(&cfgs[&peer], db, &request).await.is_err());

    // A quorum whose entry for us is a commitment we did not make for this
    // attempt.
    let mut replaced: BTreeMap<_, _> = (0..3).map(|index| commitments[&([2; 32], index)]).collect();
    replaced.insert(keys::identifier(peer)?, commitments[&([1; 32], 0)].1);

    let package = frost::SigningPackage::new(replaced, &digest);
    let request = SignRequest::new(reservation, [2; 32], package.serialize()?, &gateway);

    assert!(signer.sign(&cfgs[&peer], db, &request).await.is_err());

    Ok(())
}

#[tokio::test]
async fn the_attempt_budget_survives_a_restart() -> Result<()> {
    let cfg = configs()?
        .remove(&PeerId::from(0))
        .expect("guardian 0 exists");
    let reservation = ReservationId(sha256::Hash::hash(b"reservation"));
    let other = ReservationId(sha256::Hash::hash(b"another reservation"));
    let db = database_with_reservations(&[reservation, other]).await;
    let mut signer = Signer::default();

    for attempt in 0..MAX_ATTEMPTS {
        if attempt == MAX_ATTEMPTS / 2 {
            signer = Signer::default();
        }

        signer
            .prepare(
                &cfg,
                &db,
                (reservation, [u8::try_from(attempt)?; 32]),
                approval([7; 32]),
                NOW,
            )
            .await?;

        // Each attempt's nonce is used or lost before the next one starts.
        signer.tickets.clear();
    }

    assert!(
        signer
            .prepare(&cfg, &db, (reservation, [255; 32]), approval([7; 32]), NOW)
            .await
            .is_err()
    );

    // The budget is per reservation.
    signer
        .prepare(&cfg, &db, (other, [0; 32]), approval([7; 32]), NOW)
        .await?;

    // Expired nonces are dropped from memory.
    signer
        .prepare(
            &cfg,
            &db,
            (other, [1; 32]),
            approval([7; 32]),
            NOW + INVOICE_LIFETIME,
        )
        .await?;

    assert_eq!(signer.tickets.len(), 1);

    Ok(())
}

#[tokio::test]
async fn one_gateway_cannot_take_all_signing_capacity() -> Result<()> {
    let scenario = Scenario::new()?;
    let cfg = &scenario.cfgs[&PeerId::from(0)];
    let db = scenario.database().await;
    let mut signer = Signer::default();
    let gateway = scenario.gateway.public_key();

    // Live reservations of one gateway.
    let reservations: Vec<ReservationId> = (0..10u8)
        .map(|i| ReservationId(sha256::Hash::hash(&[i])))
        .collect();

    let mut dbtx = db.begin_transaction().await;

    for id in &reservations {
        dbtx.insert_entry(&Bolt12ReservationKey(*id), &scenario.reservation)
            .await;
    }

    dbtx.commit_tx().await;

    // At most two attempts are held in memory per reservation; a third attempt
    // evicts the oldest in-memory ticket for that reservation rather than
    // locking out legitimate retries after offline peers, while durable DB
    // state still forbids reusing the evicted attempt id.
    for attempt in 0..3u8 {
        signer
            .prepare(
                cfg,
                &db,
                (reservations[0], [attempt; 32]),
                approval_for(gateway, [7; 32]),
                NOW,
            )
            .await?;
    }

    assert_eq!(
        signer
            .tickets
            .keys()
            .filter(|(r, _)| *r == reservations[0])
            .count(),
        2
    );
    assert!(!signer.tickets.contains_key(&(reservations[0], [0; 32])));
    assert!(
        signer
            .prepare(
                cfg,
                &db,
                (reservations[0], [0; 32]),
                approval_for(gateway, [7; 32]),
                NOW,
            )
            .await
            .is_err(),
        "evicted attempt must not be re-prepared"
    );

    // At most sixteen are open per gateway.
    for id in &reservations[1..8] {
        for attempt in 0..2u8 {
            signer
                .prepare(
                    cfg,
                    &db,
                    (*id, [attempt; 32]),
                    approval_for(gateway, [7; 32]),
                    NOW,
                )
                .await?;
        }
    }

    assert!(
        signer
            .prepare(
                cfg,
                &db,
                (reservations[8], [0; 32]),
                approval_for(gateway, [7; 32]),
                NOW
            )
            .await
            .is_err()
    );

    // Other gateways still get nonces.
    let other = Keypair::new(SECP256K1, &mut OsRng).public_key();

    signer
        .prepare(
            cfg,
            &db,
            (reservations[9], [0; 32]),
            approval_for(other, [7; 32]),
            NOW,
        )
        .await?;

    // Once a reservation is funded its nonces are reclaimed.
    let mut dbtx = db.begin_transaction().await;

    dbtx.remove_entry(&Bolt12ReservationKey(reservations[1]))
        .await;
    dbtx.commit_tx().await;

    signer
        .prepare(
            cfg,
            &db,
            (reservations[8], [0; 32]),
            approval_for(gateway, [7; 32]),
            NOW,
        )
        .await?;

    Ok(())
}

#[tokio::test]
async fn unsigned_invoice_rejects_wrong_handle_and_expired_offer() -> Result<()> {
    let scenario = Scenario::new()?;
    let bolt12 = &scenario.cfgs[&PeerId::from(0)].consensus.bolt12;

    // Wrong routing handle in offer metadata must be rejected even if the
    // registration somehow committed to that offer hash.
    let wrong_handle_offer = offer(bolt12.signing_key, [0xfe; 32]);
    let wrong_req = invoice_request(&wrong_handle_offer, AMOUNT_MSATS);
    let wrong_path = encode_payment_path(&payment_path(&wrong_handle_offer, &wrong_req))?;
    let mut wrong_policy = scenario.policy.clone();
    wrong_policy.offer_hash = offer_hash(&wrong_handle_offer);
    let mut wrong_reservation = scenario.reservation.clone();
    wrong_reservation.terms = terms_hash(&wrong_req.encode(), &wrong_path);

    assert!(
        unsigned_invoice(
            Issuer {
                signing_key: bolt12.signing_key,
                network: Network::Regtest,
            },
            &wrong_policy,
            &wrong_reservation,
            Terms {
                invoice_request: &wrong_req.encode(),
                payment_path: &wrong_path,
            },
        )
        .is_err()
    );

    // An offer whose absolute_expiry is already <= reservation.created_at must
    // be rejected. Use a future wall-clock timestamp so LDK builds the payer
    // request, then set reservation.created_at equal to absolute_expiry.
    let future_expiry = fedimint_core::time::duration_since_epoch().as_secs() + 3_600;
    let expired_offer = OfferBuilder::new(bolt12.signing_key)
        .chain(Network::Regtest)
        .description("expired".to_string())
        .metadata(routing_metadata(
            FederationId::dummy(),
            scenario.policy.handle,
        ))
        .expect("metadata fits")
        .absolute_expiry(std::time::Duration::from_secs(future_expiry))
        .build()
        .expect("offer builds");
    let exp_req = invoice_request(&expired_offer, AMOUNT_MSATS);
    let exp_path = encode_payment_path(&payment_path(&expired_offer, &exp_req))?;
    let mut exp_policy = scenario.policy.clone();
    exp_policy.offer_hash = offer_hash(&expired_offer);
    let mut exp_reservation = scenario.reservation.clone();
    exp_reservation.created_at = future_expiry;
    exp_reservation.terms = terms_hash(&exp_req.encode(), &exp_path);

    assert!(
        unsigned_invoice(
            Issuer {
                signing_key: bolt12.signing_key,
                network: Network::Regtest,
            },
            &exp_policy,
            &exp_reservation,
            Terms {
                invoice_request: &exp_req.encode(),
                payment_path: &exp_path,
            },
        )
        .is_err()
    );

    Ok(())
}

#[tokio::test]
async fn seven_guardian_signing_succeeds_after_two_offline_attempts() -> Result<()> {
    // N = 7 (f = 2, quorum = 5): two failed signing attempts (e.g. two
    // distinct guardians dropping between round 1 and round 2) must not exhaust
    // the per-reservation in-memory ticket cap before attempt 3 completes.
    let cfgs = configs_for(7)?;
    let gateway = Keypair::new(SECP256K1, &mut OsRng);
    let reservation = ReservationId(sha256::Hash::hash(b"n7-res"));
    let digest = [5; 32];

    let mut signers: BTreeMap<PeerId, (Signer, Database)> = BTreeMap::new();
    for p in 0..7u16 {
        signers.insert(
            PeerId::from(p),
            (
                Signer::default(),
                database_with_reservations(&[reservation]).await,
            ),
        );
    }

    // Two failed attempts prepare on all 5 honest guardians [0..5] without
    // finishing round 2.
    for attempt in [[1; 32], [2; 32]] {
        for peer in (0..5u16).map(PeerId::from) {
            let (signer, db) = signers.get_mut(&peer).expect("peer");
            signer
                .prepare(
                    &cfgs[&peer],
                    db,
                    (reservation, attempt),
                    approval_for(gateway.public_key(), digest),
                    NOW,
                )
                .await?;
        }
    }

    // Attempt 3 must still prepare (evicting oldest ticket) and produce a valid
    // aggregated FROST signature.
    let attempt = [3; 32];
    let mut commitments = BTreeMap::new();
    for peer in (0..5u16).map(PeerId::from) {
        let (signer, db) = signers.get_mut(&peer).expect("peer");
        let resp = signer
            .prepare(
                &cfgs[&peer],
                db,
                (reservation, attempt),
                approval_for(gateway.public_key(), digest),
                NOW,
            )
            .await?;
        commitments.insert(
            keys::identifier(peer)?,
            frost::round1::SigningCommitments::deserialize(&resp.commitments)?,
        );
    }

    let package = frost::SigningPackage::new(commitments, &digest);
    let sign_req = SignRequest::new(reservation, attempt, package.serialize()?, &gateway);
    let mut shares = BTreeMap::new();
    for peer in (0..5u16).map(PeerId::from) {
        let (signer, db) = signers.get_mut(&peer).expect("peer");
        let share = signer.sign(&cfgs[&peer], db, &sign_req).await?;
        shares.insert(
            keys::identifier(peer)?,
            frost::round2::SignatureShare::deserialize(&share)?,
        );
    }

    let bolt12 = &cfgs[&PeerId::from(0)].consensus.bolt12;
    let public = frost::keys::PublicKeyPackage::deserialize(&bolt12.public_package)?;
    frost::aggregate(&package, &shares, &public)?;

    Ok(())
}
