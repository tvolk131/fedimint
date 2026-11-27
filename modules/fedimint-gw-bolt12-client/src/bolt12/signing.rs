//! Coordinating a threshold signature over a federated BOLT12 invoice.
//!
//! The gateway is an untrusted coordinator: every guardian derives the invoice
//! itself and signs nothing else, so a coordinator can only fail to obtain a
//! signature, never obtain one for different terms.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use fedimint_api_client::api::{DynModuleApi, FederationApiExt};
use fedimint_bolt12_common::bolt12::invoice::{
    Issuer, Terms, sign, signing_digest, unsigned_invoice,
};
use fedimint_bolt12_common::bolt12::{
    NonceRequest, NonceResponse, ReceivePolicy, Reservation, SignRequest, quorum,
};
use fedimint_bolt12_common::config::Bolt12ClientConfig;
use fedimint_bolt12_common::endpoint_constants::{BOLT12_NONCE_ENDPOINT, BOLT12_SIGN_ENDPOINT};
use fedimint_core::PeerId;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::secp256k1::Keypair;
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::task::timeout;
use frost_secp256k1_tr as frost;
use futures::future::join_all;
use lightning::offers::invoice::Bolt12Invoice;
use rand::seq::SliceRandom as _;

/// How long one guardian may take to answer one signing round.
const ROUND_TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bounds on what a guardian may send back.
const MAX_COMMITMENT_BYTES: usize = 256;
const MAX_SHARE_BYTES: usize = 128;

fn identifier(peer: PeerId) -> Result<frost::Identifier> {
    Ok(frost::Identifier::try_from(
        u16::from(peer)
            .checked_add(1)
            .context("guardian identifier overflow")?,
    )?)
}

/// Everything that determines the invoice guardians will sign.
#[derive(Debug, Clone, Copy)]
pub struct SigningJob<'a> {
    pub policy: &'a ReceivePolicy,
    pub reservation: &'a Reservation,
    pub invoice_request: &'a [u8],
    pub payment_path: &'a [u8],
}

/// Obtain the federation's signature on the invoice for a reservation.
///
/// Guardians that do not answer, or whose signature share is wrong, are left
/// out of the next attempt. Each attempt uses fresh nonces.
#[allow(clippy::too_many_lines)]
pub async fn sign_invoice(
    api: &DynModuleApi,
    cfg: &Bolt12ClientConfig,
    gateway_key: &Keypair,
    job: SigningJob<'_>,
) -> Result<Bolt12Invoice> {
    let bolt12 = &cfg.bolt12;

    let public = frost::keys::PublicKeyPackage::deserialize(&bolt12.public_package)?;
    let quorum = quorum(cfg.tpe_pks.len());
    let id = Reservation::id(job.reservation.registration, job.reservation.source);

    let build = || {
        unsigned_invoice(
            Issuer {
                signing_key: bolt12.signing_key,
                network: cfg.network,
            },
            job.policy,
            job.reservation,
            Terms {
                invoice_request: job.invoice_request,
                payment_path: job.payment_path,
            },
        )
    };

    // Fails here if the terms are ones no honest guardian would sign.
    let digest = signing_digest(&build()?);

    let mut excluded = BTreeSet::new();

    // Each failed attempt excludes at least one guardian, so this many
    // attempts exhaust every set that could still reach quorum.
    for _ in 0..=cfg.tpe_pks.len() - quorum {
        let mut peers: Vec<PeerId> = cfg
            .tpe_pks
            .keys()
            .filter(|peer| !excluded.contains(*peer))
            .copied()
            .collect();

        ensure!(
            peers.len() >= quorum,
            "too few responsive guardians to sign the invoice"
        );

        // Ask exactly a quorum, picked at random: a guardian asked for a
        // nonce holds it until the reservation ends, and each guardian holds
        // only a few per gateway, so spares would use up that allowance.
        peers.shuffle(&mut rand::thread_rng());
        peers.truncate(quorum);

        let attempt: [u8; 32] = rand::random();

        let nonce_request = NonceRequest::new(
            id,
            attempt,
            job.invoice_request.to_vec(),
            job.payment_path.to_vec(),
            gateway_key,
        );

        let responses = join_all(peers.iter().map(|peer| {
            timeout(
                ROUND_TIMEOUT,
                api.request_single_peer::<NonceResponse>(
                    BOLT12_NONCE_ENDPOINT.to_owned(),
                    ApiRequestErased::new(&nonce_request),
                    *peer,
                ),
            )
        }))
        .await;

        let mut commitments = BTreeMap::new();
        let mut signers = Vec::new();

        for (peer, response) in peers.iter().zip(responses) {
            let commitment = match response {
                Ok(Ok(response)) if response.commitments.len() <= MAX_COMMITMENT_BYTES => {
                    frost::round1::SigningCommitments::deserialize(&response.commitments).ok()
                }
                _ => None,
            };

            match commitment {
                Some(commitment) => {
                    commitments.insert(identifier(*peer)?, commitment);
                    signers.push(*peer);
                }
                None => {
                    excluded.insert(*peer);
                }
            }
        }

        if signers.len() < quorum {
            continue;
        }

        let package = frost::SigningPackage::new(commitments, &digest);
        let sign_request = SignRequest::new(id, attempt, package.serialize()?, gateway_key);

        let responses = join_all(signers.iter().map(|peer| {
            timeout(
                ROUND_TIMEOUT,
                api.request_single_peer::<Vec<u8>>(
                    BOLT12_SIGN_ENDPOINT.to_owned(),
                    ApiRequestErased::new(&sign_request),
                    *peer,
                ),
            )
        }))
        .await;

        let mut shares = BTreeMap::new();

        for (peer, response) in signers.iter().zip(responses) {
            let share = match response {
                Ok(Ok(bytes)) if bytes.len() <= MAX_SHARE_BYTES => {
                    frost::round2::SignatureShare::deserialize(&bytes).ok()
                }
                _ => None,
            };

            if let Some(share) = share {
                shares.insert(identifier(*peer)?, share);
            } else {
                excluded.insert(*peer);
            }
        }

        if shares.len() < signers.len() {
            continue;
        }

        match frost::aggregate(&package, &shares, &public) {
            Ok(signature) => {
                return sign(build()?, Signature::from_slice(&signature.serialize()?)?);
            }
            Err(error) => {
                let culprits = error.culprits();

                ensure!(
                    !culprits.is_empty(),
                    "invoice signature aggregation failed: {error}"
                );

                for peer in signers {
                    if culprits.contains(&identifier(peer)?) {
                        excluded.insert(peer);
                    }
                }
            }
        }
    }

    anyhow::bail!("guardians did not produce a valid invoice signature")
}
