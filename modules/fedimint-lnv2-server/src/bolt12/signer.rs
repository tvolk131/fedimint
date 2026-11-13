//! A guardian's side of threshold invoice signing.
//!
//! Signing is not consensus: a quorum of guardians each decide independently
//! whether a reservation's terms describe an invoice they will sign. Every
//! guardian derives the invoice from consensus state and the gateway's bytes,
//! so honest guardians sign the same digest or none.
//!
//! FROST nonces are single use. They are kept in memory only, and a durable
//! marker is written before a commitment or signature share leaves this
//! process, so neither a retry nor a restart can make a nonce sign twice.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_lnv2_common::bolt12::invoice::{Issuer, Terms, signing_digest, unsigned_invoice};
use fedimint_lnv2_common::bolt12::{
    NonceRequest, NonceResponse, ReservationId, SignRequest, quorum,
};
use fedimint_lnv2_common::config::LightningConfig;
use frost_secp256k1_tr as frost;
use rand::rngs::OsRng;

use crate::db::{Bolt12NonceCountKey, Bolt12NonceKey, Bolt12RegistrationKey, Bolt12ReservationKey};

/// Nonces held in memory at once, across all reservations.
const MAX_TICKETS: usize = 64;
/// Nonces ever issued for one reservation, surviving restarts.
const MAX_ATTEMPTS: u16 = 16;
/// Upper bound on a serialized signing package.
const MAX_PACKAGE_BYTES: usize = 16_384;

/// One signing attempt for one reservation.
pub type TicketId = (ReservationId, [u8; 32]);

struct Ticket {
    expires_at: u64,
    digest: [u8; 32],
    nonces: frost::round1::SigningNonces,
    commitments: frost::round1::SigningCommitments,
}

#[derive(Default)]
pub struct Signer {
    tickets: BTreeMap<TicketId, Ticket>,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer").finish_non_exhaustive()
    }
}

/// What a guardian agreed to sign for a reservation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Approval {
    pub digest: [u8; 32],
    pub expires_at: u64,
}

/// Decide whether to sign for a reservation, and what.
pub async fn approve(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    request: &NonceRequest,
    now: u64,
) -> Result<Approval> {
    let bolt12 = cfg
        .consensus
        .bolt12
        .as_ref()
        .context("federated BOLT12 is disabled")?;

    let reservation = dbtx
        .get_value(&Bolt12ReservationKey(request.reservation))
        .await
        .context("reservation is unknown or already funded")?;

    ensure!(reservation.expires_at() > now, "invoice has expired");
    ensure!(
        request.verify(&reservation.gateway),
        "invalid gateway signature"
    );

    let registration = dbtx
        .get_value(&Bolt12RegistrationKey(reservation.registration))
        .await
        .context("unknown registration")?;

    let invoice = unsigned_invoice(
        Issuer {
            signing_key: bolt12.signing_key,
            network: cfg.consensus.network,
        },
        &registration.policy,
        &reservation,
        Terms {
            invoice_request: &request.invoice_request,
            payment_path: &request.payment_path,
        },
    )?;

    Ok(Approval {
        digest: signing_digest(&invoice),
        expires_at: reservation.expires_at(),
    })
}

impl Signer {
    /// Commit to a fresh nonce for an approved digest.
    pub async fn prepare(
        &mut self,
        cfg: &LightningConfig,
        db: &Database,
        id: TicketId,
        approval: Approval,
        now: u64,
    ) -> Result<NonceResponse> {
        self.tickets.retain(|_, ticket| ticket.expires_at > now);

        // A repeated request, for example after a lost response, gets the
        // same commitment back.
        if let Some(ticket) = self.tickets.get(&id) {
            ensure!(
                ticket.digest == approval.digest,
                "attempt was started for another invoice"
            );

            return Ok(NonceResponse {
                commitments: ticket.commitments.serialize()?,
            });
        }

        ensure!(
            self.tickets.len() < MAX_TICKETS,
            "invoice signing capacity reached"
        );

        let key = key_package(cfg)?;

        let mut dbtx = db.begin_transaction().await;

        let attempts = dbtx
            .get_value(&Bolt12NonceCountKey(id.0))
            .await
            .unwrap_or(0);

        ensure!(
            attempts < MAX_ATTEMPTS,
            "invoice signing attempt limit reached"
        );
        // After a restart the marker exists but the nonce is gone.
        ensure!(
            dbtx.get_value(&Bolt12NonceKey(id.0, id.1)).await.is_none(),
            "attempt was already started; retry with a new attempt"
        );

        dbtx.insert_entry(&Bolt12NonceCountKey(id.0), &(attempts + 1))
            .await;
        dbtx.insert_new_entry(&Bolt12NonceKey(id.0, id.1), &false)
            .await;
        dbtx.commit_tx_result().await?;

        let (nonces, commitments) = frost::round1::commit(key.signing_share(), &mut OsRng);
        let response = NonceResponse {
            commitments: commitments.serialize()?,
        };

        self.tickets.insert(
            id,
            Ticket {
                expires_at: approval.expires_at,
                digest: approval.digest,
                nonces,
                commitments,
            },
        );

        Ok(response)
    }

    /// Produce our signature share for the digest we approved in round one.
    pub async fn sign(
        &mut self,
        cfg: &LightningConfig,
        db: &Database,
        request: &SignRequest,
    ) -> Result<Vec<u8>> {
        ensure!(
            request.package.len() <= MAX_PACKAGE_BYTES,
            "signing package exceeds limit"
        );

        let id = (request.reservation, request.attempt);

        // Take the nonce out before looking at the package: whatever happens
        // next, it can never be used again.
        let ticket = self
            .tickets
            .remove(&id)
            .context("unknown, spent or lost signing nonce")?;

        let package = frost::SigningPackage::deserialize(&request.package)?;
        let key = key_package(cfg)?;
        let public = frost::keys::PublicKeyPackage::deserialize(
            &cfg.consensus
                .bolt12
                .as_ref()
                .context("federated BOLT12 is disabled")?
                .public_package,
        )?;

        ensure!(
            package.message().as_slice() == ticket.digest,
            "signing package is for another invoice"
        );
        ensure!(
            package.signing_commitments().len() >= quorum(cfg.consensus.tpe_pks.len()),
            "signing package has too few participants"
        );
        ensure!(
            package
                .signing_commitments()
                .keys()
                .all(|identifier| public.verifying_shares().contains_key(identifier)),
            "signing package names an unknown participant"
        );
        ensure!(
            package.signing_commitments().get(key.identifier()) == Some(&ticket.commitments),
            "signing package changed our commitment"
        );

        let mut dbtx = db.begin_transaction().await;

        let spent = dbtx
            .get_value(&Bolt12NonceKey(id.0, id.1))
            .await
            .context("signing nonce was never recorded")?;

        ensure!(!spent, "signing nonce is already spent");

        dbtx.insert_entry(&Bolt12NonceKey(id.0, id.1), &true).await;
        dbtx.commit_tx_result().await?;

        Ok(frost::round2::sign(&package, &ticket.nonces, &key)?.serialize())
    }
}

fn key_package(cfg: &LightningConfig) -> Result<frost::keys::KeyPackage> {
    Ok(frost::keys::KeyPackage::deserialize(
        &cfg.private
            .bolt12
            .as_ref()
            .context("federated BOLT12 is disabled")?
            .key_package,
    )?)
}

#[cfg(test)]
mod tests;
