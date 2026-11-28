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
use fedimint_bolt12_common::config::Bolt12ModuleConfig;
use fedimint_bolt12_common::invoice::{Issuer, Terms, signing_digest, unsigned_invoice};
use fedimint_bolt12_common::protocol::{
    NonceRequest, NonceResponse, ReservationId, SignRequest, quorum,
};
use fedimint_core::db::{Database, DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::secp256k1::PublicKey;
use frost_secp256k1_tr as frost;
use rand::rngs::OsRng;

use crate::db::{Bolt12NonceCountKey, Bolt12NonceKey, Bolt12RegistrationKey, Bolt12ReservationKey};

/// Nonces held in memory at once, across all reservations.
const MAX_TICKETS: usize = 64;
/// Nonces held at once for one gateway's reservations, so one gateway that
/// never finishes signing cannot crowd out the others.
const MAX_TICKETS_PER_GATEWAY: usize = 16;
/// Nonces held at once for one reservation. When a gateway starts a new retry
/// beyond this bound, the oldest in-memory nonce for the same reservation is
/// evicted (its durable DB marker prevents reuse), so federations with `f >= 2`
/// can retry past multiple offline guardians without stranding honest signers.
const MAX_TICKETS_PER_RESERVATION: usize = 2;
/// Nonces ever issued for one reservation, surviving restarts.
const MAX_ATTEMPTS: u16 = 32;
/// Upper bound on a serialized signing package.
const MAX_PACKAGE_BYTES: usize = 16_384;

/// One signing attempt for one reservation.
pub type TicketId = (ReservationId, [u8; 32]);

struct Ticket {
    seq: u64,
    gateway: PublicKey,
    expires_at: u64,
    digest: [u8; 32],
    nonces: frost::round1::SigningNonces,
    commitments: frost::round1::SigningCommitments,
}

#[derive(Default)]
pub struct Signer {
    tickets: BTreeMap<TicketId, Ticket>,
    next_seq: u64,
}

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer").finish_non_exhaustive()
    }
}

/// What a guardian agreed to sign for a reservation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Approval {
    pub gateway: PublicKey,
    pub digest: [u8; 32],
    pub expires_at: u64,
}

/// Decide whether to sign for a reservation, and what.
pub async fn approve(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &Bolt12ModuleConfig,
    request: &NonceRequest,
    now: u64,
) -> Result<Approval> {
    let bolt12 = &cfg.consensus.bolt12;

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
        gateway: reservation.gateway,
        digest: signing_digest(&invoice),
        expires_at: reservation.expires_at(),
    })
}

impl Signer {
    /// Commit to a fresh nonce for an approved digest.
    pub async fn prepare(
        &mut self,
        cfg: &Bolt12ModuleConfig,
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

        let mut dbtx = db.begin_transaction().await;

        // Nonces for reservations that were funded since are of no use.
        if self.tickets.len() >= MAX_TICKETS
            || self.gateway_tickets(approval.gateway) >= MAX_TICKETS_PER_GATEWAY
        {
            let mut stale = vec![];

            for ticket_id in self.tickets.keys() {
                if dbtx
                    .get_value(&Bolt12ReservationKey(ticket_id.0))
                    .await
                    .is_none()
                {
                    stale.push(*ticket_id);
                }
            }

            for ticket_id in stale {
                self.tickets.remove(&ticket_id);
            }
        }

        // Account for tickets of this reservation that will be evicted once the
        // new attempt is durably committed, without mutating `self.tickets`
        // before validation and DB commit succeed.
        let reservation_tickets = self.tickets.keys().filter(|(r, _)| *r == id.0).count();
        let evict_count = reservation_tickets.saturating_sub(MAX_TICKETS_PER_RESERVATION - 1);

        ensure!(
            self.tickets.len().saturating_sub(evict_count) < MAX_TICKETS,
            "invoice signing capacity reached"
        );
        ensure!(
            self.gateway_tickets(approval.gateway)
                .saturating_sub(evict_count)
                < MAX_TICKETS_PER_GATEWAY,
            "invoice signing capacity for this gateway reached"
        );

        let key = key_package(cfg)?;

        // Re-verify inside the write transaction that the reservation was not
        // funded or expired since `approve()` ran, preventing orphaned nonce
        // rows from leaking into the local database.
        ensure!(
            dbtx.get_value(&Bolt12ReservationKey(id.0)).await.is_some(),
            "reservation is no longer active"
        );

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

        // Now that the new attempt is durably recorded, evict the oldest
        // in-memory ticket(s) for this reservation so live attempts stay
        // bounded at `MAX_TICKETS_PER_RESERVATION` (unblocking retries past
        // `f >= 2` offline guardians while durable `Bolt12NonceKey` prevents
        // any evicted attempt from ever being resumed).
        while self.tickets.keys().filter(|(r, _)| *r == id.0).count() >= MAX_TICKETS_PER_RESERVATION
        {
            let Some(oldest) = self
                .tickets
                .iter()
                .filter(|((r, _), _)| *r == id.0)
                .min_by_key(|(_, ticket)| ticket.seq)
                .map(|(ticket_id, _)| *ticket_id)
            else {
                break;
            };
            self.tickets.remove(&oldest);
        }

        let (nonces, commitments) = frost::round1::commit(key.signing_share(), &mut OsRng);
        let response = NonceResponse {
            commitments: commitments.serialize()?,
        };

        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        self.tickets.insert(
            id,
            Ticket {
                seq,
                gateway: approval.gateway,
                expires_at: approval.expires_at,
                digest: approval.digest,
                nonces,
                commitments,
            },
        );

        Ok(response)
    }

    fn gateway_tickets(&self, gateway: PublicKey) -> usize {
        self.tickets
            .values()
            .filter(|ticket| ticket.gateway == gateway)
            .count()
    }

    /// Produce our signature share for the digest we approved in round one.
    pub async fn sign(
        &mut self,
        cfg: &Bolt12ModuleConfig,
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
        let public =
            frost::keys::PublicKeyPackage::deserialize(&cfg.consensus.bolt12.public_package)?;

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

fn key_package(cfg: &Bolt12ModuleConfig) -> Result<frost::keys::KeyPackage> {
    Ok(frost::keys::KeyPackage::deserialize(
        &cfg.private.bolt12.key_package,
    )?)
}

#[cfg(test)]
mod tests;
