//! Consensus rules for federated BOLT12 receives.
//!
//! Everything here is a deterministic function of the database and the
//! consensus time. No BOLT12 message is parsed and no network I/O happens while
//! a transaction or consensus item is applied. See `docs/federated_bolt12.md`.

mod api;
pub mod keys;
pub mod pool;
pub mod signer;
pub mod transport;
pub mod worker;

use anyhow::{Context, Result, ensure};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::{Amount, OutPoint, PeerId};
use fedimint_lnv2_common::LightningInputError;
use fedimint_lnv2_common::bolt12::{
    AddStock, Bolt12Output, Bolt12Unlock, INVOICE_LIFETIME, MAX_PENDING_PER_GATEWAY,
    MAX_PENDING_PER_OFFER, MAX_PENDING_POOL, MAX_REGISTRATION_LIFETIME, MAX_REGISTRATIONS,
    MAX_STOCK, MAX_STOCK_BATCH, Pending, PoolItem, REGISTRATIONS_PRUNED_PER_REGISTER, Register,
    Registration, RegistrationId, Reservation, ReservationId, Reserve, Sealed, Source,
    StreamedReceive, output_amount_and_fee, quorum, reservation_is_economical,
};
use fedimint_lnv2_common::config::LightningConfig;
use futures::StreamExt;

use crate::db::{
    Bolt12ContractIndexKey, Bolt12ContractKey, Bolt12DecryptionSharesKey, Bolt12ExpiryKey,
    Bolt12ExpiryPrefix, Bolt12GatewayPendingKey, Bolt12GatewayVoteGatewayPrefix,
    Bolt12GatewayVoteKey, Bolt12HandleKey, Bolt12OfferPendingKey, Bolt12PaymentHashKey,
    Bolt12PoolItemKey, Bolt12PoolPendingKey, Bolt12RecipientKey, Bolt12RegistrationCountKey,
    Bolt12RegistrationKey, Bolt12ReservationKey, Bolt12StockKey, Bolt12StockRegistrationPrefix,
    Bolt12StreamIndexKey, Bolt12StreamKey,
};

/// What an accepted output moves and costs.
pub struct OutputEffect {
    pub amount: Amount,
    pub fee: Amount,
    /// Set when the output funded a receive.
    pub funded: bool,
}

/// Apply one BOLT12 output at consensus time `now`.
pub async fn process_output(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    output: &Bolt12Output,
    outpoint: OutPoint,
    now: u64,
) -> Result<OutputEffect> {
    let bolt12 = cfg
        .consensus
        .bolt12
        .as_ref()
        .context("federated BOLT12 is disabled")?;

    // Registrations, reservations and invoices are all timed against the
    // consensus clock. Until a threshold of guardians has voted on it, it
    // reads zero, and an invoice created at time zero is expired on arrival.
    ensure!(now > 0, "the consensus clock is not established yet");

    let receive_amount = match output {
        Bolt12Output::Register(register) => {
            process_register(dbtx, register, now).await?;
            Amount::ZERO
        }
        Bolt12Output::AddStock(add) => {
            process_add_stock(dbtx, add, now).await?;
            Amount::ZERO
        }
        Bolt12Output::Reserve(reserve) => {
            process_reserve(dbtx, cfg, reserve, now).await?;
            Amount::ZERO
        }
        Bolt12Output::Receive(reservation) => {
            process_receive(dbtx, cfg, *reservation, outpoint, now).await?
        }
    };

    let (amount, fee) =
        output_amount_and_fee(&cfg.consensus.fee_consensus, bolt12, output, receive_amount)
            .context("fee overflow")?;

    Ok(OutputEffect {
        amount,
        fee,
        funded: matches!(output, Bolt12Output::Receive(..)),
    })
}

async fn process_register(
    dbtx: &mut DatabaseTransaction<'_>,
    register: &Register,
    now: u64,
) -> Result<()> {
    let policy = &register.policy;

    ensure!(register.verify(), "invalid registration signature");
    ensure!(policy.expires_at > now, "registration is already expired");
    ensure!(
        policy.expires_at <= now.saturating_add(MAX_REGISTRATION_LIFETIME),
        "registration expires too far ahead"
    );

    prune_expired_registrations(dbtx, now).await;

    let id = policy.id();

    ensure!(
        dbtx.get_value(&Bolt12HandleKey(policy.handle))
            .await
            .is_none(),
        "routing handle is already registered"
    );
    ensure!(
        dbtx.get_value(&Bolt12RecipientKey(policy.claim_pk))
            .await
            .is_none(),
        "claim key is already registered"
    );

    let count = dbtx
        .get_value(&Bolt12RegistrationCountKey)
        .await
        .unwrap_or(0);

    ensure!(count < MAX_REGISTRATIONS, "registration capacity reached");

    dbtx.insert_new_entry(
        &Bolt12RegistrationKey(id),
        &Registration {
            policy: policy.clone(),
            stock_len: 0,
            stock_unused: 0,
            voided: false,
        },
    )
    .await;
    dbtx.insert_new_entry(&Bolt12HandleKey(policy.handle), &id)
        .await;
    dbtx.insert_new_entry(&Bolt12RecipientKey(policy.claim_pk), &id)
        .await;
    dbtx.insert_new_entry(&Bolt12ExpiryKey(policy.expires_at, id), &())
        .await;
    dbtx.insert_entry(&Bolt12RegistrationCountKey, &(count + 1))
        .await;

    Ok(())
}

/// Delete a bounded number of registrations whose last possible invoice has
/// expired, so their reservations can no longer be funded.
async fn prune_expired_registrations(dbtx: &mut DatabaseTransaction<'_>, now: u64) {
    let expired = dbtx
        .find_by_prefix(&Bolt12ExpiryPrefix)
        .await
        .map(|(key, ())| key)
        .take_while(|key| std::future::ready(key.0.saturating_add(INVOICE_LIFETIME) <= now))
        .take(REGISTRATIONS_PRUNED_PER_REGISTER)
        .collect::<Vec<_>>()
        .await;

    for key in expired {
        let id = key.1;

        dbtx.remove_entry(&key).await;

        let Some(registration) = dbtx.remove_entry(&Bolt12RegistrationKey(id)).await else {
            continue;
        };

        dbtx.remove_entry(&Bolt12HandleKey(registration.policy.handle))
            .await;
        dbtx.remove_entry(&Bolt12RecipientKey(registration.policy.claim_pk))
            .await;

        let stock = dbtx
            .find_by_prefix(&Bolt12StockRegistrationPrefix(id))
            .await
            .collect::<Vec<_>>()
            .await;

        // These hashes never appeared in an invoice, so they may be uploaded
        // again later.
        for (stock_key, item) in stock {
            dbtx.remove_entry(&stock_key).await;
            dbtx.remove_entry(&Bolt12PaymentHashKey(item.payment_hash))
                .await;
        }

        // Every entry is unfunded and, given the margin above, expired.
        for pending in dbtx
            .remove_entry(&Bolt12OfferPendingKey(id))
            .await
            .unwrap_or_default()
        {
            dbtx.remove_entry(&Bolt12ReservationKey(pending.reservation))
                .await;
        }

        let count = dbtx
            .get_value(&Bolt12RegistrationCountKey)
            .await
            .unwrap_or(0);

        dbtx.insert_entry(&Bolt12RegistrationCountKey, &count.saturating_sub(1))
            .await;
    }
}

async fn live_registration(
    dbtx: &mut DatabaseTransaction<'_>,
    id: RegistrationId,
    now: u64,
) -> Result<Registration> {
    let registration = dbtx
        .get_value(&Bolt12RegistrationKey(id))
        .await
        .context("unknown registration")?;

    ensure!(!registration.voided, "registration is voided");
    ensure!(
        registration.policy.expires_at > now,
        "registration is expired"
    );

    Ok(registration)
}

async fn process_add_stock(
    dbtx: &mut DatabaseTransaction<'_>,
    add: &AddStock,
    now: u64,
) -> Result<()> {
    let mut registration = live_registration(dbtx, add.registration, now).await?;

    ensure!(
        add.verify(&registration.policy.claim_pk),
        "invalid stock signature"
    );
    ensure!(
        (1..=MAX_STOCK_BATCH).contains(&add.items.len()),
        "stock batch size out of range"
    );
    ensure!(
        add.start == registration.stock_len,
        "stock does not continue at the next index"
    );

    let added = add.items.len() as u64;

    ensure!(
        registration.stock_len + added <= MAX_STOCK,
        "stock capacity reached"
    );

    for (index, item) in (add.start..).zip(&add.items) {
        ensure!(
            item.verify(add.registration, index),
            "invalid stock ciphertext"
        );
        // Inserting as we go also rejects a hash repeated within the batch.
        ensure!(
            dbtx.insert_entry(&Bolt12PaymentHashKey(item.payment_hash), &())
                .await
                .is_none(),
            "payment hash is already known"
        );

        dbtx.insert_new_entry(&Bolt12StockKey(add.registration, index), item)
            .await;
    }

    registration.stock_len += added;
    registration.stock_unused += added;

    dbtx.insert_entry(&Bolt12RegistrationKey(add.registration), &registration)
        .await;

    Ok(())
}

/// Whether a quorum of guardians currently approves `gateway`.
pub async fn gateway_is_approved(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    gateway: PublicKey,
) -> bool {
    let approvals = dbtx
        .find_by_prefix(&Bolt12GatewayVoteGatewayPrefix(gateway))
        .await
        .filter(|(_, approve)| std::future::ready(*approve))
        .count()
        .await;

    approvals >= quorum(cfg.consensus.tpe_pks.len())
}

/// Drop expired entries, deleting their reservations, and return the rest.
async fn live_pending(
    dbtx: &mut DatabaseTransaction<'_>,
    pending: Vec<Pending>,
    now: u64,
) -> Vec<Pending> {
    let mut live = Vec::with_capacity(pending.len());

    for entry in pending {
        if entry.expires_at > now {
            live.push(entry);
        } else {
            // Only unfunded reservations are listed, so this never touches a
            // funded receive.
            dbtx.remove_entry(&Bolt12ReservationKey(entry.reservation))
                .await;
        }
    }

    live
}

async fn process_reserve(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    reserve: &Reserve,
    now: u64,
) -> Result<()> {
    ensure!(reserve.verify(), "invalid reservation signature");
    ensure!(
        gateway_is_approved(dbtx, cfg, reserve.gateway).await,
        "gateway is not approved"
    );

    let bolt12 = cfg
        .consensus
        .bolt12
        .as_ref()
        .context("federated BOLT12 is disabled")?;

    let mut registration = live_registration(dbtx, reserve.registration, now).await?;

    ensure!(
        reservation_is_economical(
            &cfg.consensus.fee_consensus,
            &registration.policy,
            reserve.amount,
            reserve.gateway_fee,
            bolt12.claim_premium(reserve.source),
        ),
        "amount does not cover fees or the gateway fee exceeds policy"
    );

    let id = reserve.reservation_id();
    let entry = Pending {
        expires_at: now.saturating_add(INVOICE_LIFETIME),
        reservation: id,
    };

    let (payment_hash, sealed) = match reserve.source {
        Source::Stock { index } => {
            let item = dbtx
                .remove_entry(&Bolt12StockKey(reserve.registration, index))
                .await
                .context("stock item is unknown or already used")?;

            registration.stock_unused = registration.stock_unused.saturating_sub(1);

            (item.payment_hash, Sealed::Preimage(item.ciphertext))
        }
        Source::Pool { index } => {
            let item = take_pool_item(dbtx, &registration, index, &entry, now).await?;

            (item.payment_hash, item.sealed)
        }
    };

    let offer_pending = dbtx
        .get_value(&Bolt12OfferPendingKey(reserve.registration))
        .await
        .unwrap_or_default();
    let mut offer_pending = live_pending(dbtx, offer_pending, now).await;

    ensure!(
        offer_pending.len() < MAX_PENDING_PER_OFFER,
        "too many unpaid invoices for this offer"
    );

    offer_pending.push(entry.clone());

    dbtx.insert_entry(&Bolt12OfferPendingKey(reserve.registration), &offer_pending)
        .await;

    let gateway_pending = dbtx
        .get_value(&Bolt12GatewayPendingKey(reserve.gateway))
        .await
        .unwrap_or_default();
    let mut gateway_pending = live_pending(dbtx, gateway_pending, now).await;

    ensure!(
        gateway_pending.len() < MAX_PENDING_PER_GATEWAY,
        "too many unpaid invoices for this gateway"
    );

    gateway_pending.push(entry);

    dbtx.insert_entry(&Bolt12GatewayPendingKey(reserve.gateway), &gateway_pending)
        .await;

    ensure!(
        dbtx.insert_entry(
            &Bolt12ReservationKey(id),
            &Reservation {
                registration: reserve.registration,
                source: reserve.source,
                payment_hash,
                sealed,
                claim_pk: registration.policy.claim_pk,
                gateway: reserve.gateway,
                amount: reserve.amount,
                gateway_fee: reserve.gateway_fee,
                terms: reserve.terms,
                created_at: now,
            },
        )
        .await
        .is_none(),
        "source is already reserved"
    );

    dbtx.insert_entry(&Bolt12RegistrationKey(reserve.registration), &registration)
        .await;

    Ok(())
}

/// Take the generated preimage at `index` for a reservation, counting it
/// against the pool's allowance.
async fn take_pool_item(
    dbtx: &mut DatabaseTransaction<'_>,
    registration: &Registration,
    index: u64,
    entry: &Pending,
    now: u64,
) -> Result<PoolItem> {
    // The recipient pays more for a generated preimage, so one is used only
    // when it asked for that and its own stock is gone.
    ensure!(
        registration.policy.allow_pool,
        "the offer does not accept generated preimages"
    );
    ensure!(registration.stock_unused == 0, "the offer still has stock");

    let item = dbtx
        .remove_entry(&Bolt12PoolItemKey(index))
        .await
        .context("pool item is unknown or already used")?;

    let pool_pending = dbtx
        .get_value(&Bolt12PoolPendingKey)
        .await
        .unwrap_or_default();
    let mut pool_pending = live_pending(dbtx, pool_pending, now).await;

    ensure!(
        pool_pending.len() < MAX_PENDING_POOL,
        "too many unpaid invoices use generated preimages"
    );

    pool_pending.push(entry.clone());

    dbtx.insert_entry(&Bolt12PoolPendingKey, &pool_pending)
        .await;

    Ok(item)
}

fn without(pending: Option<Vec<Pending>>, id: ReservationId) -> Vec<Pending> {
    pending
        .unwrap_or_default()
        .into_iter()
        .filter(|entry| entry.reservation != id)
        .collect()
}

/// Fund a reservation, returning the amount the output must carry.
async fn process_receive(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    id: ReservationId,
    outpoint: OutPoint,
    now: u64,
) -> Result<Amount> {
    let reservation = dbtx
        .remove_entry(&Bolt12ReservationKey(id))
        .await
        .context("reservation is unknown or already funded")?;

    ensure!(reservation.expires_at() > now, "invoice has expired");

    // A paid receive stops counting against both allowances. Empty lists are
    // removed so a pruned registration or an idle gateway leaves nothing
    // behind.
    let offer_key = Bolt12OfferPendingKey(reservation.registration);
    let offer_pending = without(dbtx.remove_entry(&offer_key).await, id);

    if !offer_pending.is_empty() {
        dbtx.insert_entry(&offer_key, &offer_pending).await;
    }

    let gateway_key = Bolt12GatewayPendingKey(reservation.gateway);
    let gateway_pending = without(dbtx.remove_entry(&gateway_key).await, id);

    if !gateway_pending.is_empty() {
        dbtx.insert_entry(&gateway_key, &gateway_pending).await;
    }

    if reservation.source.is_pool() {
        let pool_pending = without(dbtx.remove_entry(&Bolt12PoolPendingKey).await, id);

        if !pool_pending.is_empty() {
            dbtx.insert_entry(&Bolt12PoolPendingKey, &pool_pending)
                .await;
        }
    }

    let contract = reservation.contract();

    dbtx.insert_new_entry(&Bolt12ContractKey(outpoint), &contract)
        .await;

    let stream_index = dbtx.get_value(&Bolt12StreamIndexKey).await.unwrap_or(0);

    dbtx.insert_entry(&Bolt12ContractIndexKey(outpoint), &stream_index)
        .await;
    dbtx.insert_entry(
        &Bolt12StreamKey(stream_index),
        &StreamedReceive {
            outpoint,
            contract: contract.clone(),
        },
    )
    .await;
    dbtx.insert_entry(&Bolt12StreamIndexKey, &(stream_index + 1))
        .await;

    // Written atomically with acceptance: a rejected funding transaction
    // leaves no share behind.
    let shares = contract
        .ciphertexts()
        .iter()
        .map(|(ciphertext, _)| tpe::create_dk_share(&cfg.private.sk, ciphertext))
        .collect::<Vec<_>>();

    dbtx.insert_entry(&Bolt12DecryptionSharesKey(outpoint), &shares)
        .await;

    Ok(contract.amount)
}

/// What spending a funded receive requires and moves.
pub struct InputEffect {
    /// The key that must sign.
    pub pub_key: PublicKey,
    pub amount: Amount,
    /// Charged on top of the ordinary input fee.
    pub premium: Amount,
}

/// Spend a funded receive: the recipient's claim if the preimage is released,
/// otherwise the gateway's refund.
pub async fn process_input(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    outpoint: OutPoint,
    unlock: &Bolt12Unlock,
) -> Result<InputEffect, LightningInputError> {
    let contract = dbtx
        .remove_entry(&Bolt12ContractKey(outpoint))
        .await
        .ok_or(LightningInputError::UnknownContract)?;

    if let Some(index) = dbtx.remove_entry(&Bolt12ContractIndexKey(outpoint)).await {
        dbtx.remove_entry(&Bolt12StreamKey(index)).await;
    }

    if unlock.is_pool() != contract.source.is_pool()
        || !contract.verify_agg_decryption_keys(&cfg.consensus.tpe_agg_pk, unlock.keys())
    {
        return Err(LightningInputError::InvalidDecryptionKey);
    }

    let premium = cfg
        .consensus
        .bolt12
        .as_ref()
        .map_or(Amount::ZERO, |bolt12| bolt12.unlock_premium(unlock));

    if contract.release(unlock.keys()).is_some() {
        return Ok(InputEffect {
            pub_key: contract.claim_pk,
            amount: contract.amount,
            premium,
        });
    }

    // The gateway gets its funding back. A stock item without its preimage
    // is the recipient's fault, so the offer also stops issuing invoices; a
    // generated preimage can only fail through misbehaving guardians.
    if !contract.source.is_pool()
        && let Some(mut registration) = dbtx
            .get_value(&Bolt12RegistrationKey(contract.registration))
            .await
    {
        registration.voided = true;

        dbtx.insert_entry(&Bolt12RegistrationKey(contract.registration), &registration)
            .await;
    }

    Ok(InputEffect {
        pub_key: contract.refund_pk,
        amount: contract.amount,
        premium,
    })
}

/// Record a guardian's vote. Repeating the stored vote is rejected so it is
/// not ordered again.
pub async fn process_gateway_vote(
    dbtx: &mut DatabaseTransaction<'_>,
    cfg: &LightningConfig,
    peer: PeerId,
    gateway: PublicKey,
    approve: bool,
) -> Result<()> {
    ensure!(
        cfg.consensus.bolt12.is_some(),
        "federated BOLT12 is disabled"
    );

    let previous = dbtx
        .insert_entry(&Bolt12GatewayVoteKey(gateway, peer), &approve)
        .await
        .unwrap_or(false);

    ensure!(previous != approve, "gateway vote is redundant");

    Ok(())
}

#[cfg(test)]
mod tests;
