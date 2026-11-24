//! The gateway's part in federated BOLT12 receives: turning an invoice
//! request into a federation-signed invoice, and funding the recipient's
//! claim once the Lightning payment is held. See `docs/federated_bolt12.md`.
//!
//! The gateway pays nothing before it holds the payment. A reservation is
//! free, and funding happens only for a held payment whose hash and amount
//! match an invoice this gateway issued.

mod receive_sm;
pub mod signing;

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, LazyLock};

use anyhow::{Context, Result, ensure};
use bitcoin::hashes::sha256;
use fedimint_client_module::module::OutPointRange;
use fedimint_client_module::transaction::{
    ClientOutput, ClientOutputBundle, ClientOutputSM, TransactionBuilder,
};
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{Amounts, CommonModuleInit};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::{Amount, impl_db_record};
use fedimint_lnv2_common::bolt12::invoice::encode_payment_path;
use fedimint_lnv2_common::bolt12::{
    Bolt12Output, ReceivePolicy, RegistrationId, Reservation, ReservationId, Reserve, Source,
    reservation_is_economical, terms_hash,
};
use fedimint_lnv2_common::{LightningCommonInit, LightningOutput, LightningOutputV0};
use futures::StreamExt as _;
use lightning::blinded_path::payment::BlindedPaymentPath;
use lightning::offers::invoice::Bolt12Invoice;
use lightning::util::ser::Writeable;

pub use self::receive_sm::{Bolt12ReceiveSMState, Bolt12ReceiveStateMachine};
use self::signing::{SigningJob, sign_invoice};
use crate::api::GatewayFederationApi;
use crate::complete_sm::IncomingCircuitKey;
use crate::{
    GatewayClientModuleV2, GatewayClientStateMachinesV2, GatewayOperationMetaV2,
    GatewayOperationRoleV2, IncomingRelayPlan, RelayIncomingHtlcError,
    incoming_circuit_operation_id,
};

/// How many candidate stock or pool items to try after losing a race or
/// hitting a locally collided payment hash.
const RESERVE_ATTEMPTS: usize = 8;

/// Blocks a held BOLT12 payment must leave before its claim deadline for the
/// gateway to fund the recipient's claim.
///
/// Invoice payment paths ask for 144 blocks, but a blinded path's delta is
/// only advisory: a payer may send an HTLC that expires much sooner, and once
/// funded the claim cannot be taken back. The node's claim deadline already
/// sits well inside the HTLC's expiry (a correctly built payment left about 80
/// blocks on regtest), and settling takes seconds, so about six hours is ample
/// while still refusing HTLCs too short to settle safely.
pub const BOLT12_CLAIM_DEADLINE_MARGIN: u32 = 36;

#[repr(u8)]
enum DbKeyPrefix {
    Issued = 0x50,
    Payment = 0x51,
    IssuedExpiry = 0x52,
    UnfundedExpiry = 0x53,
}

/// The invoice issued for an invoice request, keyed by the request's hash, so
/// a payer that repeats a request gets the same invoice back.
#[derive(Debug, Clone, Encodable, Decodable)]
struct Bolt12IssuedKey(sha256::Hash);

impl_db_record!(
    key = Bolt12IssuedKey,
    value = Vec<u8>,
    db_prefix = DbKeyPrefix::Issued,
);

/// Expiry index for cached issued invoices (`(expires_at_secs, request_hash)`),
/// sorted chronologically for `O(PRUNE_PER_ISSUE)` pruning without scanning
/// live rows.
#[derive(Debug, Clone, Encodable, Decodable)]
struct Bolt12IssuedExpiryKey(u64, sha256::Hash);

impl_db_record!(
    key = Bolt12IssuedExpiryKey,
    value = (),
    db_prefix = DbKeyPrefix::IssuedExpiry,
);

/// The reservation behind a payment hash this gateway issued an invoice for.
#[derive(Debug, Clone, Encodable, Decodable)]
struct Bolt12PaymentKey([u8; 32]);

impl_db_record!(
    key = Bolt12PaymentKey,
    value = Reservation,
    db_prefix = DbKeyPrefix::Payment,
);

/// Expiry index for cached reservations (`(expires_at_secs, payment_hash)`).
/// Once past the retention window, the index entry is always removed (while
/// `Bolt12PaymentKey` is kept if a receive operation exists), preventing
/// funded invoices from stalling pruning of later expired entries.
#[derive(Debug, Clone, Encodable, Decodable)]
struct Bolt12UnfundedExpiryKey(u64, [u8; 32]);

impl_db_record!(
    key = Bolt12UnfundedExpiryKey,
    value = ReservationId,
    db_prefix = DbKeyPrefix::UnfundedExpiry,
);

/// Retention margin past invoice expiry before pruning local BOLT12 cache rows.
const LOCAL_RECORD_RETENTION_SECS: u64 = 3600;
/// Bounded number of expired local BOLT12 records pruned per invoice issuance.
const PRUNE_PER_ISSUE: usize = 16;

/// A payer's request, as the gateway's Lightning node received it.
#[derive(Debug, Clone)]
pub struct Bolt12InvoiceRequest {
    /// The routing handle from the offer's metadata.
    pub handle: [u8; 32],
    /// The exact invoice request bytes.
    pub invoice_request: Vec<u8>,
    /// The amount the payer asks to pay.
    pub amount: Amount,
    /// What the gateway keeps from the payment.
    pub gateway_fee: Amount,
}

/// Requests being issued, by request hash.
static ISSUING: LazyLock<std::sync::Mutex<HashMap<sha256::Hash, Arc<futures::lock::Mutex<()>>>>> =
    LazyLock::new(Default::default);

/// Exclusive issuance of one invoice request.
struct IssuingLock {
    request_hash: sha256::Hash,
    guard: Option<futures::lock::OwnedMutexGuard<()>>,
}

impl IssuingLock {
    async fn acquire(request_hash: sha256::Hash) -> Self {
        let lock = ISSUING
            .lock()
            .expect("not poisoned")
            .entry(request_hash)
            .or_default()
            .clone();

        Self {
            request_hash,
            guard: Some(lock.lock_owned().await),
        }
    }
}

impl Drop for IssuingLock {
    fn drop(&mut self) {
        let mut issuing = ISSUING.lock().expect("not poisoned");

        drop(self.guard.take());

        // Only the map holds the lock now unless another request waits.
        if issuing
            .get(&self.request_hash)
            .is_some_and(|lock| Arc::strong_count(lock) == 1)
        {
            issuing.remove(&self.request_hash);
        }
    }
}

fn receive_operation_id(reservation: ReservationId) -> OperationId {
    OperationId::from_encodable(&("fedimint/bolt12/gateway-receive/v1", reservation))
}

impl GatewayClientModuleV2 {
    /// Issue the federation-signed invoice for an invoice request.
    ///
    /// `payment_path` asks the Lightning node to expect a payment for the
    /// given hash, whose preimage it does not know, and returns the blinded
    /// path the payer should use.
    ///
    /// # Errors
    ///
    /// Fails if the offer is unknown, expired, voided or out of stock, if the
    /// terms violate the recipient's policy, if this gateway is not approved
    /// or over its allowance, or if a quorum of guardians does not sign.
    pub async fn issue_bolt12_invoice<F, Fut>(
        &self,
        request: Bolt12InvoiceRequest,
        payment_path: F,
    ) -> Result<Bolt12Invoice>
    where
        F: Fn([u8; 32]) -> Fut,
        Fut: Future<Output = Result<BlindedPaymentPath>>,
    {
        ensure!(self.cfg.bolt12.is_some(), "federated BOLT12 is disabled");

        let request_hash: sha256::Hash =
            ("fedimint/bolt12/issued/v1", &request.invoice_request).consensus_hash();
        let db = self.client_ctx.module_db();

        // A repeated request waits for the first and then finds its invoice,
        // instead of reserving a second payment hash.
        let _issuing = IssuingLock::acquire(request_hash).await;

        if let Some(invoice) = db
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12IssuedKey(request_hash))
            .await
        {
            return Bolt12Invoice::try_from(invoice)
                .map_err(|e| anyhow::anyhow!("stored invoice is invalid: {e:?}"));
        }

        let (registration, state) = self
            .module_api
            .bolt12_registration_by_handle(request.handle)
            .await?
            .context("offer is not registered with this federation")?;

        let (reservation, path) = self
            .reserve_bolt12(registration, &state.policy, &request, &payment_path)
            .await?;

        let invoice = sign_invoice(
            &self.module_api,
            &self.cfg,
            &self.keypair,
            SigningJob {
                policy: &state.policy,
                reservation: &reservation,
                invoice_request: &request.invoice_request,
                payment_path: &path,
            },
        )
        .await?;

        // Stored before the invoice leaves the gateway, so a payment for it
        // always finds its reservation. Index by expiry so pruning visits only
        // expired rows in O(PRUNE_PER_ISSUE) without scanning live invoices or
        // stalling on retained funded reservations.
        let now_secs = duration_since_epoch().as_secs();
        let invoice_expires_at = invoice
            .created_at()
            .as_secs()
            .saturating_add(invoice.relative_expiry().as_secs());
        let res_id = Reservation::id(reservation.registration, reservation.source);
        let cutoff = now_secs.saturating_sub(LOCAL_RECORD_RETENTION_SECS);
        let mut dbtx = db.begin_transaction().await;

        dbtx.insert_entry(&Bolt12PaymentKey(reservation.payment_hash), &reservation)
            .await;
        dbtx.insert_entry(
            &Bolt12UnfundedExpiryKey(reservation.expires_at(), reservation.payment_hash),
            &res_id,
        )
        .await;
        dbtx.insert_entry(&Bolt12IssuedKey(request_hash), &invoice.encode())
            .await;
        dbtx.insert_entry(
            &Bolt12IssuedExpiryKey(invoice_expires_at, request_hash),
            &(),
        )
        .await;

        let zero_hash = bitcoin::hashes::Hash::all_zeros();
        let expired_issued: Vec<Bolt12IssuedExpiryKey> = dbtx
            .find_by_range(
                Bolt12IssuedExpiryKey(0, zero_hash)..Bolt12IssuedExpiryKey(cutoff, zero_hash),
            )
            .await
            .take(PRUNE_PER_ISSUE)
            .map(|(key, ())| key)
            .collect()
            .await;

        for key in expired_issued {
            if key.1 != request_hash {
                dbtx.remove_entry(&Bolt12IssuedKey(key.1)).await;
                dbtx.remove_entry(&key).await;
            }
        }

        let expired_payments: Vec<(Bolt12UnfundedExpiryKey, ReservationId)> = dbtx
            .find_by_range(
                Bolt12UnfundedExpiryKey(0, [0; 32])..Bolt12UnfundedExpiryKey(cutoff, [0; 32]),
            )
            .await
            .take(PRUNE_PER_ISSUE)
            .collect()
            .await;

        for (key, expired_res_id) in expired_payments {
            if key.1 == reservation.payment_hash {
                continue;
            }
            // Always drop the expiry-index row once past retention so retained
            // funded reservations never stall pruning of later expired rows.
            dbtx.remove_entry(&key).await;
            if !self
                .client_ctx
                .operation_exists_dbtx(&mut dbtx.to_ref_nc(), receive_operation_id(expired_res_id))
                .await
            {
                dbtx.remove_entry(&Bolt12PaymentKey(key.1)).await;
            }
        }

        dbtx.commit_tx_result().await?;

        Ok(invoice)
    }

    /// Up to 8 candidate sources for `registration`, starting past `min_stock`
    /// (or past `min_pool` once unused stock is exhausted and the recipient
    /// allows pool preimages).
    async fn candidate_bolt12_sources(
        &self,
        registration: RegistrationId,
        policy: &ReceivePolicy,
        min_stock: u64,
        min_pool: u64,
    ) -> Result<Vec<(Source, [u8; 32])>> {
        let stock = self
            .module_api
            .bolt12_stock_items(registration, min_stock)
            .await?;
        if !stock.is_empty() {
            return Ok(stock
                .into_iter()
                .map(|(index, item)| (Source::Stock { index }, item.payment_hash))
                .collect());
        }

        // Only fall back to the pool if the offer truly has no unused stock
        // remaining (not merely because we skipped past `min_stock`).
        if min_stock > 0
            && self
                .module_api
                .bolt12_next_stock(registration)
                .await?
                .is_some()
        {
            anyhow::bail!("no usable stock items left without a local payment-hash collision");
        }

        ensure!(policy.allow_pool, "offer has no unused stock left");

        let pool = self.module_api.bolt12_pool_items(min_pool).await?;
        ensure!(
            !pool.is_empty(),
            "offer has no unused stock left and the pool is empty"
        );

        Ok(pool
            .into_iter()
            .map(|(index, payment_hash)| (Source::Pool { index }, payment_hash))
            .collect())
    }

    /// Reserve a payment hash for this request. Returns the reservation and
    /// the encoded payment path it pins.
    async fn reserve_bolt12<F, Fut>(
        &self,
        registration: RegistrationId,
        policy: &ReceivePolicy,
        request: &Bolt12InvoiceRequest,
        payment_path: &F,
    ) -> Result<(Reservation, Vec<u8>)>
    where
        F: Fn([u8; 32]) -> Fut,
        Fut: Future<Output = Result<BlindedPaymentPath>>,
    {
        let bolt12 = self
            .cfg
            .bolt12
            .as_ref()
            .context("federated BOLT12 is disabled")?;

        let mut last_error = None;
        let mut min_stock = 0u64;
        let mut min_pool = 0u64;
        let mut attempts = 0usize;

        // Another gateway may reserve the same item first, or a payment hash
        // may already be registered locally (e.g. front-run via BOLT11 or an
        // interrupted previous issuance); skip collided hashes and retry with
        // the next unused candidate.
        while attempts < RESERVE_ATTEMPTS {
            let candidates = self
                .candidate_bolt12_sources(registration, policy, min_stock, min_pool)
                .await?;

            for (source, payment_hash) in candidates {
                if attempts >= RESERVE_ATTEMPTS {
                    break;
                }
                attempts += 1;

                match source {
                    Source::Stock { index } => min_stock = index.saturating_add(1),
                    Source::Pool { index } => min_pool = index.saturating_add(1),
                }

                ensure!(
                    reservation_is_economical(
                        &self.cfg.fee_consensus,
                        policy,
                        request.amount,
                        request.gateway_fee,
                        bolt12.claim_premium(source),
                    ),
                    "amount does not cover fees or the fee exceeds the recipient's limit"
                );

                // The path commits to the payment hash, so it must be built
                // before the reservation that pins it. If the hash is already
                // claimed locally (BOLT11 collision or interrupted prior issue),
                // skip to the next unused item instead of wedging the offer.
                let path = match payment_path(payment_hash).await {
                    Ok(path) => encode_payment_path(&path)?,
                    Err(error) => {
                        last_error = Some(error);
                        continue;
                    }
                };

                let expected_terms = terms_hash(&request.invoice_request, &path);

                let reserve = Reserve::new(
                    registration,
                    source,
                    request.amount,
                    request.gateway_fee,
                    expected_terms,
                    &self.keypair,
                );
                let id = reserve.reservation_id();

                if let Err(error) = self
                    .submit_bolt12_output(Bolt12Output::Reserve(reserve))
                    .await
                {
                    last_error = Some(error);
                    continue;
                }

                let reservation = self
                    .module_api
                    .bolt12_reservation(id)
                    .await?
                    .context("accepted reservation is missing")?;

                ensure!(
                    reservation.registration == registration
                        && reservation.source == source
                        && reservation.payment_hash == payment_hash
                        && reservation.gateway == self.keypair.public_key()
                        && reservation.amount == request.amount
                        && reservation.gateway_fee == request.gateway_fee
                        && reservation.terms == expected_terms,
                    "accepted reservation does not match requested terms or payment hash"
                );

                return Ok((reservation, path));
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no reservation attempt was made")))
    }

    /// Submit an output that moves no funds and wait for it to be accepted.
    async fn submit_bolt12_output(&self, output: Bolt12Output) -> Result<()> {
        let operation_id = OperationId::new_random();

        let outputs = self
            .client_ctx
            .make_client_outputs(ClientOutputBundle::new_no_sm(vec![ClientOutput {
                output: LightningOutput::V0(LightningOutputV0::Bolt12(output)),
                amounts: Amounts::ZERO,
            }]));

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                |_| GatewayOperationMetaV2::role(GatewayOperationRoleV2::Bolt12Reserve),
                TransactionBuilder::new().with_outputs(outputs),
            )
            .await?;

        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(range.txid())
            .await
            .map_err(|e| anyhow::anyhow!("the federation rejected the reservation: {e}"))
    }

    /// The reservation behind a payment hash, if this gateway issued a
    /// federated BOLT12 invoice for it.
    pub async fn bolt12_reservation_for_hash(
        &self,
        payment_hash: sha256::Hash,
    ) -> Option<Reservation> {
        use bitcoin::hashes::Hash;

        self.client_ctx
            .module_db()
            .begin_transaction_nc()
            .await
            .get_value(&Bolt12PaymentKey(payment_hash.to_byte_array()))
            .await
    }

    /// Fund the recipient's claim for a held BOLT12 payment and start the
    /// operation that settles or fails the payment's circuit.
    ///
    /// A receive or circuit that is already being handled is joined rather
    /// than started twice.
    ///
    /// # Errors
    ///
    /// Fails with a [`RelayIncomingHtlcError`] if the held amount differs from
    /// the invoice, if a fresh receive is not funded because the claim
    /// deadline is too close or the federation does not answer, or if the
    /// funding transaction or completion operation could not be started.
    #[allow(clippy::too_many_arguments)]
    async fn fresh_bolt12_receive_funding(
        &self,
        id: ReservationId,
        reservation: &Reservation,
        payment_hash: sha256::Hash,
        receive_operation_id: OperationId,
        amount_msat: u64,
        blocks_to_claim_deadline: u32,
        receive_enabled: bool,
    ) -> Result<TransactionBuilder, RelayIncomingHtlcError> {
        if !receive_enabled {
            return Err(RelayIncomingHtlcError::ReceiveDisabled);
        }

        // Funding pays the recipient the invoice amount less our fee, so
        // the payment we hold must be exactly the invoice amount.
        if amount_msat != reservation.amount.msats {
            return Err(RelayIncomingHtlcError::Bolt12AmountMismatch {
                expected_msat: reservation.amount.msats,
                received_msat: amount_msat,
            });
        }

        if blocks_to_claim_deadline < BOLT12_CLAIM_DEADLINE_MARGIN {
            return Err(RelayIncomingHtlcError::ClaimDeadlineTooClose {
                blocks_to_claim_deadline,
            });
        }

        self.ensure_federation_responsive(payment_hash).await?;

        let contract = reservation.contract();
        let refund_keypair = self.keypair;

        let client_output = ClientOutput::<LightningOutput> {
            output: LightningOutput::V0(LightningOutputV0::Bolt12(Bolt12Output::Receive(id))),
            amounts: Amounts::new_bitcoin(contract.amount),
        };
        let client_output_sm = ClientOutputSM::<GatewayClientStateMachinesV2> {
            state_machines: Arc::new(move |range: OutPointRange| {
                assert_eq!(range.count(), 1);

                vec![GatewayClientStateMachinesV2::Bolt12Receive(
                    Bolt12ReceiveStateMachine {
                        operation_id: receive_operation_id,
                        contract: contract.clone(),
                        outpoint: range
                            .into_iter()
                            .next()
                            .expect("the range holds one outpoint"),
                        refund_keypair,
                        state: Bolt12ReceiveSMState::Funding,
                    },
                )]
            }),
        };

        let outputs = self.client_ctx.make_client_outputs(ClientOutputBundle::new(
            vec![client_output],
            vec![client_output_sm],
        ));

        Ok(TransactionBuilder::new().with_outputs(outputs))
    }

    pub async fn relay_bolt12_htlc(
        &self,
        reservation: Reservation,
        payment_hash: sha256::Hash,
        circuit: IncomingCircuitKey,
        amount_msat: u64,
        blocks_to_claim_deadline: u32,
        receive_enabled: bool,
    ) -> Result<(), RelayIncomingHtlcError> {
        let id = Reservation::id(reservation.registration, reservation.source);
        let receive_operation_id = receive_operation_id(id);
        let completion_operation_id = incoming_circuit_operation_id(receive_operation_id, circuit);

        let funding = match self
            .read_incoming_relay_plan(receive_operation_id, completion_operation_id, circuit)
            .await
        {
            IncomingRelayPlan::Replay => return Ok(()),
            IncomingRelayPlan::AddCompletion => None,
            IncomingRelayPlan::CreateReceiveAndCompletion => match self
                .fresh_bolt12_receive_funding(
                    id,
                    &reservation,
                    payment_hash,
                    receive_operation_id,
                    amount_msat,
                    blocks_to_claim_deadline,
                    receive_enabled,
                )
                .await
            {
                Ok(funding) => Some(funding),
                // A concurrent relay may have funded the claim while checks ran;
                // re-read the persisted operations before returning an error that
                // would allow failing the HTLC back.
                Err(error) => match self
                    .read_incoming_relay_plan(
                        receive_operation_id,
                        completion_operation_id,
                        circuit,
                    )
                    .await
                {
                    IncomingRelayPlan::Replay => return Ok(()),
                    IncomingRelayPlan::AddCompletion => None,
                    IncomingRelayPlan::CreateReceiveAndCompletion => return Err(error),
                },
            },
        };

        self.commit_receive_and_completion(
            receive_operation_id,
            completion_operation_id,
            payment_hash,
            circuit,
            funding,
            None,
        )
        .await
    }
}
