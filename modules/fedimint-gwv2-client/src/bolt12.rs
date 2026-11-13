//! The gateway's part in federated BOLT12 receives: turning an invoice
//! request into a federation-signed invoice, and funding the recipient's
//! claim once the Lightning payment is held. See `docs/federated_bolt12.md`.
//!
//! The gateway pays nothing before it holds the payment. A reservation is
//! free, and funding happens only for a held payment whose hash and amount
//! match an invoice this gateway issued.

mod receive_sm;
pub mod signing;

use std::future::Future;
use std::sync::Arc;

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
use fedimint_core::{Amount, impl_db_record};
use fedimint_lnv2_common::bolt12::invoice::encode_payment_path;
use fedimint_lnv2_common::bolt12::{
    Bolt12Output, RegistrationId, Reservation, ReservationId, Reserve, Source,
    reservation_is_economical, terms_hash,
};
use fedimint_lnv2_common::{LightningCommonInit, LightningOutput, LightningOutputV0};
use lightning::blinded_path::payment::BlindedPaymentPath;
use lightning::offers::invoice::Bolt12Invoice;
use lightning::util::ser::Writeable;

pub use self::receive_sm::{Bolt12ReceiveSMState, Bolt12ReceiveStateMachine};
use self::signing::{SigningJob, sign_invoice};
use crate::api::GatewayFederationApi;
use crate::complete_sm::IncomingCircuitKey;
use crate::{
    GatewayClientModuleV2, GatewayClientStateMachinesV2, GatewayOperationMetaV2,
    GatewayOperationRoleV2, IncomingRelayPlan, LNV2_CLAIM_DEADLINE_MARGIN, RelayIncomingHtlcError,
    incoming_circuit_operation_id, incoming_relay_plan, operation_creation_failed_permanently,
};

/// How often to pick another stock item after losing a race for one.
const RESERVE_ATTEMPTS: usize = 3;

#[repr(u8)]
enum DbKeyPrefix {
    Bolt12Issued = 0x50,
    Bolt12Payment = 0x51,
}

/// The invoice issued for an invoice request, keyed by the request's hash, so
/// a payer that repeats a request gets the same invoice back.
#[derive(Debug, Encodable, Decodable)]
struct Bolt12IssuedKey(sha256::Hash);

impl_db_record!(
    key = Bolt12IssuedKey,
    value = Vec<u8>,
    db_prefix = DbKeyPrefix::Bolt12Issued,
);

/// The reservation behind a payment hash this gateway issued an invoice for.
#[derive(Debug, Encodable, Decodable)]
struct Bolt12PaymentKey([u8; 32]);

impl_db_record!(
    key = Bolt12PaymentKey,
    value = Reservation,
    db_prefix = DbKeyPrefix::Bolt12Payment,
);

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

        ensure!(
            reservation_is_economical(
                &self.cfg.fee_consensus,
                &state.policy,
                request.amount,
                request.gateway_fee
            ),
            "amount does not cover fees or the fee exceeds the recipient's limit"
        );

        let (reservation, path) = self
            .reserve_bolt12_stock(registration, &request, &payment_path)
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
        // always finds its reservation.
        let mut dbtx = db.begin_transaction().await;

        dbtx.insert_entry(&Bolt12PaymentKey(reservation.payment_hash), &reservation)
            .await;
        dbtx.insert_entry(&Bolt12IssuedKey(request_hash), &invoice.encode())
            .await;
        dbtx.commit_tx_result().await?;

        Ok(invoice)
    }

    /// Reserve one of the offer's unused stock items for this request.
    /// Returns the reservation and the encoded payment path it pins.
    async fn reserve_bolt12_stock<F, Fut>(
        &self,
        registration: RegistrationId,
        request: &Bolt12InvoiceRequest,
        payment_path: &F,
    ) -> Result<(Reservation, Vec<u8>)>
    where
        F: Fn([u8; 32]) -> Fut,
        Fut: Future<Output = Result<BlindedPaymentPath>>,
    {
        let mut last_error = None;

        // Another gateway may reserve the same item first; that only costs a
        // retry with the next one.
        for _ in 0..RESERVE_ATTEMPTS {
            let (index, item) = self
                .module_api
                .bolt12_next_stock(registration)
                .await?
                .context("offer has no unused stock left")?;

            // The path commits to the payment hash, so it must be built
            // before the reservation that pins it.
            let path = encode_payment_path(&payment_path(item.payment_hash).await?)?;

            let reserve = Reserve::new(
                registration,
                Source::Stock { index },
                request.amount,
                request.gateway_fee,
                terms_hash(&request.invoice_request, &path),
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
                reservation.gateway == self.keypair.public_key(),
                "stock item was reserved by another gateway"
            );

            return Ok((reservation, path));
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
    pub async fn relay_bolt12_htlc(
        &self,
        reservation: Reservation,
        payment_hash: sha256::Hash,
        circuit: IncomingCircuitKey,
        amount_msat: u64,
        blocks_to_claim_deadline: u32,
    ) -> Result<(), RelayIncomingHtlcError> {
        let id = Reservation::id(reservation.registration, reservation.source);
        let receive_operation_id = receive_operation_id(id);
        let completion_operation_id = incoming_circuit_operation_id(receive_operation_id, circuit);

        let plan = incoming_relay_plan(
            self.client_ctx.operation_exists(receive_operation_id).await,
            self.client_ctx
                .operation_exists(completion_operation_id)
                .await,
            false,
        );

        if plan == IncomingRelayPlan::Replay {
            return Ok(());
        }

        if plan == IncomingRelayPlan::CreateReceiveAndCompletion {
            // Funding pays the recipient the invoice amount less our fee, so
            // the payment we hold must be exactly the invoice amount.
            if amount_msat != reservation.amount.msats {
                return Err(RelayIncomingHtlcError::Bolt12AmountMismatch {
                    expected_msat: reservation.amount.msats,
                    received_msat: amount_msat,
                });
            }

            if blocks_to_claim_deadline < LNV2_CLAIM_DEADLINE_MARGIN {
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

            let creation_result = self
                .client_ctx
                .finalize_and_submit_transaction(
                    receive_operation_id,
                    LightningCommonInit::KIND.as_str(),
                    |_| GatewayOperationMetaV2::role(GatewayOperationRoleV2::Receive),
                    TransactionBuilder::new().with_outputs(outputs),
                )
                .await;

            if let Err(error) = creation_result {
                let operation_exists = self.client_ctx.operation_exists(receive_operation_id).await;

                if operation_creation_failed_permanently(true, operation_exists) {
                    return Err(error.into());
                }
            }
        }

        self.start_circuit_completion(
            receive_operation_id,
            completion_operation_id,
            payment_hash,
            circuit,
        )
        .await
    }
}
