mod api;
pub mod bolt12;
mod complete_sm;
pub mod events;
mod receive_sm;
mod send_sm;

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::Message;
use events::{IncomingPaymentStarted, OutgoingPaymentStarted};
use fedimint_api_client::api::{DynModuleApi, FederationError};
use fedimint_client::ClientHandleArc;
use fedimint_client_module::error::{ClientModuleError, OperationAlreadyExistsError};
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule, OutPointRange};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientOutput, ClientOutputBundle, ClientOutputSM, TransactionBuilder,
};
use fedimint_client_module::{
    DynGlobalClientContext, TransactionSubmitError, sm_enum_variant_translation,
};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{AutocommitError, DatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::task::timeout;
use fedimint_core::time::now;
use fedimint_core::util::{FmtCompact, Spanned, backoff_util, retry};
use fedimint_core::{Amount, OutPoint, PeerId, apply, async_trait_maybe_send, secp256k1};
use fedimint_lightning::{InterceptPaymentResponse, LightningRpcError};
use fedimint_lnv2_common::config::LightningClientConfig;
use fedimint_lnv2_common::contracts::{IncomingContract, PaymentImage};
use fedimint_lnv2_common::gateway_api::SendPaymentPayload;
use fedimint_lnv2_common::{
    LightningCommonInit, LightningInputV0, LightningInvoice, LightningModuleTypes, LightningOutput,
    LightningOutputV0,
};
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use receive_sm::{ReceiveSMState, ReceiveStateMachine};
use secp256k1::schnorr::Signature;
use send_sm::{SendSMState, SendStateMachine};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tpe::{AggregatePublicKey, PublicKeyShare};
use tracing::{info, warn};

use crate::api::GatewayFederationApi;
use crate::bolt12::Bolt12ReceiveSMState;
pub use crate::complete_sm::IncomingCircuitKey;
use crate::complete_sm::{
    CircuitCompleteSMCommon, CircuitCompleteStateMachine, CompleteSMState, CompleteStateMachine,
};
use crate::receive_sm::ReceiveSMCommon;
use crate::send_sm::SendSMCommon;

/// Bound on the federation liveness probe that gates funding a fresh incoming
/// contract. A healthy federation answers well within this; the bound only
/// decides how quickly an unreachable one fails the HTLC back.
const FEDERATION_LIVENESS_TIMEOUT: Duration = Duration::from_secs(10);

/// Minimum number of blocks between the current height and an incoming HTLC's
/// claim deadline for the gateway to fund its incoming contract.
const LNV2_CLAIM_DEADLINE_MARGIN: u32 = 2;

/// LNv2 CLTV Delta in blocks
pub const EXPIRATION_DELTA_MINIMUM_V2: u64 = 144;

fn incoming_circuit_operation_id(
    receive_operation_id: OperationId,
    circuit: IncomingCircuitKey,
) -> OperationId {
    OperationId::from_encodable(&(
        "gateway-lnv2-incoming-circuit",
        receive_operation_id,
        circuit,
    ))
}

fn is_legacy_completion_for_circuit(
    state: &GatewayClientStateMachinesV2,
    circuit: IncomingCircuitKey,
) -> bool {
    let IncomingCircuitKey {
        incoming_chan_id,
        htlc_id,
    } = circuit;
    matches!(
        state,
        GatewayClientStateMachinesV2::Complete(CompleteStateMachine {
            common,
            ..
        }) if common.incoming_chan_id == incoming_chan_id && common.htlc_id == htlc_id
    )
}

fn legacy_completion_in_states(
    active: &[GatewayClientStateMachinesV2],
    inactive: &[GatewayClientStateMachinesV2],
    circuit: IncomingCircuitKey,
) -> bool {
    active
        .iter()
        .chain(inactive)
        .any(|state| is_legacy_completion_for_circuit(state, circuit))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum IncomingRelayPlan {
    Replay,
    AddCompletion,
    CreateReceiveAndCompletion,
}

fn incoming_relay_plan(
    receive_exists: bool,
    completion_exists: bool,
    legacy_completion_exists: bool,
) -> IncomingRelayPlan {
    if completion_exists || legacy_completion_exists {
        IncomingRelayPlan::Replay
    } else if receive_exists {
        IncomingRelayPlan::AddCompletion
    } else {
        IncomingRelayPlan::CreateReceiveAndCompletion
    }
}

/// Identifies the role of an LNv2 gateway operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GatewayOperationMetaV2 {
    /// Metadata written before operation roles were distinguished.
    Legacy(()),
    /// Metadata written for a role-specific operation.
    Role {
        /// Role used when recovering active operations.
        role: GatewayOperationRoleV2,
    },
}

/// Role of an LNv2 gateway operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayOperationRoleV2 {
    /// An outgoing payment operation.
    Send,
    /// A federation receive operation.
    Receive,
    /// An incoming Lightning circuit completion operation.
    CircuitCompletion,
    /// A federated BOLT12 invoice reservation, which moves no funds.
    Bolt12Reserve,
}

impl GatewayOperationMetaV2 {
    /// Constructs metadata for `role`.
    pub fn role(role: GatewayOperationRoleV2) -> Self {
        Self::Role { role }
    }

    /// Returns whether shutdown must await Lightning circuit completion.
    pub fn waits_for_completion(&self) -> bool {
        matches!(
            self,
            Self::Legacy(())
                | Self::Role {
                    role: GatewayOperationRoleV2::CircuitCompletion
                }
        )
    }
}

#[derive(Debug, Clone)]
pub struct GatewayClientInitV2 {
    pub gateway: Arc<dyn IGatewayClientV2>,
}

impl ModuleInit for GatewayClientInitV2 {
    type Common = LightningCommonInit;

    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(vec![].into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for GatewayClientInitV2 {
    type Module = GatewayClientModuleV2;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(
        &self,
        args: &ClientModuleInitArgs<Self>,
    ) -> Result<Self::Module, ClientModuleError> {
        Ok(GatewayClientModuleV2 {
            federation_id: *args.federation_id(),
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
            module_api: args.module_api().clone(),
            keypair: args
                .module_root_secret()
                .clone()
                .to_secp_key(fedimint_core::secp256k1::SECP256K1),
            gateway: self.gateway.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GatewayClientModuleV2 {
    pub federation_id: FederationId,
    pub cfg: LightningClientConfig,
    pub notifier: ModuleNotifier<GatewayClientStateMachinesV2>,
    pub client_ctx: ClientContext<Self>,
    pub module_api: DynModuleApi,
    pub keypair: Keypair,
    pub gateway: Arc<dyn IGatewayClientV2>,
}

#[derive(Debug, Clone)]
pub struct GatewayClientContextV2 {
    pub module: GatewayClientModuleV2,
    pub decoder: Decoder,
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
    pub gateway: Arc<dyn IGatewayClientV2>,
}

impl Context for GatewayClientContextV2 {
    const KIND: Option<ModuleKind> = Some(fedimint_lnv2_common::KIND);
}

impl ClientModule for GatewayClientModuleV2 {
    type Init = GatewayClientInitV2;
    type Common = LightningModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = GatewayClientContextV2;
    type States = GatewayClientStateMachinesV2;

    fn context(&self) -> Self::ModuleStateMachineContext {
        GatewayClientContextV2 {
            module: self.clone(),
            decoder: self.decoder(),
            tpe_agg_pk: self.cfg.tpe_agg_pk,
            tpe_pks: self.cfg.tpe_pks.clone(),
            gateway: self.gateway.clone(),
        }
    }
    fn input_fee(
        &self,
        amount: &Amounts,
        input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        let fee = self.cfg.fee_consensus.fee(amount.expect_only_bitcoin());

        // Spending a receive backed by a generated preimage costs more.
        let premium = match (input.ensure_v0_ref().ok()?, self.cfg.bolt12.as_ref()) {
            (LightningInputV0::Bolt12Receive(_, unlock), Some(bolt12)) => {
                bolt12.unlock_premium(unlock)
            }
            _ => Amount::ZERO,
        };

        Some(Amounts::new_bitcoin(fee.checked_add(premium)?))
    }

    fn output_fee(
        &self,
        amount: &Amounts,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        self.cfg
            .output_fee(output.ensure_v0_ref().ok()?, amount.expect_only_bitcoin())
            .map(Amounts::new_bitcoin)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum GatewayClientStateMachinesV2 {
    Send(SendStateMachine),
    Receive(ReceiveStateMachine),
    /// Legacy completion state retained to decode and resume combined receive
    /// operations created by older clients.
    Complete(CompleteStateMachine),
    /// Completes one incoming circuit independently of other circuits carrying
    /// the same payment hash and amount.
    CircuitComplete(CircuitCompleteStateMachine),
    /// Funds a federated BOLT12 receive and recovers its preimage.
    Bolt12Receive(bolt12::Bolt12ReceiveStateMachine),
}

impl fmt::Display for GatewayClientStateMachinesV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayClientStateMachinesV2::Send(send) => {
                write!(f, "{send}")
            }
            GatewayClientStateMachinesV2::Receive(receive) => {
                write!(f, "{receive}")
            }
            GatewayClientStateMachinesV2::Complete(complete) => {
                write!(f, "{complete}")
            }
            GatewayClientStateMachinesV2::CircuitComplete(complete) => {
                write!(f, "{complete}")
            }
            GatewayClientStateMachinesV2::Bolt12Receive(receive) => {
                write!(f, "{receive}")
            }
        }
    }
}

impl IntoDynInstance for GatewayClientStateMachinesV2 {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for GatewayClientStateMachinesV2 {
    type ModuleContext = GatewayClientContextV2;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            GatewayClientStateMachinesV2::Send(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesV2::Send
                )
            }
            GatewayClientStateMachinesV2::Receive(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesV2::Receive
                )
            }
            GatewayClientStateMachinesV2::Complete(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesV2::Complete
                )
            }
            GatewayClientStateMachinesV2::CircuitComplete(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesV2::CircuitComplete
                )
            }
            GatewayClientStateMachinesV2::Bolt12Receive(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesV2::Bolt12Receive
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            GatewayClientStateMachinesV2::Send(state) => state.operation_id(),
            GatewayClientStateMachinesV2::Receive(state) => state.operation_id(),
            GatewayClientStateMachinesV2::Complete(state) => state.operation_id(),
            GatewayClientStateMachinesV2::CircuitComplete(state) => state.operation_id(),
            GatewayClientStateMachinesV2::Bolt12Receive(state) => state.operation_id(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable, Encodable)]
pub enum FinalReceiveState {
    Rejected,
    Success([u8; 32]),
    Refunded,
    Failure,
}

impl GatewayClientModuleV2 {
    /// Starts paying the invoice of an LNv2 outgoing contract, or joins the
    /// payment already under way for it, and waits for its outcome.
    ///
    /// The `Ok` value is that outcome: the preimage if the payment succeeded,
    /// or the gateway's forfeit signature, which lets the sender reclaim the
    /// contract, if it was cancelled.
    ///
    /// # Errors
    ///
    /// Fails with a [`GatewaySendPaymentError`] if the request is refused
    /// before any payment starts: the gateway is not connected to its
    /// lightning node, the contract is another gateway's, the
    /// request's signature does not verify, the federation has not confirmed
    /// this contract at that outpoint or cannot be asked, the invoice has no
    /// amount or does not match the contract, the gateway cannot price the
    /// payment, or another contract already claimed the payment image.
    pub async fn send_payment(
        &self,
        payload: SendPaymentPayload,
    ) -> Result<Result<[u8; 32], Signature>, GatewaySendPaymentError> {
        let operation_start = now();

        // The operation id is equal to the contract id which also doubles as the
        // message signed by the gateway via the forfeit signature to forfeit
        // the gateways claim to a contract in case of cancellation. We only create a
        // forfeit signature after we have started the send state machine to
        // prevent replay attacks with a previously cancelled outgoing contract
        let operation_id = OperationId::from_encodable(&payload.contract.clone());

        // Since the following checks may only fail due to client side
        // programming error we do not have to enable cancellation and can check
        // them before we start the state machine.
        if payload.contract.claim_pk != self.keypair.public_key() {
            return Err(GatewaySendPaymentError::NotOurContract);
        }

        // This prevents DOS attacks where an attacker submits a different invoice.
        if secp256k1::SECP256K1
            .verify_schnorr(
                &payload.auth,
                &Message::from_digest(*payload.invoice.consensus_hash::<sha256::Hash>().as_ref()),
                &payload.contract.refund_pk.x_only_public_key().0,
            )
            .is_err()
        {
            return Err(GatewaySendPaymentError::InvalidAuthSignature);
        }

        // The operation id is derived from the contract, which is public in the
        // funding transaction, and joining the operation yields its preimage. So
        // the join belongs behind the signature above.
        if self.client_ctx.operation_exists(operation_id).await {
            return Ok(self.subscribe_send(operation_id).await);
        }

        // A send accepted while the lightning node is unreachable would sit
        // waiting for it, and nothing about the payment is known until then.
        // Refusing up front keeps the sender free to use another gateway. Only
        // new sends are refused: joining an existing operation above resumes
        // one already started.
        if !self.gateway.is_lightning_connected().await {
            return Err(GatewaySendPaymentError::LightningNotConnected);
        }

        // We need to check that the contract has been confirmed by the federation
        // before we start the state machine to prevent DOS attacks.
        let (contract_id, expiration) = self
            .module_api
            .outgoing_contract_expiration(payload.outpoint)
            .await?
            .ok_or(GatewaySendPaymentError::ContractNotConfirmed)?;

        if contract_id != payload.contract.contract_id() {
            return Err(GatewaySendPaymentError::ContractIdMismatch);
        }

        let (payment_hash, amount) = match &payload.invoice {
            LightningInvoice::Bolt11(invoice) => (
                invoice.payment_hash(),
                invoice
                    .amount_milli_satoshis()
                    .ok_or(GatewaySendPaymentError::MissingInvoiceAmount)?,
            ),
        };

        if PaymentImage::Hash(*payment_hash) != payload.contract.payment_image {
            return Err(GatewaySendPaymentError::PaymentHashMismatch);
        }

        let min_contract_amount = self
            .gateway
            .min_contract_amount(&payload.federation_id, amount)
            .await
            .map_err(GatewaySendPaymentError::MinContractAmount)?;

        // Contracts for different invoices, on LNv1 or in other federations, can
        // share a payment image, and paying one pays them all. So only the first
        // operation to claim the image may ever pay it out; the claim is never
        // released. It is taken before the state machine exists, so a refused
        // contract has not been paid for. A retry of this operation finds its own
        // claim.
        //
        // TODO(joschisan): review whether answering with a forfeit signature is
        // safe here, so the sender is refunded immediately instead of at the
        // contract's expiration. It should be: a refused contract can never take
        // the claim later, so we never pay out on it.
        if !self
            .gateway
            .claim_payment_image(&payload.contract.payment_image, operation_id)
            .await
        {
            return Err(GatewaySendPaymentError::PaymentImageAlreadyClaimed);
        }

        let send_sm = GatewayClientStateMachinesV2::Send(SendStateMachine {
            common: SendSMCommon {
                operation_id,
                outpoint: payload.outpoint,
                contract: payload.contract.clone(),
                max_delay: expiration.saturating_sub(EXPIRATION_DELTA_MINIMUM_V2),
                min_contract_amount,
                invoice: payload.invoice,
                claim_keypair: self.keypair,
            },
            state: SendSMState::Sending,
        });

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
        self.client_ctx
            .manual_operation_start_dbtx(
                &mut dbtx.to_ref_nc(),
                operation_id,
                LightningCommonInit::KIND.as_str(),
                GatewayOperationMetaV2::role(GatewayOperationRoleV2::Send),
                vec![self.client_ctx.make_dyn_state(send_sm)],
            )
            .await
            .ok();

        self.client_ctx
            .log_event(
                &mut dbtx,
                OutgoingPaymentStarted {
                    operation_start,
                    outgoing_contract: payload.contract.clone(),
                    min_contract_amount,
                    invoice_amount: Amount::from_msats(amount),
                    max_delay: expiration.saturating_sub(EXPIRATION_DELTA_MINIMUM_V2),
                },
            )
            .await;
        dbtx.commit_tx().await;

        Ok(self.subscribe_send(operation_id).await)
    }

    /// Returns the timelock budget, in blocks, that the outgoing contract at
    /// `outpoint` leaves for a payment dispatched now, retrying until the
    /// federation answers. A contract the federation no longer knows leaves
    /// no budget.
    async fn await_outgoing_contract_max_delay(&self, outpoint: OutPoint) -> u64 {
        let expiration = retry(
            "outgoing contract expiration",
            backoff_util::background_backoff(),
            || self.module_api.outgoing_contract_expiration(outpoint),
        )
        .await
        .expect("Retries until the federation answers");

        expiration.map_or(0, |(_, expiration)| {
            expiration.saturating_sub(EXPIRATION_DELTA_MINIMUM_V2)
        })
    }

    pub async fn subscribe_send(&self, operation_id: OperationId) -> Result<[u8; 32], Signature> {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            if let Some(GatewayClientStateMachinesV2::Send(state)) = stream.next().await {
                match state.state {
                    SendSMState::Sending => {}
                    SendSMState::Claiming(claiming) => {
                        // The preimage is proof the payment succeeded, so return it to
                        // the sender as soon as it is available rather than waiting for
                        // an additional ordering. The gateway's claim of the outgoing
                        // contract has already been submitted by the send state machine
                        // and finalizes in the background.
                        return Ok(claiming.preimage);
                    }
                    SendSMState::Cancelled(cancelled) => {
                        warn!("Outgoing lightning payment is cancelled {:?}", cancelled);

                        let signature = self
                            .keypair
                            .sign_schnorr(state.common.contract.forfeit_message());

                        assert!(state.common.contract.verify_forfeit_signature(&signature));

                        return Err(signature);
                    }
                }
            }
        }
    }

    async fn legacy_completion_exists(
        &self,
        operation_id: OperationId,
        circuit: IncomingCircuitKey,
    ) -> bool {
        let active = self
            .client_ctx
            .get_own_operation_active_states(operation_id)
            .await
            .into_iter()
            .map(|(state, _)| state)
            .collect::<Vec<_>>();
        let inactive = self
            .client_ctx
            .get_own_operation_inactive_states(operation_id)
            .await
            .into_iter()
            .map(|(state, _)| state)
            .collect::<Vec<_>>();

        legacy_completion_in_states(&active, &inactive, circuit)
    }

    /// Refuses to fund a fresh incoming contract unless a threshold of
    /// guardians is answering. LNv1 gets this check implicitly by fetching the
    /// offer from the federation first; LNv2 reads the contract from the
    /// gateway's own database, so it has to probe explicitly.
    async fn ensure_federation_responsive(
        &self,
        payment_hash: sha256::Hash,
    ) -> Result<(), RelayIncomingHtlcError> {
        match timeout(
            FEDERATION_LIVENESS_TIMEOUT,
            self.module_api.consensus_block_count(),
        )
        .await
        {
            Ok(Ok(_consensus_block_count)) => Ok(()),
            Ok(Err(err)) => {
                warn!(
                    %payment_hash,
                    err = %err.fmt_compact(),
                    "Federation liveness probe failed, refusing to fund incoming contract"
                );
                Err(RelayIncomingHtlcError::FederationUnreachable(Box::new(err)))
            }
            Err(_elapsed) => {
                warn!(
                    %payment_hash,
                    timeout_secs = FEDERATION_LIVENESS_TIMEOUT.as_secs(),
                    "Federation liveness probe timed out, refusing to fund incoming contract"
                );
                Err(RelayIncomingHtlcError::FederationTimeout {
                    timeout_secs: FEDERATION_LIVENESS_TIMEOUT.as_secs(),
                })
            }
        }
    }

    /// Plans a relay of `circuit` from the operations persisted so far.
    async fn read_incoming_relay_plan(
        &self,
        receive_operation_id: OperationId,
        completion_operation_id: OperationId,
        circuit: IncomingCircuitKey,
    ) -> IncomingRelayPlan {
        let receive_exists = self.client_ctx.operation_exists(receive_operation_id).await;
        let completion_exists = self
            .client_ctx
            .operation_exists(completion_operation_id)
            .await;
        let legacy_completion_exists = self
            .legacy_completion_exists(receive_operation_id, circuit)
            .await;

        incoming_relay_plan(receive_exists, completion_exists, legacy_completion_exists)
    }

    /// Checks that a fresh incoming contract may be funded and builds the
    /// transaction funding it.
    async fn fresh_receive_funding(
        &self,
        payment_hash: sha256::Hash,
        receive_operation_id: OperationId,
        contract: IncomingContract,
        blocks_to_claim_deadline: u32,
        receive_enabled: bool,
    ) -> Result<TransactionBuilder, RelayIncomingHtlcError> {
        if !receive_enabled {
            return Err(RelayIncomingHtlcError::ReceiveDisabled);
        }

        // Funding is irreversible, and the gateway is only reimbursed by
        // settling the HTLC before its claim deadline, so do not fund an
        // HTLC that is about to expire. The margin is small because LDK's
        // default invoices leave only 3 blocks before the claim deadline.
        if blocks_to_claim_deadline < LNV2_CLAIM_DEADLINE_MARGIN {
            return Err(RelayIncomingHtlcError::ClaimDeadlineTooClose {
                blocks_to_claim_deadline,
            });
        }
        self.ensure_federation_responsive(payment_hash).await?;

        let refund_keypair = self.keypair;
        let client_output = ClientOutput::<LightningOutput> {
            output: LightningOutput::V0(LightningOutputV0::Incoming(contract.clone())),
            amounts: Amounts::new_bitcoin(contract.commitment.amount),
        };
        let client_output_sm = ClientOutputSM::<GatewayClientStateMachinesV2> {
            state_machines: Arc::new(move |range: OutPointRange| {
                assert_eq!(range.count(), 1);

                vec![GatewayClientStateMachinesV2::Receive(ReceiveStateMachine {
                    common: ReceiveSMCommon {
                        operation_id: receive_operation_id,
                        contract: contract.clone(),
                        outpoint: range.into_iter().next().unwrap(),
                        refund_keypair,
                    },
                    state: ReceiveSMState::Funding,
                })]
            }),
        };

        let client_output = self.client_ctx.make_client_outputs(ClientOutputBundle::new(
            vec![client_output],
            vec![client_output_sm],
        ));
        let funding = TransactionBuilder::new().with_outputs(client_output);

        Ok(funding)
    }

    /// Funds the incoming contract of an intercepted LNv2 HTLC and starts the
    /// operation that completes the HTLC's circuit.
    ///
    /// A contract or circuit that is already being handled is joined rather
    /// than started twice.
    ///
    /// # Concurrency
    ///
    /// A relay that refuses to fund a fresh contract reads the persisted
    /// operations again and joins a receive or completion that a concurrent
    /// relay created in the meantime. A concurrent relay can still fund the
    /// contract just after that read, so the caller must not let another relay
    /// of the same circuit that can fund a fresh contract run between this
    /// relay and the decision to fail the HTLC back.
    ///
    /// # Errors
    ///
    /// Fails with a [`RelayIncomingHtlcError`] if a fresh contract is not
    /// funded because the HTLC's claim deadline is too close or the federation
    /// does not answer, or if the funding transaction and the completion
    /// operation could not be started and no earlier attempt had started them.
    /// Only [`RelayIncomingHtlcError::CompletionNotStarted`] and
    /// [`RelayIncomingHtlcError::ReceiveVanished`] can leave a funded contract
    /// behind; see [`RelayIncomingHtlcError::htlc_may_be_failed_back`].
    pub async fn relay_incoming_htlc(
        &self,
        payment_hash: sha256::Hash,
        incoming_chan_id: u64,
        htlc_id: u64,
        contract: IncomingContract,
        amount_msat: u64,
        blocks_to_claim_deadline: u32,
    ) -> Result<(), RelayIncomingHtlcError> {
        self.relay_incoming_htlc_with_policy(
            payment_hash,
            incoming_chan_id,
            htlc_id,
            contract,
            amount_msat,
            blocks_to_claim_deadline,
            true,
        )
        .await
    }

    /// Like [`Self::relay_incoming_htlc`], but enforces `receive_enabled` only
    /// when funding a fresh receive (`IncomingRelayPlan::CreateReceiveAndCompletion`),
    /// never cancelling an already-funded contract on restart redelivery.
    #[allow(clippy::too_many_arguments)]
    pub async fn relay_incoming_htlc_with_policy(
        &self,
        payment_hash: sha256::Hash,
        incoming_chan_id: u64,
        htlc_id: u64,
        contract: IncomingContract,
        amount_msat: u64,
        blocks_to_claim_deadline: u32,
        receive_enabled: bool,
    ) -> Result<(), RelayIncomingHtlcError> {
        let operation_start = now();
        let receive_operation_id = OperationId::from_encodable(&contract);
        let circuit = IncomingCircuitKey {
            incoming_chan_id,
            htlc_id,
        };
        let completion_operation_id = incoming_circuit_operation_id(receive_operation_id, circuit);
        let commitment = contract.commitment.clone();

        let funding = match self
            .read_incoming_relay_plan(receive_operation_id, completion_operation_id, circuit)
            .await
        {
            IncomingRelayPlan::Replay => return Ok(()),
            IncomingRelayPlan::AddCompletion => None,
            IncomingRelayPlan::CreateReceiveAndCompletion => match self
                .fresh_receive_funding(
                    payment_hash,
                    receive_operation_id,
                    contract,
                    blocks_to_claim_deadline,
                    receive_enabled,
                )
                .await
            {
                Ok(funding) => Some(funding),
                // A concurrent relay of this circuit may have funded the
                // contract while these checks ran, and an error would then
                // let the caller fail back an HTLC the gateway has paid for.
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
            Some((operation_start, commitment, amount_msat)),
        )
        .await
    }

    /// Atomically commit optional `funding` transaction (plus optional LNv2
    /// `IncomingPaymentStarted` event) together with `CircuitCompleteStateMachine`
    /// in a single database transaction.
    pub(crate) async fn commit_receive_and_completion(
        &self,
        receive_operation_id: OperationId,
        completion_operation_id: OperationId,
        payment_hash: sha256::Hash,
        circuit: IncomingCircuitKey,
        funding: Option<TransactionBuilder>,
        incoming_event: Option<(
            std::time::SystemTime,
            fedimint_lnv2_common::contracts::Commitment,
            u64,
        )>,
    ) -> Result<(), RelayIncomingHtlcError> {
        let completion =
            self.client_ctx
                .make_dyn_state(GatewayClientStateMachinesV2::CircuitComplete(
                    CircuitCompleteStateMachine {
                        common: CircuitCompleteSMCommon {
                            operation_id: completion_operation_id,
                            receive_operation_id,
                            payment_hash,
                            circuit,
                        },
                        state: CompleteSMState::Pending,
                    },
                ));

        // Funding the incoming contract pays the recipient, and only the
        // completion operation settles the HTLC that reimburses the gateway.
        // Both are committed in one transaction: a relay that stops anywhere
        // (a crash, a power loss) leaves either both or neither, and an
        // error means neither was written by this call.
        let result = self
            .client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    let funding = funding.clone();
                    let completion = completion.clone();
                    let incoming_event = incoming_event.clone();
                    Box::pin(async move {
                        // The receive is found by its state machines, as the
                        // plan found it. A concurrent relay of another circuit
                        // for the same contract may have funded it since the
                        // plan was made; its receive is joined rather than
                        // funded twice.
                        if !self
                            .client_ctx
                            .operation_exists_dbtx(dbtx, receive_operation_id)
                            .await
                        {
                            // State machines are never removed, so only a
                            // fresh receive plan finds none.
                            let Some(funding) = funding else {
                                return Err(RelayIncomingHtlcError::ReceiveVanished);
                            };

                            // An operation log entry without state machines
                            // funds nothing, and its operation id cannot be
                            // used to fund the contract.
                            if self
                                .client_ctx
                                .get_operation_dbtx(dbtx, receive_operation_id)
                                .await
                                .is_some()
                            {
                                return Err(TransactionSubmitError::from(
                                    OperationAlreadyExistsError {
                                        operation_id: receive_operation_id,
                                    },
                                )
                                .into());
                            }

                            self.client_ctx
                                .finalize_and_submit_transaction_dbtx(
                                    dbtx,
                                    receive_operation_id,
                                    LightningCommonInit::KIND.as_str(),
                                    |_| {
                                        GatewayOperationMetaV2::role(
                                            GatewayOperationRoleV2::Receive,
                                        )
                                    },
                                    funding,
                                )
                                .await?;

                            if let Some((operation_start, commitment, amount_msat)) = incoming_event
                            {
                                self.client_ctx
                                    .log_event(
                                        dbtx,
                                        IncomingPaymentStarted {
                                            operation_start,
                                            incoming_contract_commitment: commitment,
                                            invoice_amount: Amount::from_msats(amount_msat),
                                        },
                                    )
                                    .await;
                            }
                        }

                        self.client_ctx
                            .manual_operation_start_dbtx(
                                dbtx,
                                completion_operation_id,
                                LightningCommonInit::KIND.as_str(),
                                GatewayOperationMetaV2::role(
                                    GatewayOperationRoleV2::CircuitCompletion,
                                ),
                                vec![completion],
                            )
                            .await
                            .map_err(TransactionSubmitError::from)?;

                        Ok::<_, RelayIncomingHtlcError>(())
                    })
                },
                Some(100),
            )
            .await;

        let error = match result {
            Ok(()) => return Ok(()),
            Err(AutocommitError::ClosureError { error, .. }) => error,
            Err(AutocommitError::CommitFailed { last_error, .. }) => {
                TransactionSubmitError::Database(last_error).into()
            }
        };

        // Nothing was written by this call, but a concurrent relay of this
        // circuit may have started its completion, or one of another circuit
        // of this contract may have funded it.
        if self
            .client_ctx
            .operation_exists(completion_operation_id)
            .await
        {
            return Ok(());
        }

        match error {
            RelayIncomingHtlcError::Transaction(error)
                if self.client_ctx.operation_exists(receive_operation_id).await =>
            {
                Err(RelayIncomingHtlcError::CompletionNotStarted(error))
            }
            error => Err(error),
        }
    }

    /// Funds the incoming contract of a direct swap and waits for its final
    /// state.
    ///
    /// A swap that was already started resumes unconditionally: its operation
    /// is keyed on the contract, so a re-entrant call — a restarted state
    /// machine, or a concurrent payer — joins the operation in progress
    /// instead of funding twice. `allow_fresh_dispatch` is consulted only
    /// when no such operation exists: callers pass `false` when a wall-clock
    /// gate such as invoice expiry forbids starting a new swap, and receive
    /// `Ok(None)` to signal that nothing was started.
    ///
    /// # Errors
    ///
    /// Fails with a [`TransactionSubmitError`] if the funding transaction of a
    /// fresh swap could not be submitted.
    pub async fn relay_direct_swap(
        &self,
        contract: IncomingContract,
        amount_msat: u64,
        allow_fresh_dispatch: bool,
    ) -> Result<Option<FinalReceiveState>, TransactionSubmitError> {
        let operation_start = now();

        let operation_id = OperationId::from_encodable(&contract);

        if self.client_ctx.operation_exists(operation_id).await {
            return Ok(Some(self.await_receive(operation_id).await));
        }

        if !allow_fresh_dispatch {
            return Ok(None);
        }

        let refund_keypair = self.keypair;

        let client_output = ClientOutput::<LightningOutput> {
            output: LightningOutput::V0(LightningOutputV0::Incoming(contract.clone())),
            amounts: Amounts::new_bitcoin(contract.commitment.amount),
        };
        let commitment = contract.commitment.clone();
        let client_output_sm = ClientOutputSM::<GatewayClientStateMachinesV2> {
            state_machines: Arc::new(move |range| {
                assert_eq!(range.count(), 1);

                vec![GatewayClientStateMachinesV2::Receive(ReceiveStateMachine {
                    common: ReceiveSMCommon {
                        operation_id,
                        contract: contract.clone(),
                        outpoint: range.into_iter().next().unwrap(),
                        refund_keypair,
                    },
                    state: ReceiveSMState::Funding,
                })]
            }),
        };

        let client_output = self.client_ctx.make_client_outputs(ClientOutputBundle::new(
            vec![client_output],
            vec![client_output_sm],
        ));

        let transaction = TransactionBuilder::new().with_outputs(client_output);

        self.client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                LightningCommonInit::KIND.as_str(),
                |_| GatewayOperationMetaV2::role(GatewayOperationRoleV2::Receive),
                transaction,
            )
            .await?;

        let mut dbtx = self.client_ctx.module_db().begin_transaction().await;
        self.client_ctx
            .log_event(
                &mut dbtx,
                IncomingPaymentStarted {
                    operation_start,
                    incoming_contract_commitment: commitment,
                    invoice_amount: Amount::from_msats(amount_msat),
                },
            )
            .await;
        dbtx.commit_tx().await;

        Ok(Some(self.await_receive(operation_id).await))
    }

    pub async fn await_receive(&self, operation_id: OperationId) -> FinalReceiveState {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            // A federated BOLT12 receive ends in the same outcomes as an
            // incoming contract, so both are read as one kind of state.
            let state = match stream.next().await {
                Some(GatewayClientStateMachinesV2::Receive(state)) => state.state,
                Some(GatewayClientStateMachinesV2::Bolt12Receive(state)) => match state.state {
                    Bolt12ReceiveSMState::Funding => ReceiveSMState::Funding,
                    Bolt12ReceiveSMState::Rejected(error) => ReceiveSMState::Rejected(error),
                    Bolt12ReceiveSMState::Success(preimage) => ReceiveSMState::Success(preimage),
                    Bolt12ReceiveSMState::Failure => ReceiveSMState::Failure,
                    Bolt12ReceiveSMState::Refunding(out_points) => {
                        ReceiveSMState::Refunding(out_points)
                    }
                },
                _ => continue,
            };

            {
                match state {
                    ReceiveSMState::Funding => {}
                    ReceiveSMState::Rejected(..) => return FinalReceiveState::Rejected,
                    ReceiveSMState::Success(preimage) => {
                        return FinalReceiveState::Success(preimage);
                    }
                    ReceiveSMState::Refunding(out_points) => {
                        if self
                            .client_ctx
                            .await_primary_module_outputs(operation_id, out_points)
                            .await
                            .is_err()
                        {
                            return FinalReceiveState::Failure;
                        }

                        return FinalReceiveState::Refunded;
                    }
                    ReceiveSMState::Failure => return FinalReceiveState::Failure,
                }
            }
        }
    }

    /// Waits for a legacy combined receive operation or a circuit-completion
    /// operation to finish.
    ///
    /// `operation_id` must identify either a legacy operation containing
    /// [`GatewayClientStateMachinesV2::Complete`] or a role-specific operation
    /// containing [`GatewayClientStateMachinesV2::CircuitComplete`]. Both
    /// successful completion and a durable permanent outcome conflict terminate
    /// the wait.
    pub async fn await_completion(&self, operation_id: OperationId) {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            match stream.next().await {
                Some(GatewayClientStateMachinesV2::Complete(state)) => {
                    if matches!(
                        state.state,
                        CompleteSMState::Completed | CompleteSMState::CompletionFailed(_)
                    ) {
                        info!(%state, "LNv2 completion state machine finished");
                        return;
                    }

                    info!(%state, "Waiting for LNv2 completion state machine");
                }
                Some(GatewayClientStateMachinesV2::Receive(state)) => {
                    info!(%state, "Waiting for LNv2 completion state machine");
                    continue;
                }
                Some(GatewayClientStateMachinesV2::CircuitComplete(state)) => {
                    if matches!(
                        state.state,
                        CompleteSMState::Completed | CompleteSMState::CompletionFailed(_)
                    ) {
                        info!(%state, "LNv2 circuit completion state machine finished");
                        return;
                    }

                    info!(%state, "Waiting for LNv2 circuit completion state machine");
                }
                Some(state) => {
                    warn!(%state, "Operation is not an LNv2 completion state machine");
                    return;
                }
                None => return,
            }
        }
    }
}

/// A refusal to pay an invoice for an LNv2 client.
///
/// These are the checks the gateway makes before it starts paying. A payment
/// that starts and is later cancelled is not a failure: it is reported as the
/// forfeit signature in the `Ok` value.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GatewaySendPaymentError {
    /// The gateway is not connected to its lightning node, so a new send
    /// would sit waiting for it.
    #[error("The gateway is not connected to its lightning node")]
    LightningNotConnected,

    /// The outgoing contract names another gateway's key, so this gateway
    /// could never claim it.
    #[error("The outgoing contract is keyed to another gateway")]
    NotOurContract,

    /// The request's signature over the invoice does not verify against the
    /// contract's refund key.
    #[error("Invalid auth signature for the invoice data")]
    InvalidAuthSignature,

    /// The federation could not be asked about the outgoing contract.
    #[error("The gateway can not reach the federation")]
    Federation(#[source] Box<FederationError>),

    /// The federation has not confirmed the outgoing contract yet.
    #[error("The outgoing contract has not yet been confirmed")]
    ContractNotConfirmed,

    /// The contract the federation confirmed at the request's outpoint is not
    /// the one in the request.
    #[error("Contract Id returned by the federation does not match contract in request")]
    ContractIdMismatch,

    /// The invoice carries no amount.
    #[error("Invoice is missing amount")]
    MissingInvoiceAmount,

    /// The invoice's payment hash is not the one the contract is locked to.
    #[error("The invoices payment hash does not match the contracts payment hash")]
    PaymentHashMismatch,

    /// The gateway could not work out the smallest contract amount it accepts
    /// for this payment.
    #[error("The minimum contract amount could not be computed")]
    MinContractAmount(#[source] GatewayClientV2Error),

    /// Another operation already claimed the contract's payment image, so this
    /// gateway will never pay it out for this contract.
    #[error("Another contract for this payment image was already accepted")]
    PaymentImageAlreadyClaimed,
}

/// Why the gateway did not relay an intercepted LNv2 HTLC.
#[derive(Debug, Error)]
pub enum RelayIncomingHtlcError {
    /// The federation liveness probe failed, so a fresh incoming contract is
    /// not funded.
    #[error("The federation did not answer the liveness probe")]
    FederationUnreachable(#[source] Box<FederationError>),

    /// The federation liveness probe did not complete in time, so a fresh
    /// incoming contract is not funded.
    #[error("The federation did not answer the liveness probe within {timeout_secs}s")]
    FederationTimeout {
        /// How long the probe waited.
        timeout_secs: u64,
    },

    /// The HTLC's claim deadline is too close to fund a fresh incoming
    /// contract and still settle the HTLC in time.
    #[error("HTLC claim deadline is only {blocks_to_claim_deadline} blocks away")]
    ClaimDeadlineTooClose {
        /// Blocks left until the HTLC's claim deadline.
        blocks_to_claim_deadline: u32,
    },

    /// The funding transaction and the completion operation could not be
    /// started, so nothing was funded.
    #[error("The incoming contract could not be funded")]
    Transaction(#[from] TransactionSubmitError),

    /// The incoming contract is funded, but the operation that settles the
    /// HTLC could not be started. The HTLC must stay held: failing it back
    /// would leave the gateway having paid the recipient without being
    /// reimbursed. Relaying it again adds the missing operation once the
    /// cause has cleared, and fails again while it persists.
    #[error("The incoming contract is funded but its HTLC completion could not be started")]
    CompletionNotStarted(#[source] TransactionSubmitError),

    /// The relay found the receive operation that funds the incoming contract
    /// when it planned, but not when it came to start the operation that
    /// settles the HTLC, so it wrote nothing. State machines are never
    /// removed, so this should not happen; as the contract may be funded, the
    /// HTLC must stay held.
    #[error("The incoming contract's receive operation disappeared during the relay")]
    ReceiveVanished,

    /// The held payment's amount is not the amount of the federated BOLT12
    /// invoice it pays, so funding the recipient would not be covered.
    #[error("Held {received_msat} msat for a BOLT12 invoice over {expected_msat} msat")]
    Bolt12AmountMismatch {
        /// The invoice amount.
        expected_msat: u64,
        /// The amount the Lightning node holds.
        received_msat: u64,
    },

    /// Receives are disabled for this federation, so a fresh incoming contract
    /// is not funded. Already-funded receives are never rejected with this
    /// error.
    #[error("Receives are disabled for this federation")]
    ReceiveDisabled,
}

impl RelayIncomingHtlcError {
    /// Whether the HTLC may be failed back after this error.
    ///
    /// This is `false` once the incoming contract is or may be funded, as the
    /// recipient can then claim it and the gateway is reimbursed only by
    /// settling the HTLC. A `true` answer holds only while no other relay
    /// of the same circuit can fund the contract before the HTLC is failed
    /// back; see the caller's obligations on
    /// [`GatewayClientModuleV2::relay_incoming_htlc`].
    pub fn htlc_may_be_failed_back(&self) -> bool {
        !matches!(self, Self::CompletionNotStarted(_) | Self::ReceiveVanished)
    }
}

impl From<FederationError> for GatewaySendPaymentError {
    fn from(source: FederationError) -> Self {
        Self::Federation(Box::new(source))
    }
}

/// An interface between module implementation and the general `Gateway`
///
/// To abstract away and decouple the core gateway from the modules, the
/// interface between the is expressed as a trait. The core gateway handles
/// LNv2 operations that require access to the database or lightning node.
#[async_trait]
pub trait IGatewayClientV2: Debug + Send + Sync {
    /// Uses the gateway's Lightning node to complete a payment.
    ///
    /// Implementations must absorb and retry every transient node or
    /// connectivity failure. They return `Err` only when Lightning has reached
    /// a permanent state that makes the requested outcome impossible. The
    /// future may block while retrying and must remain cancellation-safe.
    /// Completion state machines persist any returned error as terminal
    /// `CompletionFailed`.
    async fn complete_htlc(
        &self,
        htlc_response: InterceptPaymentResponse,
    ) -> Result<(), LightningRpcError>;

    /// Determines if the payment can be completed using a direct swap to
    /// another federation.
    ///
    /// A direct swap is determined by checking the gateway's connected
    /// lightning node against the invoice's payee lightning node. If they
    /// are the same, then the gateway can use another client to complete
    /// the payment be swapping ecash instead of a payment over the
    /// Lightning network.
    ///
    /// # Errors
    ///
    /// Fails with a [`GatewayClientV2Error`] if the invoice is payable by a
    /// direct swap but the gateway holds no incoming contract it can use for
    /// it. The send state machine cancels the payment on a failure.
    async fn is_direct_swap(
        &self,
        invoice: &Bolt11Invoice,
    ) -> Result<Option<(IncomingContract, ClientHandleArc)>, GatewayClientV2Error>;

    /// Initiates a payment over the Lightning network.
    async fn pay(
        &self,
        invoice: Bolt11Invoice,
        max_delay: u64,
        max_fee: Amount,
    ) -> Result<[u8; 32], LightningRpcError>;

    /// Returns whether the gateway's Lightning node has any record of an
    /// outbound payment for `payment_hash`, whatever its state.
    ///
    /// The send state machine consults this when it resumes after a restart:
    /// a payment the node already knows was dispatched before the crash and
    /// must be resolved through [`IGatewayClientV2::pay`]'s idempotent resume
    /// path rather than cancelled by pre-dispatch checks. A wrong `false`
    /// forfeits a contract whose payment may still settle, so implementations
    /// must absorb transient node failures and only answer once the node's
    /// payment store could actually be consulted.
    async fn outbound_payment_exists(&self, payment_hash: sha256::Hash) -> bool;

    /// Computes the minimum contract amount necessary for making an outgoing
    /// payment.
    ///
    /// The minimum contract amount must contain transaction fees to cover the
    /// gateway's transaction fee and optionally additional fee to cover the
    /// gateway's Lightning fee if the payment goes over the Lightning
    /// network.
    ///
    /// # Errors
    ///
    /// Fails with a [`GatewayClientV2Error`] if the gateway cannot price a
    /// payment for this federation.
    async fn min_contract_amount(
        &self,
        federation_id: &FederationId,
        amount: u64,
    ) -> Result<Amount, GatewayClientV2Error>;

    /// Check if this invoice was created using LNv1 and if the gateway is
    /// connected to the target federation.
    async fn is_lnv1_invoice(&self, invoice: &Bolt11Invoice) -> Option<Spanned<ClientHandleArc>>;

    /// Perform a swap from an LNv2 `OutgoingContract` to an LNv1
    /// `IncomingContract`.
    ///
    /// A swap that was already started resumes unconditionally;
    /// `allow_fresh_dispatch` is consulted only when no operation for this
    /// swap exists yet. Callers pass `false` when a wall-clock gate such as
    /// invoice expiry forbids starting a new swap, and receive `Ok(None)` to
    /// signal that nothing was started.
    ///
    /// # Errors
    ///
    /// Fails with a [`GatewayClientV2Error`] if the swap could not be started
    /// or followed. The send state machine cancels the payment on a failure.
    async fn relay_lnv1_swap(
        &self,
        client: &ClientHandleArc,
        invoice: &Bolt11Invoice,
        allow_fresh_dispatch: bool,
    ) -> Result<Option<FinalReceiveState>, GatewayClientV2Error>;

    /// Claims the given payment image for `operation_id` in the gateway's
    /// global database, returning `true` if this operation may claim the
    /// outgoing contract (the image was unclaimed, or already claimed by
    /// this same operation) and `false` if another operation already
    /// claimed it.
    ///
    /// A single Lightning payment yields a single preimage, so the gateway may
    /// claim at most one outgoing contract per payment image. Unlike the
    /// per-federation module database, this spans all of the gateway's
    /// federations, so two clients in different federations paying the same
    /// invoice cannot both be claimed.
    async fn claim_payment_image(
        &self,
        payment_image: &PaymentImage,
        operation_id: OperationId,
    ) -> bool;

    /// Returns whether the gateway currently holds a connection to its
    /// lightning node. Only suitable for refusing new work: the answer is
    /// local, so it must not decide the fate of a payment already started.
    async fn is_lightning_connected(&self) -> bool;

    /// Waits until the gateway holds a connection to its lightning node.
    async fn await_lightning_connected(&self);
}

/// A failure reported by the gateway behind [`IGatewayClientV2`].
///
/// The trait is implemented by the gateway, not by this module, so the causes
/// are the gateway's own. This type carries them unchanged: its `Display` and
/// its `source()` are the cause's.
#[derive(Debug, Error)]
#[error(transparent)]
pub struct GatewayClientV2Error(Box<dyn std::error::Error + Send + Sync>);

impl GatewayClientV2Error {
    /// Wraps a failure of the gateway's [`IGatewayClientV2`] implementation,
    /// which may be any error value or a plain message.
    pub fn new<E>(source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self(source.into())
    }
}

#[cfg(test)]
mod tests;
