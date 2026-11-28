#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

//! Gateway client module for servicing federated BOLT12 offline receives.

mod api;
pub mod complete_sm;
pub mod events;
pub mod receive;
pub mod receive_sm;
pub mod signing;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use api::GatewayBolt12FederationApi;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::{Keypair, SECP256K1};
pub use complete_sm::IncomingCircuitKey;
use complete_sm::{CircuitCompleteSMCommon, CircuitCompleteStateMachine, CompleteSMState};
use fedimint_api_client::api::{DynModuleApi, FederationError};
use fedimint_bolt12_common::config::Bolt12ClientConfig;
use fedimint_bolt12_common::{Bolt12CommonInit, Bolt12InputV0, Bolt12ModuleTypes, KIND};
use fedimint_client_module::error::OperationAlreadyExistsError;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule, IClientModule};
use fedimint_client_module::sm::{Context, DynState, ModuleNotifier, State, StateTransition};
use fedimint_client_module::transaction::TransactionBuilder;
use fedimint_client_module::{
    ClientModuleError, DynGlobalClientContext, TransactionSubmitError, sm_enum_variant_translation,
};
use fedimint_core::config::FederationId;
use fedimint_core::core::{Decoder, IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{AutocommitError, DatabaseTransaction};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::timeout;
use fedimint_core::util::FmtCompact as _;
use fedimint_core::{apply, async_trait_maybe_send};
use fedimint_lightning::{InterceptPaymentResponse, LightningRpcError};
use futures::StreamExt as _;
use receive_sm::Bolt12ReceiveSMState;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tpe::{AggregatePublicKey, PublicKeyShare};
use tracing::{info, warn};

const FEDERATION_LIVENESS_TIMEOUT: Duration = Duration::from_secs(10);

fn incoming_circuit_operation_id(
    receive_operation_id: OperationId,
    circuit: IncomingCircuitKey,
) -> OperationId {
    OperationId::from_encodable(&(
        "gateway-bolt12-incoming-circuit",
        receive_operation_id,
        circuit,
    ))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum IncomingRelayPlan {
    Replay,
    AddCompletion,
    CreateReceiveAndCompletion,
}

fn incoming_relay_plan(receive_exists: bool, completion_exists: bool) -> IncomingRelayPlan {
    if completion_exists {
        IncomingRelayPlan::Replay
    } else if receive_exists {
        IncomingRelayPlan::AddCompletion
    } else {
        IncomingRelayPlan::CreateReceiveAndCompletion
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub enum GatewayOperationRoleBolt12 {
    Reserve,
    Receive,
    CircuitComplete,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayOperationMetaBolt12 {
    pub role: GatewayOperationRoleBolt12,
}

impl GatewayOperationMetaBolt12 {
    pub fn role(role: GatewayOperationRoleBolt12) -> Self {
        Self { role }
    }
}

/// Callback interface from the BOLT12 gateway client module back into the
/// gateway server's Lightning node.
#[apply(async_trait_maybe_send!)]
pub trait IGatewayClientBolt12: std::fmt::Debug + Send + Sync {
    async fn complete_htlc(
        &self,
        htlc_response: InterceptPaymentResponse,
    ) -> Result<(), LightningRpcError>;
}

#[derive(Debug, Clone)]
pub struct GatewayClientInitBolt12 {
    pub gateway: Arc<dyn IGatewayClientBolt12>,
}

impl ModuleInit for GatewayClientInitBolt12 {
    type Common = Bolt12CommonInit;

    #[allow(clippy::unused_async_trait_impl)]
    async fn dump_database(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(std::iter::empty())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for GatewayClientInitBolt12 {
    type Module = GatewayClientModuleBolt12;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(
        &self,
        args: &ClientModuleInitArgs<Self>,
    ) -> Result<Self::Module, ClientModuleError> {
        Ok(GatewayClientModuleBolt12 {
            federation_id: *args.federation_id(),
            cfg: args.cfg().clone(),
            notifier: args.notifier().clone(),
            client_ctx: args.context(),
            module_api: args.module_api().clone(),
            keypair: args.module_root_secret().clone().to_secp_key(SECP256K1),
            gateway: self.gateway.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct GatewayClientModuleBolt12 {
    pub federation_id: FederationId,
    pub cfg: Bolt12ClientConfig,
    pub notifier: ModuleNotifier<GatewayClientStateMachinesBolt12>,
    pub client_ctx: ClientContext<Self>,
    pub module_api: DynModuleApi,
    pub keypair: Keypair,
    pub gateway: Arc<dyn IGatewayClientBolt12>,
}

#[derive(Debug, Clone)]
pub struct GatewayClientContextBolt12 {
    pub module: GatewayClientModuleBolt12,
    pub decoder: Decoder,
    pub tpe_agg_pk: AggregatePublicKey,
    pub tpe_pks: BTreeMap<fedimint_core::PeerId, PublicKeyShare>,
    pub gateway: Arc<dyn IGatewayClientBolt12>,
}

impl Context for GatewayClientContextBolt12 {
    const KIND: Option<ModuleKind> = Some(KIND);
}

impl ClientModule for GatewayClientModuleBolt12 {
    type Init = GatewayClientInitBolt12;
    type Common = Bolt12ModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = GatewayClientContextBolt12;
    type States = GatewayClientStateMachinesBolt12;

    fn context(&self) -> Self::ModuleStateMachineContext {
        GatewayClientContextBolt12 {
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
        let Bolt12InputV0::Receive(_, unlock) = input.ensure_v0_ref().ok()?;
        let premium = self.cfg.bolt12.unlock_premium(unlock);
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

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum GatewayClientStateMachinesBolt12 {
    CircuitComplete(CircuitCompleteStateMachine),
    Bolt12Receive(receive_sm::Bolt12ReceiveStateMachine),
}

impl fmt::Display for GatewayClientStateMachinesBolt12 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayClientStateMachinesBolt12::CircuitComplete(complete) => write!(f, "{complete}"),
            GatewayClientStateMachinesBolt12::Bolt12Receive(receive) => write!(f, "{receive}"),
        }
    }
}

impl IntoDynInstance for GatewayClientStateMachinesBolt12 {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for GatewayClientStateMachinesBolt12 {
    type ModuleContext = GatewayClientContextBolt12;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match self {
            GatewayClientStateMachinesBolt12::CircuitComplete(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesBolt12::CircuitComplete
                )
            }
            GatewayClientStateMachinesBolt12::Bolt12Receive(state) => {
                sm_enum_variant_translation!(
                    state.transitions(context, global_context),
                    GatewayClientStateMachinesBolt12::Bolt12Receive
                )
            }
        }
    }

    fn operation_id(&self) -> OperationId {
        match self {
            GatewayClientStateMachinesBolt12::CircuitComplete(state) => state.operation_id(),
            GatewayClientStateMachinesBolt12::Bolt12Receive(state) => state.operation_id(),
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

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RelayIncomingHtlcError {
    #[error("Receives are disabled for this federation")]
    ReceiveDisabled,

    #[error(
        "Held amount ({received_msat} msat) differs from BOLT12 invoice ({expected_msat} msat)"
    )]
    Bolt12AmountMismatch {
        expected_msat: u64,
        received_msat: u64,
    },

    #[error("HTLC claim deadline is too close ({blocks_to_claim_deadline} blocks left)")]
    ClaimDeadlineTooClose { blocks_to_claim_deadline: u32 },

    #[error("Federation liveness probe failed: {0}")]
    FederationUnreachable(#[source] Box<FederationError>),

    #[error("Federation liveness probe timed out after {timeout_secs}s")]
    FederationTimeout { timeout_secs: u64 },

    #[error("Receive operation vanished before completion could be attached")]
    ReceiveVanished,

    #[error("Failed to submit receive funding transaction: {0}")]
    TransactionSubmit(#[from] TransactionSubmitError),

    #[error("Failed to attach circuit completion operation: {0}")]
    CompletionAttach(#[source] anyhow::Error),
}

impl RelayIncomingHtlcError {
    /// Whether the held HTLC may safely be failed back to the Lightning node.
    ///
    /// Returns `false` if the federation receive contract may already have been
    /// funded (so failing the HTLC could lose funds).
    pub fn htlc_may_be_failed_back(&self) -> bool {
        !matches!(self, Self::CompletionAttach(_) | Self::ReceiveVanished)
    }
}

impl GatewayClientModuleBolt12 {
    async fn ensure_federation_responsive(
        &self,
        payment_hash: sha256::Hash,
    ) -> Result<(), RelayIncomingHtlcError> {
        match timeout(
            FEDERATION_LIVENESS_TIMEOUT,
            self.module_api
                .bolt12_gateway_approved(self.keypair.public_key()),
        )
        .await
        {
            Ok(Ok(_approved)) => Ok(()),
            Ok(Err(err)) => {
                warn!(
                    %payment_hash,
                    err = %err.fmt_compact(),
                    "Federation liveness probe failed, refusing to fund BOLT12 receive"
                );
                Err(RelayIncomingHtlcError::FederationUnreachable(Box::new(err)))
            }
            Err(_elapsed) => {
                warn!(
                    %payment_hash,
                    timeout_secs = FEDERATION_LIVENESS_TIMEOUT.as_secs(),
                    "Federation liveness probe timed out, refusing to fund BOLT12 receive"
                );
                Err(RelayIncomingHtlcError::FederationTimeout {
                    timeout_secs: FEDERATION_LIVENESS_TIMEOUT.as_secs(),
                })
            }
        }
    }

    async fn read_incoming_relay_plan(
        &self,
        receive_operation_id: OperationId,
        completion_operation_id: OperationId,
    ) -> IncomingRelayPlan {
        let receive_exists = self.client_ctx.operation_exists(receive_operation_id).await;
        let completion_exists = self
            .client_ctx
            .operation_exists(completion_operation_id)
            .await;

        incoming_relay_plan(receive_exists, completion_exists)
    }

    pub(crate) async fn commit_receive_and_completion(
        &self,
        receive_operation_id: OperationId,
        completion_operation_id: OperationId,
        payment_hash: sha256::Hash,
        circuit: IncomingCircuitKey,
        funding: Option<TransactionBuilder>,
    ) -> Result<(), RelayIncomingHtlcError> {
        let completion =
            self.client_ctx
                .make_dyn_state(GatewayClientStateMachinesBolt12::CircuitComplete(
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

        let result = self
            .client_ctx
            .module_db()
            .autocommit(
                |dbtx, _| {
                    let funding = funding.clone();
                    let completion = completion.clone();
                    Box::pin(async move {
                        if !self
                            .client_ctx
                            .operation_exists_dbtx(dbtx, receive_operation_id)
                            .await
                        {
                            let Some(funding) = funding else {
                                return Err(RelayIncomingHtlcError::ReceiveVanished);
                            };

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
                                    Bolt12CommonInit::KIND.as_str(),
                                    |_| {
                                        GatewayOperationMetaBolt12::role(
                                            GatewayOperationRoleBolt12::Receive,
                                        )
                                    },
                                    funding,
                                )
                                .await?;
                        }

                        if !self
                            .client_ctx
                            .operation_exists_dbtx(dbtx, completion_operation_id)
                            .await
                        {
                            self.client_ctx
                                .add_state_machines_dbtx(dbtx, vec![completion])
                                .await
                                .map_err(|err| {
                                    RelayIncomingHtlcError::CompletionAttach(anyhow::anyhow!(
                                        "{err:?}"
                                    ))
                                })?;

                            self.client_ctx
                                .add_operation_log_entry_dbtx(
                                    dbtx,
                                    completion_operation_id,
                                    Bolt12CommonInit::KIND.as_str(),
                                    GatewayOperationMetaBolt12::role(
                                        GatewayOperationRoleBolt12::CircuitComplete,
                                    ),
                                )
                                .await;
                        }

                        Ok(())
                    })
                },
                None,
            )
            .await;

        match result {
            Ok(()) => Ok(()),
            Err(AutocommitError::ClosureError { error, .. }) => Err(error),
            Err(AutocommitError::CommitFailed { last_error, .. }) => {
                Err(RelayIncomingHtlcError::CompletionAttach(last_error.into()))
            }
        }
    }

    pub async fn await_receive(&self, operation_id: OperationId) -> FinalReceiveState {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            let Some(GatewayClientStateMachinesBolt12::Bolt12Receive(state)) = stream.next().await
            else {
                continue;
            };

            match state.state {
                Bolt12ReceiveSMState::Funding => {}
                Bolt12ReceiveSMState::Rejected(..) => return FinalReceiveState::Rejected,
                Bolt12ReceiveSMState::Success(preimage) => {
                    return FinalReceiveState::Success(preimage);
                }
                Bolt12ReceiveSMState::Refunding(out_points) => {
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
                Bolt12ReceiveSMState::Failure => return FinalReceiveState::Failure,
            }
        }
    }

    pub async fn await_completion(&self, operation_id: OperationId) {
        let mut stream = self.notifier.subscribe(operation_id).await;

        loop {
            match stream.next().await {
                Some(GatewayClientStateMachinesBolt12::CircuitComplete(state)) => {
                    if matches!(
                        state.state,
                        CompleteSMState::Completed | CompleteSMState::CompletionFailed(_)
                    ) {
                        info!(%state, "BOLT12 circuit completion state machine finished");
                        return;
                    }
                    info!(%state, "Waiting for BOLT12 circuit completion state machine");
                }
                Some(GatewayClientStateMachinesBolt12::Bolt12Receive(_)) => {}
                None => return,
            }
        }
    }
}
