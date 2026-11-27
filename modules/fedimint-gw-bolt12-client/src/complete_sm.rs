use std::fmt;

use bitcoin::hashes::sha256;
use fedimint_client::DynGlobalClientContext;
use fedimint_client_module::sm::{State, StateTransition};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_lightning::{InterceptPaymentResponse, LightningRpcError, PaymentAction, Preimage};

use crate::events::CompleteLightningPaymentSucceeded;
use crate::{FinalReceiveState, GatewayClientContextBolt12};

/// Identifies one incoming Lightning circuit on the gateway's Lightning node.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct IncomingCircuitKey {
    pub incoming_chan_id: u64,
    pub htlc_id: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct CircuitCompleteSMCommon {
    pub operation_id: OperationId,
    pub receive_operation_id: OperationId,
    pub payment_hash: sha256::Hash,
    pub circuit: IncomingCircuitKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum CompleteSMState {
    Pending,
    Completing(FinalReceiveState),
    Completed,
    CompletionFailed(String),
}

impl fmt::Display for CompleteSMState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompleteSMState::Pending => write!(f, "Pending"),
            CompleteSMState::Completing(_) => write!(f, "Completing"),
            CompleteSMState::Completed => write!(f, "Completed"),
            CompleteSMState::CompletionFailed(_) => write!(f, "Completion Failed"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct CircuitCompleteStateMachine {
    pub common: CircuitCompleteSMCommon,
    pub state: CompleteSMState,
}

impl fmt::Display for CircuitCompleteStateMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BOLT12 Circuit Complete SM Operation ID: {:?} State: {}",
            self.common.operation_id, self.state
        )
    }
}

impl CircuitCompleteStateMachine {
    fn update(&self, state: CompleteSMState) -> Self {
        Self {
            common: self.common.clone(),
            state,
        }
    }
}

impl State for CircuitCompleteStateMachine {
    type ModuleContext = GatewayClientContextBolt12;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gateway_context = context.clone();
        match &self.state {
            CompleteSMState::Pending => vec![StateTransition::new(
                await_receive(context.clone(), self.common.receive_operation_id),
                |_, result, old_state: CircuitCompleteStateMachine| {
                    Box::pin(async move { old_state.update(CompleteSMState::Completing(result)) })
                },
            )],
            CompleteSMState::Completing(final_receive_state) => vec![StateTransition::new(
                complete_circuit(
                    gateway_context.clone(),
                    self.common.payment_hash,
                    final_receive_state.clone(),
                    self.common.circuit,
                ),
                move |dbtx, result, old_state: CircuitCompleteStateMachine| {
                    let client_ctx = gateway_context.module.client_ctx.clone();
                    Box::pin(async move {
                        match result {
                            Ok(()) => {
                                client_ctx
                                    .log_event(
                                        &mut dbtx.module_tx(),
                                        CompleteLightningPaymentSucceeded {
                                            payment_hash: old_state.common.payment_hash,
                                        },
                                    )
                                    .await;
                                old_state.update(CompleteSMState::Completed)
                            }
                            Err(err) => {
                                old_state.update(CompleteSMState::CompletionFailed(err.to_string()))
                            }
                        }
                    })
                },
            )],
            CompleteSMState::Completed | CompleteSMState::CompletionFailed(_) => Vec::new(),
        }
    }

    fn operation_id(&self) -> OperationId {
        self.common.operation_id
    }
}

async fn await_receive(
    context: GatewayClientContextBolt12,
    operation_id: OperationId,
) -> FinalReceiveState {
    context.module.await_receive(operation_id).await
}

async fn complete_circuit(
    context: GatewayClientContextBolt12,
    payment_hash: sha256::Hash,
    final_receive_state: FinalReceiveState,
    circuit: IncomingCircuitKey,
) -> Result<(), LightningRpcError> {
    let action = match final_receive_state {
        FinalReceiveState::Success(preimage) => PaymentAction::Settle(Preimage(preimage)),
        FinalReceiveState::Rejected | FinalReceiveState::Refunded | FinalReceiveState::Failure => {
            PaymentAction::Cancel
        }
    };

    let response = InterceptPaymentResponse {
        incoming_chan_id: circuit.incoming_chan_id,
        htlc_id: circuit.htlc_id,
        payment_hash,
        action,
    };

    context.gateway.complete_htlc(response).await
}
