use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::OutPoint;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::Amounts;
use fedimint_core::secp256k1::Keypair;
use fedimint_core::util::FmtCompact;
use fedimint_lnv2_common::bolt12::{Bolt12Unlock, StreamedReceive};
use fedimint_lnv2_common::{LightningInput, LightningInputV0};
use fedimint_logging::LOG_CLIENT_MODULE_LNV2;
use tracing::warn;

use crate::LightningClientContext;
use crate::events::ReceivePaymentEvent;

/// Claims one funded federated BOLT12 receive.
///
/// The receive is already funded when the wallet finds it in the federation's
/// stream, so there is nothing to wait for: the only transition submits the
/// claim.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct Bolt12ReceiveStateMachine {
    pub operation_id: OperationId,
    pub receive: StreamedReceive,
    pub claim_keypair: Keypair,
    pub unlock: Bolt12Unlock,
    pub state: Bolt12ReceiveSMState,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum Bolt12ReceiveSMState {
    Pending,
    Claiming(Vec<OutPoint>),
    /// Claiming costs more in federation fees than the receive is worth.
    Uneconomical,
}

impl State for Bolt12ReceiveStateMachine {
    type ModuleContext = LightningClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();
        let ctx = context.clone();

        match &self.state {
            Bolt12ReceiveSMState::Pending => {
                vec![StateTransition::new(
                    std::future::ready(()),
                    move |dbtx, (), old_state| {
                        Box::pin(Self::transition_claim(
                            dbtx,
                            old_state,
                            ctx.clone(),
                            gc.clone(),
                        ))
                    },
                )]
            }
            Bolt12ReceiveSMState::Claiming(..) | Bolt12ReceiveSMState::Uneconomical => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

impl Bolt12ReceiveStateMachine {
    async fn transition_claim(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        mut old_state: Bolt12ReceiveStateMachine,
        context: LightningClientContext,
        global_context: DynGlobalClientContext,
    ) -> Bolt12ReceiveStateMachine {
        let contract = &old_state.receive.contract;

        let client_input = ClientInput::<LightningInput> {
            input: LightningInput::V0(LightningInputV0::Bolt12Receive(
                old_state.receive.outpoint,
                old_state.unlock.clone(),
            )),
            amounts: Amounts::new_bitcoin(contract.amount),
            keys: vec![old_state.claim_keypair],
        };

        let change_range = match global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![client_input]))
            .await
        {
            Ok(change_range) => change_range,
            // As for incoming contracts: this must end in a state, not a
            // panic, because the executor polls this transition again on
            // every restart.
            Err(err) => {
                warn!(
                    target: LOG_CLIENT_MODULE_LNV2,
                    err = %err.fmt_compact(),
                    amount = %contract.amount,
                    "Not claiming BOLT12 receive, its amount does not cover the claim fee"
                );

                old_state.state = Bolt12ReceiveSMState::Uneconomical;

                return old_state;
            }
        };

        context
            .client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                ReceivePaymentEvent {
                    operation_id: old_state.operation_id,
                    amount: contract.amount + contract.gateway_fee,
                    fee: contract.gateway_fee,
                },
            )
            .await;

        old_state.state = Bolt12ReceiveSMState::Claiming(change_range.into_iter().collect());

        old_state
    }
}
