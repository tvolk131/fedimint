use std::fmt::{self, Display};

use fedimint_client::ClientHandleArc;
use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle,
};
use fedimint_core::config::FederationId;
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, TransactionId, secp256k1};
use fedimint_lightning::{LightningRpcError, PayInvoiceResponse};
use fedimint_ln_client::api::LnFederationApi;
use fedimint_ln_client::pay::{PayInvoicePayload, PaymentData};
use fedimint_ln_common::config::FeeToAmount;
use fedimint_ln_common::contracts::outgoing::OutgoingContractAccount;
use fedimint_ln_common::contracts::{ContractId, FundedContract, IdentifiableContract, Preimage};
use fedimint_ln_common::{LightningInput, LightningOutput};
use futures::future;
use lightning_invoice::RoutingFees;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_stream::StreamExt;
use tracing::{Instrument, debug, error, info, warn};

use super::{GatewayClientContext, GatewayExtReceiveStates};
use crate::GatewayClientModule;
use crate::events::{OutgoingPaymentFailed, OutgoingPaymentSucceeded};

const TIMELOCK_DELTA: u64 = 10;

#[cfg_attr(doc, aquamarine::aquamarine)]
/// State machine that executes the Lightning payment on behalf of
/// the fedimint user that requested an invoice to be paid.
///
/// ```mermaid
/// graph LR
/// classDef virtual fill:#fff,stroke-dasharray: 5 5
///
///    PayInvoice -- fetch contract failed --> Canceled
///    PayInvoice -- validate contract failed --> CancelContract
///    PayInvoice -- pay invoice unsuccessful --> CancelContract
///    PayInvoice -- pay invoice over Lightning successful --> ClaimOutgoingContract
///    PayInvoice -- pay invoice via direct swap successful --> WaitForSwapPreimage
///    WaitForSwapPreimage -- received preimage --> ClaimOutgoingContract
///    WaitForSwapPreimage -- wait for preimge failed --> Canceled
///    ClaimOutgoingContract -- claim tx submission --> Preimage
///    CancelContract -- cancel tx submission successful --> Canceled
///    CancelContract -- cancel tx submission unsuccessful --> Failed
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub enum GatewayPayStates {
    PayInvoice(GatewayPayInvoice),
    CancelContract(Box<GatewayPayCancelContract>),
    Preimage(Vec<OutPoint>, Preimage),
    OfferDoesNotExist(ContractId),
    Canceled {
        txid: TransactionId,
        contract_id: ContractId,
        error: OutgoingPaymentError,
    },
    WaitForSwapPreimage(Box<GatewayPayWaitForSwapPreimage>),
    ClaimOutgoingContract(Box<GatewayPayClaimOutgoingContract>),
    Failed {
        error: OutgoingPaymentError,
        error_message: String,
    },
}

impl fmt::Display for GatewayPayStates {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayPayStates::PayInvoice(_) => write!(f, "PayInvoice"),
            GatewayPayStates::CancelContract(_) => write!(f, "CancelContract"),
            GatewayPayStates::Preimage(..) => write!(f, "Preimage"),
            GatewayPayStates::OfferDoesNotExist(_) => write!(f, "OfferDoesNotExist"),
            GatewayPayStates::Canceled { .. } => write!(f, "Canceled"),
            GatewayPayStates::WaitForSwapPreimage(_) => write!(f, "WaitForSwapPreimage"),
            GatewayPayStates::ClaimOutgoingContract(_) => write!(f, "ClaimOutgoingContract"),
            GatewayPayStates::Failed { .. } => write!(f, "Failed"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub struct GatewayPayCommon {
    pub operation_id: OperationId,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub struct GatewayPayStateMachine {
    pub common: GatewayPayCommon,
    pub state: GatewayPayStates,
}

impl fmt::Display for GatewayPayStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Gateway Pay State Machine Operation ID: {:?} State: {}",
            self.common.operation_id, self.state
        )
    }
}

impl State for GatewayPayStateMachine {
    type ModuleContext = GatewayClientContext;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match &self.state {
            GatewayPayStates::PayInvoice(gateway_pay_invoice) => {
                gateway_pay_invoice.transitions(global_context.clone(), context, &self.common)
            }
            GatewayPayStates::WaitForSwapPreimage(gateway_pay_wait_for_swap_preimage) => {
                gateway_pay_wait_for_swap_preimage.transitions(context.clone(), self.common.clone())
            }
            GatewayPayStates::ClaimOutgoingContract(gateway_pay_claim_outgoing_contract) => {
                gateway_pay_claim_outgoing_contract.transitions(
                    global_context.clone(),
                    context.clone(),
                    self.common.clone(),
                )
            }
            GatewayPayStates::CancelContract(gateway_pay_cancel) => gateway_pay_cancel.transitions(
                global_context.clone(),
                context.clone(),
                self.common.clone(),
            ),
            _ => {
                vec![]
            }
        }
    }

    fn operation_id(&self) -> fedimint_core::core::OperationId {
        self.common.operation_id
    }
}

#[derive(
    Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq, Hash,
)]
pub enum OutgoingContractError {
    #[error("Invalid OutgoingContract {contract_id}")]
    InvalidOutgoingContract { contract_id: ContractId },
    #[error("The contract is already cancelled and can't be processed by the gateway")]
    CancelledContract,
    #[error("The Account or offer is keyed to another gateway")]
    NotOurKey,
    #[error("Invoice is missing amount")]
    InvoiceMissingAmount,
    #[error("Outgoing contract is underfunded, wants us to pay {0}, but only contains {1}")]
    Underfunded(Amount, Amount),
    #[error("The contract's timeout is in the past or does not allow for a safety margin")]
    TimeoutTooClose,
    #[error("Gateway could not retrieve metadata about the contract.")]
    MissingContractData,
    #[error("The invoice is expired. Expiry happened at timestamp: {0}")]
    InvoiceExpired(u64),
}

#[derive(
    Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq, Hash,
)]
pub enum OutgoingPaymentErrorType {
    #[error("OutgoingContract does not exist {contract_id}")]
    OutgoingContractDoesNotExist { contract_id: ContractId },
    #[error("An error occurred while paying the lightning invoice.")]
    LightningPayError { lightning_error: LightningRpcError },
    #[error("An invalid contract was specified.")]
    InvalidOutgoingContract { error: OutgoingContractError },
    #[error("An error occurred while attempting direct swap between federations.")]
    SwapFailed { swap_error: String },
    #[error("Invoice has already been paid")]
    InvoiceAlreadyPaid,
    #[error("No federation configuration")]
    InvalidFederationConfiguration,
    #[error("Invalid invoice preimage")]
    InvalidInvoicePreimage,
}

#[derive(
    Error, Debug, Serialize, Deserialize, Encodable, Decodable, Clone, Eq, PartialEq, Hash,
)]
pub struct OutgoingPaymentError {
    pub error_type: OutgoingPaymentErrorType,
    pub contract_id: ContractId,
    pub contract: Option<OutgoingContractAccount>,
}

impl Display for OutgoingPaymentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OutgoingContractError: {}", self.error_type)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub struct GatewayPayInvoice {
    pub pay_invoice_payload: PayInvoicePayload,
}

impl GatewayPayInvoice {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        context: &GatewayClientContext,
        common: &GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        let payload = self.pay_invoice_payload.clone();
        vec![StateTransition::new(
            Self::fetch_parameters_and_pay(
                global_context,
                payload,
                context.clone(),
                common.clone(),
            ),
            |_dbtx, result, _old_state| Box::pin(futures::future::ready(result)),
        )]
    }

    async fn fetch_parameters_and_pay(
        global_context: DynGlobalClientContext,
        pay_invoice_payload: PayInvoicePayload,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> GatewayPayStateMachine {
        match Self::await_get_payment_parameters(
            global_context,
            context.clone(),
            pay_invoice_payload.contract_id,
            pay_invoice_payload.payment_data.clone(),
            pay_invoice_payload.federation_id,
        )
        .await
        {
            Ok((contract, payment_parameters)) => {
                Self::buy_preimage(
                    context.clone(),
                    contract.clone(),
                    payment_parameters.clone(),
                    common.clone(),
                    pay_invoice_payload.clone(),
                )
                .await
            }
            Err(e) => {
                warn!("Failed to get payment parameters: {e:?}");
                match e.contract.clone() {
                    Some(contract) => GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::CancelContract(Box::new(
                            GatewayPayCancelContract { contract, error: e },
                        )),
                    },
                    None => GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::OfferDoesNotExist(e.contract_id),
                    },
                }
            }
        }
    }

    async fn buy_preimage(
        context: GatewayClientContext,
        contract: OutgoingContractAccount,
        payment_parameters: PaymentParameters,
        common: GatewayPayCommon,
        payload: PayInvoicePayload,
    ) -> GatewayPayStateMachine {
        debug!("Buying preimage contract {contract:?}");
        // Verify that this client is authorized to receive the preimage.
        if let Err(err) = context
            .lightning_manager
            .verify_preimage_authentication(
                payload.payment_data.payment_hash(),
                payload.preimage_auth,
                contract.clone(),
            )
            .await
        {
            warn!("Preimage authentication failed: {err} for contract {contract:?}");
            return GatewayPayStateMachine {
                common,
                state: GatewayPayStates::CancelContract(Box::new(GatewayPayCancelContract {
                    contract,
                    error: err,
                })),
            };
        }

        match context
            .lightning_manager
            .get_client_for_invoice(payment_parameters.payment_data.clone())
            .await
        {
            Some(client) => {
                client
                    .with(|client| {
                        Self::buy_preimage_via_direct_swap(
                            client,
                            payment_parameters.payment_data.clone(),
                            contract.clone(),
                            common.clone(),
                        )
                    })
                    .await
            }
            _ => {
                Self::buy_preimage_over_lightning(
                    context,
                    payment_parameters,
                    contract.clone(),
                    common.clone(),
                )
                .await
            }
        }
    }

    async fn await_get_payment_parameters(
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        contract_id: ContractId,
        payment_data: PaymentData,
        federation_id: FederationId,
    ) -> Result<(OutgoingContractAccount, PaymentParameters), OutgoingPaymentError> {
        debug!("Await payment parameters for outgoing contract {contract_id:?}");
        let account = global_context
            .module_api()
            .await_contract(contract_id)
            .await;

        if let FundedContract::Outgoing(contract) = account.contract {
            let outgoing_contract_account = OutgoingContractAccount {
                amount: account.amount,
                contract,
            };

            let consensus_block_count = global_context
                .module_api()
                .fetch_consensus_block_count()
                .await
                .map_err(|_| OutgoingPaymentError {
                    contract_id,
                    contract: Some(outgoing_contract_account.clone()),
                    error_type: OutgoingPaymentErrorType::InvalidOutgoingContract {
                        error: OutgoingContractError::TimeoutTooClose,
                    },
                })?;

            debug!(
                "Consensus block count: {consensus_block_count:?} for outgoing contract {contract_id:?}"
            );
            if consensus_block_count.is_none() {
                return Err(OutgoingPaymentError {
                    contract_id,
                    contract: Some(outgoing_contract_account.clone()),
                    error_type: OutgoingPaymentErrorType::InvalidOutgoingContract {
                        error: OutgoingContractError::MissingContractData,
                    },
                });
            }

            let routing_fees = context
                .lightning_manager
                .get_routing_fees(federation_id)
                .await
                .ok_or(OutgoingPaymentError {
                    error_type: OutgoingPaymentErrorType::InvalidFederationConfiguration,
                    contract_id,
                    contract: Some(outgoing_contract_account.clone()),
                })?;

            let payment_parameters = Self::validate_outgoing_account(
                &outgoing_contract_account,
                context.redeem_key,
                consensus_block_count.unwrap(),
                &payment_data,
                routing_fees,
            )
            .map_err(|e| {
                warn!("Invalid outgoing contract: {e:?}");
                OutgoingPaymentError {
                    contract_id,
                    contract: Some(outgoing_contract_account.clone()),
                    error_type: OutgoingPaymentErrorType::InvalidOutgoingContract { error: e },
                }
            })?;
            debug!("Got payment parameters: {payment_parameters:?} for contract {contract_id:?}");
            return Ok((outgoing_contract_account, payment_parameters));
        }

        error!("Contract {contract_id:?} is not an outgoing contract");
        Err(OutgoingPaymentError {
            contract_id,
            contract: None,
            error_type: OutgoingPaymentErrorType::OutgoingContractDoesNotExist { contract_id },
        })
    }

    async fn buy_preimage_over_lightning(
        context: GatewayClientContext,
        buy_preimage: PaymentParameters,
        contract: OutgoingContractAccount,
        common: GatewayPayCommon,
    ) -> GatewayPayStateMachine {
        debug!("Buying preimage over lightning for contract {contract:?}");

        let max_delay = buy_preimage.max_delay;
        let max_fee = buy_preimage.max_send_amount.saturating_sub(
            buy_preimage
                .payment_data
                .amount()
                .expect("We already checked that an amount was supplied"),
        );

        let payment_result = context
            .lightning_manager
            .pay(buy_preimage.payment_data, max_delay, max_fee)
            .await;

        match payment_result {
            Ok(PayInvoiceResponse { preimage, .. }) => {
                debug!("Preimage received for contract {contract:?}");
                GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::ClaimOutgoingContract(Box::new(
                        GatewayPayClaimOutgoingContract { contract, preimage },
                    )),
                }
            }
            Err(error) => Self::gateway_pay_cancel_contract(error, contract, common),
        }
    }

    fn gateway_pay_cancel_contract(
        error: LightningRpcError,
        contract: OutgoingContractAccount,
        common: GatewayPayCommon,
    ) -> GatewayPayStateMachine {
        warn!("Failed to buy preimage with {error} for contract {contract:?}");
        let outgoing_error = OutgoingPaymentError {
            contract_id: contract.contract.contract_id(),
            contract: Some(contract.clone()),
            error_type: OutgoingPaymentErrorType::LightningPayError {
                lightning_error: error,
            },
        };
        GatewayPayStateMachine {
            common,
            state: GatewayPayStates::CancelContract(Box::new(GatewayPayCancelContract {
                contract,
                error: outgoing_error,
            })),
        }
    }

    async fn buy_preimage_via_direct_swap(
        client: ClientHandleArc,
        payment_data: PaymentData,
        contract: OutgoingContractAccount,
        common: GatewayPayCommon,
    ) -> GatewayPayStateMachine {
        debug!("Buying preimage via direct swap for contract {contract:?}");
        match payment_data.try_into() {
            Ok(swap_params) => match client
                .get_first_module::<GatewayClientModule>()
                .expect("Must have client module")
                .gateway_handle_direct_swap(swap_params)
                .await
            {
                Ok(operation_id) => {
                    debug!("Direct swap initiated for contract {contract:?}");
                    GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::WaitForSwapPreimage(Box::new(
                            GatewayPayWaitForSwapPreimage {
                                contract,
                                federation_id: client.federation_id(),
                                operation_id,
                            },
                        )),
                    }
                }
                Err(e) => {
                    info!("Failed to initiate direct swap: {e:?} for contract {contract:?}");
                    let outgoing_payment_error = OutgoingPaymentError {
                        contract_id: contract.contract.contract_id(),
                        contract: Some(contract.clone()),
                        error_type: OutgoingPaymentErrorType::SwapFailed {
                            swap_error: format!("Failed to initiate direct swap: {e}"),
                        },
                    };
                    GatewayPayStateMachine {
                        common,
                        state: GatewayPayStates::CancelContract(Box::new(
                            GatewayPayCancelContract {
                                contract: contract.clone(),
                                error: outgoing_payment_error,
                            },
                        )),
                    }
                }
            },
            Err(e) => {
                info!("Failed to initiate direct swap: {e:?} for contract {contract:?}");
                let outgoing_payment_error = OutgoingPaymentError {
                    contract_id: contract.contract.contract_id(),
                    contract: Some(contract.clone()),
                    error_type: OutgoingPaymentErrorType::SwapFailed {
                        swap_error: format!("Failed to initiate direct swap: {e}"),
                    },
                };
                GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::CancelContract(Box::new(GatewayPayCancelContract {
                        contract: contract.clone(),
                        error: outgoing_payment_error,
                    })),
                }
            }
        }
    }

    fn validate_outgoing_account(
        account: &OutgoingContractAccount,
        redeem_key: bitcoin::key::Keypair,
        consensus_block_count: u64,
        payment_data: &PaymentData,
        routing_fees: RoutingFees,
    ) -> Result<PaymentParameters, OutgoingContractError> {
        let our_pub_key = secp256k1::PublicKey::from_keypair(&redeem_key);

        if account.contract.cancelled {
            return Err(OutgoingContractError::CancelledContract);
        }

        if account.contract.gateway_key != our_pub_key {
            return Err(OutgoingContractError::NotOurKey);
        }

        let payment_amount = payment_data
            .amount()
            .ok_or(OutgoingContractError::InvoiceMissingAmount)?;

        let gateway_fee = routing_fees.to_amount(&payment_amount);
        let necessary_contract_amount = payment_amount + gateway_fee;
        if account.amount < necessary_contract_amount {
            return Err(OutgoingContractError::Underfunded(
                necessary_contract_amount,
                account.amount,
            ));
        }

        let max_delay = u64::from(account.contract.timelock)
            .checked_sub(consensus_block_count.saturating_sub(1))
            .and_then(|delta| delta.checked_sub(TIMELOCK_DELTA));
        if max_delay.is_none() {
            return Err(OutgoingContractError::TimeoutTooClose);
        }

        if payment_data.is_expired() {
            return Err(OutgoingContractError::InvoiceExpired(
                payment_data.expiry_timestamp(),
            ));
        }

        Ok(PaymentParameters {
            max_delay: max_delay.unwrap(),
            max_send_amount: account.amount,
            payment_data: payment_data.clone(),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable, Serialize, Deserialize)]
struct PaymentParameters {
    max_delay: u64,
    max_send_amount: Amount,
    payment_data: PaymentData,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub struct GatewayPayClaimOutgoingContract {
    contract: OutgoingContractAccount,
    preimage: Preimage,
}

impl GatewayPayClaimOutgoingContract {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        let contract = self.contract.clone();
        let preimage = self.preimage.clone();
        vec![StateTransition::new(
            future::ready(()),
            move |dbtx, (), _| {
                Box::pin(Self::transition_claim_outgoing_contract(
                    dbtx,
                    global_context.clone(),
                    context.clone(),
                    common.clone(),
                    contract.clone(),
                    preimage.clone(),
                ))
            },
        )]
    }

    async fn transition_claim_outgoing_contract(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        common: GatewayPayCommon,
        contract: OutgoingContractAccount,
        preimage: Preimage,
    ) -> GatewayPayStateMachine {
        debug!("Claiming outgoing contract {contract:?}");

        context
            .client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                OutgoingPaymentSucceeded {
                    outgoing_contract: contract.clone(),
                    contract_id: contract.contract.contract_id(),
                    preimage: preimage.consensus_encode_to_hex(),
                },
            )
            .await;

        let claim_input = contract.claim(preimage.clone());
        let client_input = ClientInput::<LightningInput> {
            input: claim_input,
            amount: contract.amount,
            keys: vec![context.redeem_key],
        };

        let out_points = global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![client_input]))
            .await
            .expect("Cannot claim input, additional funding needed")
            .into_iter()
            .collect();
        debug!("Claimed outgoing contract {contract:?} with out points {out_points:?}");
        GatewayPayStateMachine {
            common,
            state: GatewayPayStates::Preimage(out_points, preimage),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub struct GatewayPayWaitForSwapPreimage {
    contract: OutgoingContractAccount,
    federation_id: FederationId,
    operation_id: OperationId,
}

impl GatewayPayWaitForSwapPreimage {
    fn transitions(
        &self,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        let federation_id = self.federation_id;
        let operation_id = self.operation_id;
        let contract = self.contract.clone();
        vec![StateTransition::new(
            Self::await_preimage(context, federation_id, operation_id, contract.clone()),
            move |_dbtx, result, _old_state| {
                let common = common.clone();
                let contract = contract.clone();
                Box::pin(async {
                    Self::transition_claim_outgoing_contract(common, result, contract)
                })
            },
        )]
    }

    async fn await_preimage(
        context: GatewayClientContext,
        federation_id: FederationId,
        operation_id: OperationId,
        contract: OutgoingContractAccount,
    ) -> Result<Preimage, OutgoingPaymentError> {
        debug!("Waiting preimage for contract {contract:?}");

        let client = context
            .lightning_manager
            .get_client(&federation_id)
            .await
            .ok_or(OutgoingPaymentError {
                contract_id: contract.contract.contract_id(),
                contract: Some(contract.clone()),
                error_type: OutgoingPaymentErrorType::SwapFailed {
                    swap_error: "Federation client not found".to_string(),
                },
            })?;

        async {
            let mut stream = client
                .value()
                .get_first_module::<GatewayClientModule>()
                .expect("Must have client module")
                .gateway_subscribe_ln_receive(operation_id)
                .await
                .map_err(|e| {
                    let contract_id = contract.contract.contract_id();
                    warn!(
                        ?contract_id,
                        "Failed to subscribe to ln receive of direct swap: {e:?}"
                    );
                    OutgoingPaymentError {
                        contract_id,
                        contract: Some(contract.clone()),
                        error_type: OutgoingPaymentErrorType::SwapFailed {
                            swap_error: format!(
                                "Failed to subscribe to ln receive of direct swap: {e}"
                            ),
                        },
                    }
                })?
                .into_stream();

            loop {
                debug!("Waiting next state of preimage buy for contract {contract:?}");
                if let Some(state) = stream.next().await {
                    match state {
                        GatewayExtReceiveStates::Funding => {
                            debug!(?contract, "Funding");
                            continue;
                        }
                        GatewayExtReceiveStates::Preimage(preimage) => {
                            debug!(?contract, "Received preimage");
                            return Ok(preimage);
                        }
                        other => {
                            warn!(?contract, "Got state {other:?}");
                            return Err(OutgoingPaymentError {
                                contract_id: contract.contract.contract_id(),
                                contract: Some(contract),
                                error_type: OutgoingPaymentErrorType::SwapFailed {
                                    swap_error: "Failed to receive preimage".to_string(),
                                },
                            });
                        }
                    }
                }
            }
        }
        .instrument(client.span())
        .await
    }

    fn transition_claim_outgoing_contract(
        common: GatewayPayCommon,
        result: Result<Preimage, OutgoingPaymentError>,
        contract: OutgoingContractAccount,
    ) -> GatewayPayStateMachine {
        match result {
            Ok(preimage) => GatewayPayStateMachine {
                common,
                state: GatewayPayStates::ClaimOutgoingContract(Box::new(
                    GatewayPayClaimOutgoingContract { contract, preimage },
                )),
            },
            Err(e) => GatewayPayStateMachine {
                common,
                state: GatewayPayStates::CancelContract(Box::new(GatewayPayCancelContract {
                    contract,
                    error: e,
                })),
            },
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable, Serialize, Deserialize)]
pub struct GatewayPayCancelContract {
    contract: OutgoingContractAccount,
    error: OutgoingPaymentError,
}

impl GatewayPayCancelContract {
    fn transitions(
        &self,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        common: GatewayPayCommon,
    ) -> Vec<StateTransition<GatewayPayStateMachine>> {
        let contract = self.contract.clone();
        let error = self.error.clone();
        vec![StateTransition::new(
            future::ready(()),
            move |dbtx, (), _| {
                Box::pin(Self::transition_canceled(
                    dbtx,
                    contract.clone(),
                    global_context.clone(),
                    context.clone(),
                    common.clone(),
                    error.clone(),
                ))
            },
        )]
    }

    async fn transition_canceled(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        contract: OutgoingContractAccount,
        global_context: DynGlobalClientContext,
        context: GatewayClientContext,
        common: GatewayPayCommon,
        error: OutgoingPaymentError,
    ) -> GatewayPayStateMachine {
        info!("Canceling outgoing contract {contract:?}");

        context
            .client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                OutgoingPaymentFailed {
                    outgoing_contract: contract.clone(),
                    contract_id: contract.contract.contract_id(),
                    error: error.clone(),
                },
            )
            .await;

        let cancel_signature = context.secp.sign_schnorr(
            &bitcoin::secp256k1::Message::from_digest(
                *contract.contract.cancellation_message().as_ref(),
            ),
            &context.redeem_key,
        );
        let cancel_output = LightningOutput::new_v0_cancel_outgoing(
            contract.contract.contract_id(),
            cancel_signature,
        );
        let client_output = ClientOutput::<LightningOutput> {
            output: cancel_output,
            amount: Amount::ZERO,
        };

        match global_context
            .fund_output(dbtx, ClientOutputBundle::new_no_sm(vec![client_output]))
            .await
        {
            Ok(change_range) => {
                info!(
                    "Canceled outgoing contract {contract:?} with txid {:?}",
                    change_range.txid()
                );
                GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::Canceled {
                        txid: change_range.txid(),
                        contract_id: contract.contract.contract_id(),
                        error,
                    },
                }
            }
            Err(e) => {
                warn!("Failed to cancel outgoing contract {contract:?}: {e:?}");
                GatewayPayStateMachine {
                    common,
                    state: GatewayPayStates::Failed {
                        error,
                        error_message: format!(
                            "Failed to submit refund transaction to federation {e:?}"
                        ),
                    },
                }
            }
        }
    }
}
