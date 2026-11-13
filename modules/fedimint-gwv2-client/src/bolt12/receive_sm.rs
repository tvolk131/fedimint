use core::fmt;
use std::collections::BTreeMap;
use std::sync::Arc;

use fedimint_api_client::api::{FederationApiExt, ServerError};
use fedimint_api_client::query::FilterMapThreshold;
use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::sm::{ClientSMDatabaseTransaction, State, StateTransition};
use fedimint_client_module::transaction::{ClientInput, ClientInputBundle};
use fedimint_core::bitcoin::hashes::{Hash, sha256};
use fedimint_core::core::OperationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{Amounts, ApiRequestErased};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::util::FmtCompact;
use fedimint_core::{NumPeersExt, OutPoint, PeerId, runtime};
use fedimint_lnv2_common::bolt12::ReceiveContract;
use fedimint_lnv2_common::contracts::PaymentImage;
use fedimint_lnv2_common::endpoint_constants::DECRYPTION_KEY_SHARE_ENDPOINT;
use fedimint_lnv2_common::{LightningInput, LightningInputV0};
use fedimint_logging::LOG_CLIENT_MODULE_GW;
use tpe::{AggregatePublicKey, DecryptionKeyShare, PublicKeyShare, aggregate_dk_shares};
use tracing::warn;

use crate::GatewayClientContextV2;
use crate::events::{IncomingPaymentFailed, IncomingPaymentSucceeded};
use crate::receive_sm::DecryptionOutcome;

/// Funds a federated BOLT12 receive and recovers the Lightning preimage.
///
/// This is the BOLT12 counterpart of the incoming contract state machine, and
/// ends in the same outcomes, so circuit completion treats both alike. The
/// difference is who made the ciphertext: here the recipient uploaded it
/// before going offline, bound to its registration rather than to a contract.
///
/// ```mermaid
/// graph LR
///     Funding -- funding transaction is rejected --> Rejected
///     Funding -- aggregated decryption key is invalid --> Failure
///     Funding -- decrypted preimage is valid --> Success
///     Funding -- decrypted preimage is invalid --> Refunding
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct Bolt12ReceiveStateMachine {
    pub operation_id: OperationId,
    pub contract: ReceiveContract,
    pub outpoint: OutPoint,
    pub refund_keypair: Keypair,
    pub state: Bolt12ReceiveSMState,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum Bolt12ReceiveSMState {
    Funding,
    Rejected(String),
    Success([u8; 32]),
    Failure,
    Refunding(Vec<OutPoint>),
}

impl fmt::Display for Bolt12ReceiveStateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self.state {
            Bolt12ReceiveSMState::Funding => "Funding",
            Bolt12ReceiveSMState::Rejected(_) => "Rejected",
            Bolt12ReceiveSMState::Success(_) => "Success",
            Bolt12ReceiveSMState::Failure => "Failure",
            Bolt12ReceiveSMState::Refunding(_) => "Refunding",
        };

        write!(
            f,
            "BOLT12 Receive State Machine Operation ID: {:?} State: {state}",
            self.operation_id
        )
    }
}

impl State for Bolt12ReceiveStateMachine {
    type ModuleContext = GatewayClientContextV2;

    fn transitions(
        &self,
        context: &Self::ModuleContext,
        global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        let gc = global_context.clone();
        let ctx = context.clone();

        match &self.state {
            Bolt12ReceiveSMState::Funding => {
                vec![StateTransition::new(
                    Self::await_decryption_shares(
                        global_context.clone(),
                        context.tpe_pks.clone(),
                        context.tpe_agg_pk,
                        self.outpoint,
                        self.contract.clone(),
                    ),
                    move |dbtx, outcome, old_state| {
                        Box::pin(Self::transition_decryption_shares(
                            dbtx,
                            outcome,
                            old_state,
                            gc.clone(),
                            ctx.clone(),
                        ))
                    },
                )]
            }
            Bolt12ReceiveSMState::Success(..)
            | Bolt12ReceiveSMState::Rejected(..)
            | Bolt12ReceiveSMState::Refunding(..)
            | Bolt12ReceiveSMState::Failure => vec![],
        }
    }

    fn operation_id(&self) -> OperationId {
        self.operation_id
    }
}

impl Bolt12ReceiveStateMachine {
    fn payment_image(&self) -> PaymentImage {
        PaymentImage::Hash(sha256::Hash::from_byte_array(self.contract.payment_hash))
    }

    async fn await_decryption_shares(
        global_context: DynGlobalClientContext,
        tpe_pks: BTreeMap<PeerId, PublicKeyShare>,
        tpe_agg_pk: AggregatePublicKey,
        outpoint: OutPoint,
        contract: ReceiveContract,
    ) -> DecryptionOutcome {
        let num_peers = global_context.api().all_peers().to_num_peers();
        let module_api = global_context.module_api();
        let tpe_pks = Arc::new(tpe_pks);
        let contract = Arc::new(contract);

        // The share endpoint long-polls until the funding output is accepted,
        // so the request can overlap with awaiting acceptance.
        let decryption_shares = module_api.request_with_strategy_retry(
            FilterMapThreshold::new(
                {
                    let tpe_pks = tpe_pks.clone();
                    let contract = contract.clone();

                    move |peer_id, share: DecryptionKeyShare| {
                        let tpe_pks = tpe_pks.clone();
                        let contract = contract.clone();

                        // Pairing arithmetic; keep it off the async workers.
                        runtime::spawn_blocking(move || {
                            let pk =
                                tpe_pks
                                    .get(&peer_id)
                                    .ok_or(ServerError::InternalClientError(format!(
                                        "Missing TPE PK for peer {peer_id}?!"
                                    )))?;

                            if !contract.verify_decryption_share(pk, &share) {
                                return Err(ServerError::InvalidResponse(
                                    "Invalid decryption share".to_string(),
                                ));
                            }

                            Ok(share)
                        })
                    }
                },
                num_peers,
            ),
            DECRYPTION_KEY_SHARE_ENDPOINT.to_owned(),
            ApiRequestErased::new(outpoint),
        );

        let decryption_shares = std::pin::pin!(decryption_shares);
        let tx_accepted = std::pin::pin!(global_context.await_tx_accepted(outpoint.txid));

        let decryption_shares = match futures::future::select(decryption_shares, tx_accepted).await
        {
            futures::future::Either::Left((shares, _)) => shares,
            futures::future::Either::Right((accepted, decryption_shares)) => {
                if let Err(error) = accepted {
                    return DecryptionOutcome::Rejected(error);
                }

                decryption_shares.await
            }
        };

        runtime::spawn_blocking(move || {
            let agg_decryption_key = aggregate_dk_shares(
                &decryption_shares
                    .into_iter()
                    .map(|(peer, share)| (peer.to_usize() as u64, share))
                    .collect(),
            );

            if !contract.verify_agg_decryption_key(&tpe_agg_pk, &agg_decryption_key) {
                return DecryptionOutcome::InconsistentKeys;
            }

            let preimage = contract.decrypt_preimage(&agg_decryption_key);

            DecryptionOutcome::Decrypted(agg_decryption_key, preimage)
        })
        .await
    }

    async fn fail(
        mut self,
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        client_ctx: &GatewayClientContextV2,
        error: &str,
        state: Bolt12ReceiveSMState,
    ) -> Self {
        client_ctx
            .module
            .client_ctx
            .log_event(
                &mut dbtx.module_tx(),
                IncomingPaymentFailed {
                    payment_image: self.payment_image(),
                    error: error.to_string(),
                },
            )
            .await;

        self.state = state;

        self
    }

    async fn transition_decryption_shares(
        dbtx: &mut ClientSMDatabaseTransaction<'_, '_>,
        outcome: DecryptionOutcome,
        mut old_state: Bolt12ReceiveStateMachine,
        global_context: DynGlobalClientContext,
        client_ctx: GatewayClientContextV2,
    ) -> Bolt12ReceiveStateMachine {
        let (agg_decryption_key, preimage) = match outcome {
            DecryptionOutcome::Rejected(error) => {
                let state = Bolt12ReceiveSMState::Rejected(error.clone());

                return old_state.fail(dbtx, &client_ctx, &error, state).await;
            }
            DecryptionOutcome::InconsistentKeys => {
                warn!(
                    target: LOG_CLIENT_MODULE_GW,
                    "Failed to obtain decryption key. Client config's public keys are inconsistent"
                );

                return old_state
                    .fail(
                        dbtx,
                        &client_ctx,
                        "Client config's public keys are inconsistent",
                        Bolt12ReceiveSMState::Failure,
                    )
                    .await;
            }
            DecryptionOutcome::Decrypted(agg_decryption_key, preimage) => {
                (agg_decryption_key, preimage)
            }
        };

        if let Some(preimage) = preimage {
            client_ctx
                .module
                .client_ctx
                .log_event(
                    &mut dbtx.module_tx(),
                    IncomingPaymentSucceeded {
                        payment_image: old_state.payment_image(),
                    },
                )
                .await;

            old_state.state = Bolt12ReceiveSMState::Success(preimage);

            return old_state;
        }

        // The recipient's stock item did not contain the preimage. The
        // Lightning payment cannot be settled, so take the funding back.
        let client_input = ClientInput::<LightningInput> {
            input: LightningInput::V0(LightningInputV0::Bolt12Receive(
                old_state.outpoint,
                agg_decryption_key,
            )),
            amounts: Amounts::new_bitcoin(old_state.contract.amount),
            keys: vec![old_state.refund_keypair],
        };

        match global_context
            .claim_inputs(dbtx, ClientInputBundle::new_no_sm(vec![client_input]))
            .await
        {
            Ok(outpoints) => {
                let state = Bolt12ReceiveSMState::Refunding(outpoints.into_iter().collect());

                old_state
                    .fail(dbtx, &client_ctx, "Failed to decrypt preimage", state)
                    .await
            }
            // As for incoming contracts: a refund the fees would swallow ends
            // in a state, not a panic in the executor.
            Err(err) => {
                warn!(
                    target: LOG_CLIENT_MODULE_GW,
                    err = %err.fmt_compact(),
                    amount = %old_state.contract.amount,
                    "Not refunding BOLT12 receive, its amount does not cover the refund fee"
                );

                old_state
                    .fail(
                        dbtx,
                        &client_ctx,
                        "Receive does not cover the refund fee",
                        Bolt12ReceiveSMState::Failure,
                    )
                    .await
            }
        }
    }
}
