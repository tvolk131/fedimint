//! Federated BOLT12: answering invoice requests for offers the federation
//! issues, and funding the recipient's claim when the payment arrives.
//!
//! See `docs/federated_bolt12.md` for the protocol.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, ensure};
use bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::Amount;
use fedimint_core::config::FederationId;
use fedimint_core::task::{TaskGroup, timeout};
use fedimint_core::util::FmtCompact as _;
use fedimint_gwv2_client::bolt12::Bolt12InvoiceRequest;
use fedimint_gwv2_client::{GatewayClientModuleV2, IncomingCircuitKey};
use fedimint_lightning::bolt12::{Bolt12Request, Bolt12RequestFilter};
use fedimint_lightning::{
    ILnRpcClient, InterceptPaymentRequest, InterceptPaymentResponse, LightningContext,
    PaymentAction,
};
use fedimint_lnv2_common::bolt12::invoice::{is_routing_metadata, parse_routing_metadata};
use fedimint_lnv2_common::gateway_api::Bolt12Ingress;
use fedimint_logging::LOG_GATEWAY;
use lightning::offers::invoice_request::InvoiceRequest;
use lightning::util::ser::Writeable as _;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::{Gateway, PublicGatewayError, Result};

/// Invoice requests answered at once. Each one waits on a consensus round
/// and two signing rounds, so they must overlap; beyond this many the
/// gateway drops requests and payers retry.
const MAX_CONCURRENT_REQUESTS: usize = 16;

/// How long the gateway works on one invoice request. Payers give up on an
/// unanswered request after about this long.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Invoice requests being answered, by the hash of their bytes. Payers resend
/// a request they have no answer to yet; a resend that overlapped the first
/// attempt would reserve a second stock item for the same payment.
#[derive(Default)]
struct InProgress(Mutex<HashSet<sha256::Hash>>);

impl InProgress {
    /// Claim `request`, or `None` if it is already being answered. The claim
    /// ends when the returned guard drops.
    fn claim(self: &Arc<Self>, request: &InvoiceRequest) -> Option<InProgressGuard> {
        let key = sha256::Hash::hash(&request.encode());

        self.0
            .lock()
            .expect("not poisoned")
            .insert(key)
            .then(|| InProgressGuard(self.clone(), key))
    }
}

struct InProgressGuard(Arc<InProgress>, sha256::Hash);

impl Drop for InProgressGuard {
    fn drop(&mut self) {
        self.0.0.lock().expect("not poisoned").remove(&self.1);
    }
}

fn is_federated(request: &InvoiceRequest) -> bool {
    request
        .metadata()
        .is_some_and(|metadata| is_routing_metadata(metadata))
}

impl Gateway {
    /// How payers reach this gateway for a federation's BOLT12 offers, or
    /// `None` if it does not serve them there.
    pub async fn bolt12_ingress_v2(
        &self,
        federation_id: &FederationId,
    ) -> Result<Option<Bolt12Ingress>> {
        let Some(routing_info) = self.routing_info_v2(federation_id).await? else {
            return Ok(None);
        };

        let enabled = self
            .select_client(*federation_id)
            .await?
            .value()
            .get_first_module::<GatewayClientModuleV2>()
            .is_ok_and(|module| module.cfg.bolt12.is_some());

        if !enabled || !routing_info.receive_enabled {
            return Ok(None);
        }

        let context = self.get_lightning_context().await?;

        match context.lnrpc.bolt12_message_path().await {
            Ok(path) => Ok(Some(Bolt12Ingress::new(
                &path,
                routing_info.module_public_key,
                routing_info.receive_fee,
            ))),
            Err(err) => {
                debug!(target: LOG_GATEWAY, err = %err.fmt_compact(), "No BOLT12 message path");
                Ok(None)
            }
        }
    }

    /// Answer federated invoice requests the Lightning node receives until
    /// `task_group` shuts down. Does nothing if the node cannot serve them.
    pub fn spawn_bolt12_request_handler(
        &self,
        task_group: &TaskGroup,
        lnrpc: Arc<dyn ILnRpcClient>,
    ) {
        let filter: Bolt12RequestFilter = Arc::new(is_federated);

        let mut requests = match lnrpc.bolt12_requests(filter) {
            Ok(requests) => requests,
            Err(err) => {
                debug!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Not serving federated BOLT12 offers");
                return;
            }
        };

        let gateway = self.clone();
        let request_tasks = task_group.clone();

        task_group.spawn_cancellable("bolt12 invoice requests", async move {
            let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
            let in_progress = Arc::new(InProgress::default());

            while let Some(request) = requests.recv().await {
                // The first attempt answers over its own reply path, which
                // reaches the same payer.
                let Some(claim) = in_progress.claim(&request.invoice_request) else {
                    debug!(target: LOG_GATEWAY, "Dropping a resent BOLT12 invoice request that is still being answered");
                    continue;
                };

                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    debug!(target: LOG_GATEWAY, "Dropping a BOLT12 invoice request: too many in progress");
                    continue;
                };

                let gateway = gateway.clone();
                let lnrpc = lnrpc.clone();

                request_tasks.spawn_cancellable_silent("bolt12 invoice request", async move {
                    let _permit = permit;
                    let _claim = claim;

                    match timeout(REQUEST_TIMEOUT, gateway.answer_bolt12_request(request, lnrpc))
                        .await
                    {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => {
                            info!(target: LOG_GATEWAY, err = %(&*err).fmt_compact(), "Did not answer a BOLT12 invoice request");
                        }
                        Err(_) => {
                            info!(target: LOG_GATEWAY, "Timed out answering a BOLT12 invoice request");
                        }
                    }
                });
            }
        });
    }

    /// Answer one claimed invoice request with a federation-signed invoice.
    pub async fn answer_bolt12_request(
        &self,
        request: Bolt12Request,
        lnrpc: Arc<dyn ILnRpcClient>,
    ) -> anyhow::Result<()> {
        // Every request costs the federation a reservation and the node a
        // registered payment, so it shares the invoice rate limit.
        ensure!(
            self.invoice_rate_limiter.try_acquire(),
            "BOLT12 invoice requests are rate limited"
        );

        let invoice_request = Arc::new(request.invoice_request.clone());

        let (federation_id, handle) = parse_routing_metadata(
            invoice_request
                .metadata()
                .context("The offer carries no metadata")?,
        )?;

        let amount = Amount::from_msats(
            invoice_request
                .amount_msats()
                .context("The request names no amount")?,
        );

        let routing_info = self
            .routing_info_v2(&federation_id)
            .await?
            .context("This gateway does not serve the federation over LNv2")?;

        ensure!(
            routing_info.receive_enabled,
            "Receives are disabled for this federation"
        );

        let client = self.select_client(federation_id).await?;
        let module = client.value().get_first_module::<GatewayClientModuleV2>()?;

        let payment_path = |payment_hash: [u8; 32]| {
            let lnrpc = lnrpc.clone();
            let invoice_request = invoice_request.clone();

            async move {
                // The handle labels the payment in the node's records; the
                // node has no offer of its own to name.
                lnrpc
                    .register_bolt12_payment(
                        sha256::Hash::from_byte_array(payment_hash),
                        amount,
                        &invoice_request,
                        handle,
                    )
                    .await
                    .map_err(anyhow::Error::from)
            }
        };

        let invoice = module
            .issue_bolt12_invoice(
                Bolt12InvoiceRequest {
                    handle,
                    invoice_request: invoice_request.encode(),
                    amount,
                    gateway_fee: routing_info.receive_fee.fee(amount.msats),
                },
                payment_path,
            )
            .await?;

        request.respond(invoice)?;

        Ok(())
    }

    /// Fund the claim behind a held payment for a federated BOLT12 invoice
    /// this gateway issued. Fails if the payment is for no such invoice.
    pub async fn try_handle_lightning_payment_bolt12(
        &self,
        htlc_request: &InterceptPaymentRequest,
        lightning_context: &LightningContext,
    ) -> Result<()> {
        let clients = self.federation_manager.read().await.clients();

        for client in clients {
            let Ok(module) = client.value().get_first_module::<GatewayClientModuleV2>() else {
                continue;
            };

            let Some(reservation) = module
                .bolt12_reservation_for_hash(htlc_request.payment_hash)
                .await
            else {
                continue;
            };

            let result = if self.receive_enabled(module.federation_id).await {
                let current_block_height = lightning_context
                    .lnrpc
                    .info()
                    .await
                    .ok()
                    .map(|info| info.block_height);

                module
                    .relay_bolt12_htlc(
                        reservation,
                        htlc_request.payment_hash,
                        IncomingCircuitKey {
                            incoming_chan_id: htlc_request.incoming_chan_id,
                            htlc_id: htlc_request.htlc_id,
                        },
                        htlc_request.incoming_amount_msat,
                        htlc_request.lnv2_blocks_to_claim_deadline(current_block_height),
                    )
                    .await
                    .map_err(anyhow::Error::from)
            } else {
                Err(anyhow::anyhow!("Receives are disabled for this federation"))
            };

            if let Err(err) = result {
                warn!(target: LOG_GATEWAY, err = %(&*err).fmt_compact(), "Failing a federated BOLT12 payment");

                let outcome = InterceptPaymentResponse {
                    action: PaymentAction::Cancel,
                    payment_hash: htlc_request.payment_hash,
                    incoming_chan_id: htlc_request.incoming_chan_id,
                    htlc_id: htlc_request.htlc_id,
                };

                if let Err(err) = lightning_context.lnrpc.complete_htlc(outcome).await {
                    warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Error sending HTLC response to lightning node");
                }
            }

            return Ok(());
        }

        Err(PublicGatewayError::Unexpected(anyhow::anyhow!(
            "Not a federated BOLT12 payment"
        )))
    }
}
