use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::anyhow;
use clap::Parser;
use fedimint_core::fedimint_build_code_version_env;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::handle_version_hash_command;
use futures::Stream;
use ldk_node::io::sqlite_store::SqliteStore;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning::ln::PaymentHash;
use ldk_node::lightning_invoice::Bolt11Invoice;
use ldk_node::{Network, UnknownPreimageFetcher};
use ln_gateway::envs::FM_CLN_EXTENSION_LISTEN_ADDRESS_ENV;
use ln_gateway::gateway_lnrpc::gateway_lightning_server::{
    GatewayLightning, GatewayLightningServer,
};
use ln_gateway::gateway_lnrpc::intercept_htlc_response::Action;
use ln_gateway::gateway_lnrpc::{
    EmptyRequest, EmptyResponse, GetNodeInfoResponse, GetRouteHintsRequest, GetRouteHintsResponse,
    InterceptHtlcRequest, InterceptHtlcResponse, PayInvoiceRequest, PayInvoiceResponse,
};
use ln_gateway::lightning::cln::{HtlcResult, RouteHtlcStream};
use std::future::IntoFuture;
use std::str::FromStr;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Server;
use tonic::Status;
use tracing::debug;

#[derive(Parser)]
struct LdkExtensionOpts {
    /// Gateway LDK extension service listen address
    #[arg(long = "fm-gateway-listen", env = FM_CLN_EXTENSION_LISTEN_ADDRESS_ENV)]
    fm_gateway_listen: SocketAddr,

    /// The network the gateway is running on
    #[arg(long = "network", env = "FM_GATEWAY_NETWORK_ENV")]
    network: bitcoin30::Network,

    /// The URL of the esplora server
    #[arg(long = "esplora-server-url", env = "FM_ESPLORA_SERVER_URL")]
    esplora_server_url: String,

    /// The listening addresses of the gateway
    #[arg(long = "listening-addresses", env = "FM_GATEWAY_LISTEN_ADDR_ENV")]
    listening_addresses: Vec<String>,

    /// The storage directory path
    #[arg(long = "storage-dir-path", env = "FM_GATEWAY_DATA_DIR_ENV")]
    storage_dir_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    handle_version_hash_command(fedimint_build_code_version_env!());

    // Parse configurations or read from environment variables
    // TODO: Describe the environment variables in the error message
    let opts = LdkExtensionOpts::try_parse()
        .map_err(|_| anyhow!("Failed to parse command line options"))?;

    // Parse the listening addresses
    let mut listening_addresses = Vec::new();
    for addr in opts.listening_addresses.iter() {
        listening_addresses.push(
            addr.parse()
                .map_err(|_| anyhow!("Invalid address: '{}'", addr))?,
        );
    }

    let service = LdkService::new(
        opts.network
            .try_into()
            .map_err(|_| anyhow!("Invalid network"))?,
        opts.esplora_server_url,
        listening_addresses,
        opts.storage_dir_path,
    )
    .await
    .map_err(|e| anyhow!("Failed to create LDKService: {}", e))?;

    debug!(
        "Starting gateway-ldk-extension with listen address : {}",
        opts.fm_gateway_listen
    );

    Server::builder()
        .add_service(GatewayLightningServer::new(service))
        .serve(opts.fm_gateway_listen)
        .await
        .map_err(|e| anyhow!("Failed to start server, {:?}", e))?;

    Ok(())
}

#[derive(Debug)]
struct LdkPreimageFetcher {
    // TODO: Store this on disk
    in_flight_htlc_txs: Mutex<HashMap<u64, tokio::sync::oneshot::Sender<InterceptHtlcResponse>>>,
    htlc_id: Mutex<u64>,
    intercept_htlc_request_stream_tx: Mutex<tokio::sync::mpsc::Sender<HtlcResult>>,
}

impl LdkPreimageFetcher {
    pub fn new() -> (Self, RouteHtlcStream<'static>) {
        let (tx, rx) = tokio::sync::mpsc::channel(1000);
        (
            Self {
                in_flight_htlc_txs: Mutex::new(HashMap::new()),
                htlc_id: Mutex::new(0),
                intercept_htlc_request_stream_tx: Mutex::new(tx),
            },
            Box::pin(ReceiverStream::new(rx)),
        )
    }

    pub async fn get_next_htlc_id(&self) -> u64 {
        let mut htlc_id = self.htlc_id.lock().await;
        *htlc_id += 1;
        *htlc_id
    }
}

#[async_trait::async_trait]
impl UnknownPreimageFetcher for LdkPreimageFetcher {
    async fn get_preimage(
        &self,
        payment_hash: PaymentHash,
    ) -> Result<ldk_node::lightning::ln::PaymentPreimage, ldk_node::NodeError> {
        let htlc_id = self.get_next_htlc_id().await;
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.in_flight_htlc_txs.lock().await.insert(htlc_id, tx);
        self.intercept_htlc_request_stream_tx
            .lock()
            .await
            .send(Ok(InterceptHtlcRequest {
                payment_hash: payment_hash.0.to_vec(),
                // TODO: Fill out the rest of the fields in the InterceptHtlcRequest.
                incoming_amount_msat: 0,
                outgoing_amount_msat: 0,
                incoming_expiry: 0,
                short_channel_id: 0,
                incoming_chan_id: 0,
                htlc_id,
            }))
            .await
            .unwrap();
        match rx.into_future().await {
            Ok(response) => {
                if let Some(action) = response.action {
                    if let Action::Settle(settle) = action {
                        Ok(ldk_node::lightning::ln::PaymentPreimage(
                            settle.preimage.try_into().unwrap(),
                        ))
                    } else {
                        Err(ldk_node::NodeError::InvalidPaymentPreimage)
                    }
                } else {
                    Err(ldk_node::NodeError::InvalidPaymentPreimage)
                }
            }
            Err(_) => Err(ldk_node::NodeError::InvalidPaymentPreimage),
        }
    }
}

#[allow(dead_code)]
struct LdkService {
    node: ldk_node::Node<SqliteStore>,
    network: Network,
    preimage_fetcher: Arc<LdkPreimageFetcher>,
    route_htlc_stream_or: Mutex<Option<RouteHtlcStream<'static>>>,
    task_group: TaskGroup,
}

impl LdkService {
    async fn new(
        network: Network,
        esplora_server_url: String,
        listening_addresses: Vec<SocketAddress>,
        storage_dir_path: String,
    ) -> anyhow::Result<Self> {
        let (preimage_fetcher, route_htlc_stream) = LdkPreimageFetcher::new();
        let preimage_fetcher_arc = Arc::from(preimage_fetcher);

        let node = ldk_node::Builder::new()
            .set_unknown_preimage_fetcher(preimage_fetcher_arc.clone())
            .set_listening_addresses(listening_addresses)
            .unwrap()
            .set_network(network)
            .set_esplora_server(esplora_server_url)
            .set_gossip_source_p2p()
            .set_storage_dir_path(storage_dir_path)
            .build()
            .unwrap();

        node.start()
            .map_err(|e| anyhow!("Failed to start LDK Node: {e}"))?;

        Ok(Self {
            node,
            network,
            preimage_fetcher: preimage_fetcher_arc,
            route_htlc_stream_or: Mutex::new(Some(route_htlc_stream)),
            task_group: TaskGroup::new(),
        })
    }
}

#[tonic::async_trait]
impl GatewayLightning for LdkService {
    async fn get_node_info(
        &self,
        _request: tonic::Request<EmptyRequest>,
    ) -> Result<tonic::Response<GetNodeInfoResponse>, Status> {
        Ok(tonic::Response::new(GetNodeInfoResponse {
            pub_key: self.node.node_id().to_string().into_bytes(),
            alias: "Gateway LDK Extension".to_string(), // TODO: Get the alias from the node
            network: self.network.to_string(), // TODO: Verify that this serializes correctly
        }))
    }

    async fn get_route_hints(
        &self,
        _request: tonic::Request<GetRouteHintsRequest>,
    ) -> Result<tonic::Response<GetRouteHintsResponse>, Status> {
        // We don't need this since all invoices must be created by the gateway, which
        // give it the ability to add route hints to the invoice directly.
        Err(Status::unimplemented("Not implemented"))
    }

    async fn pay_invoice(
        &self,
        request: tonic::Request<PayInvoiceRequest>,
    ) -> Result<tonic::Response<PayInvoiceResponse>, tonic::Status> {
        let PayInvoiceRequest {
            invoice,
            max_delay: _,
            max_fee_msat: _,
            payment_hash: _,
        } = request.into_inner();

        // TODO: Respect `max_fee` and `max_delay` from the request
        let payment_hash = self
            .node
            .send_payment(
                &Bolt11Invoice::from_str(&invoice)
                    .map_err(|_| tonic::Status::invalid_argument("Invalid invoice"))?,
            )
            .map_err(|_| tonic::Status::internal("Failed to send payment"))?;

        let payment = match self.node.payment(&payment_hash) {
            Some(payment) => payment,
            None => {
                return Err(tonic::Status::internal("Failed to get payment from store"));
            }
        };

        let preimage = match payment.preimage {
            Some(preimage) => preimage,
            None => {
                return Err(tonic::Status::internal(
                    "Failed to get preimage from payment",
                ));
            }
        };

        Ok(tonic::Response::new(PayInvoiceResponse {
            preimage: preimage.0.to_vec(),
        }))
    }

    // type RouteHtlcsStream = ReceiverStream<Result<InterceptHtlcRequest, Status>>;
    type RouteHtlcsStream =
        Pin<Box<dyn Stream<Item = Result<InterceptHtlcRequest, Status>> + Send>>;

    async fn route_htlcs(
        &self,
        _: tonic::Request<EmptyRequest>,
    ) -> Result<tonic::Response<Self::RouteHtlcsStream>, Status> {
        let route_htlc_stream = match self.route_htlc_stream_or.lock().await.take() {
            Some(stream) => Ok(stream),
            None => Err(Status::failed_precondition(
                "Stream does not exist. Likely was already taken by calling `route_htlcs()`.",
            )),
        }?;

        Ok(tonic::Response::new(route_htlc_stream))
    }

    async fn complete_htlc(
        &self,
        intercept_response: tonic::Request<InterceptHtlcResponse>,
    ) -> Result<tonic::Response<EmptyResponse>, Status> {
        let response_inner = intercept_response.into_inner();

        let rx = match self
            .preimage_fetcher
            .in_flight_htlc_txs
            .lock()
            .await
            .remove(&response_inner.htlc_id)
        {
            Some(rx) => rx,
            None => {
                return Err(Status::failed_precondition("Invalid HTLC"));
            }
        };

        rx.send(response_inner)
            .map_err(|_| Status::internal("Failed to send response"))?;

        Ok(tonic::Response::new(EmptyResponse {}))
    }
}
