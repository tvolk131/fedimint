use std::{ffi, iter};

use clap::{Parser, Subcommand};
use fedimint_api_client::api::FederationError;
use fedimint_client_module::error::OperationLookupError;
use fedimint_core::core::OperationId;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId};
use fedimint_lnv2_common::bolt12::{MAX_POOL_TARGET, Registration, RegistrationId};
use fedimint_lnv2_common::gateway_api::PaymentFee;
use lightning_invoice::Bolt11Invoice;
use serde::Serialize;
use serde_json::Value;

use crate::api::LightningFederationApi;
use crate::bolt12::Bolt12OfferParams;
use crate::{
    Bolt11InvoiceDescription, GenerateLnurlError, LightningClientModule, ListGatewaysError,
    ReceiveError, SelectGatewayError, SendPaymentError,
};

#[cfg(test)]
mod tests;

const DEFAULT_OFFER_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_OFFER_STOCK: u64 = 8;
const DEFAULT_RESCAN_MAX_INDEX: u64 = 100;
const POOL_ITEMS_PAGE_SIZE: usize = 32;

#[derive(Parser, Serialize)]
enum Opts {
    /// Pay an invoice. For  testing  you can optionally specify a gateway to
    /// route with, otherwise a gateway will be selected automatically.
    Send {
        invoice: Bolt11Invoice,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
    /// Await the final state of the send operation.
    AwaitSend { operation_id: OperationId },
    /// Request an invoice. For testing you can optionally specify a gateway to
    /// generate the invoice, otherwise a gateway will be selected
    /// automatically.
    Receive {
        amount: Amount,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
    /// Await the final state of the receive operation.
    AwaitReceive { operation_id: OperationId },
    /// Lnurl subcommands
    #[command(subcommand)]
    Lnurl(LnurlOpts),
    /// Gateway subcommands
    #[command(subcommand)]
    Gateways(GatewaysOpts),
    /// Federated BOLT12 offline-receive subcommands
    #[command(subcommand)]
    Bolt12(Bolt12Opts),
}

#[derive(Clone, Subcommand, Serialize)]
enum LnurlOpts {
    /// Generate a new lnurl.
    Generate {
        recurringd: SafeUrl,
        #[arg(long)]
        gateway: Option<SafeUrl>,
    },
}

#[derive(Clone, Subcommand, Serialize)]
enum GatewaysOpts {
    /// Update the mapping from lightning node public keys to gateway api
    /// endpoints maintained in the module database to optimise gateway
    /// selection for a given invoice; this command is intended for testing.
    Map,
    /// Select an online vetted gateway; this command is intended for testing.
    Select {
        #[arg(long)]
        invoice: Option<Bolt11Invoice>,
    },
    /// List all vetted gateways.
    List {
        #[arg(long)]
        peer: Option<PeerId>,
    },
    /// Add a vetted gateway.
    Add { gateway: SafeUrl },
    /// Remove a vetted gateway.
    Remove { gateway: SafeUrl },
}

#[derive(Clone, Subcommand, Serialize)]
enum Bolt12Opts {
    /// Show federated BOLT12 configuration and current MPC pool availability.
    Status,
    /// Query BOLT12 ingress metadata and approval status for gateways.
    Gateways {
        /// Specific gateway API URLs to query. Defaults to the federation's
        /// vetted gateways.
        #[arg(long = "gateway")]
        gateways: Vec<SafeUrl>,
        /// Include gateways that serve BOLT12 ingress but do not yet have
        /// guardian quorum approval.
        #[arg(long)]
        include_unapproved: bool,
    },
    /// Register a new reusable federated BOLT12 offer and upload initial stock.
    CreateOffer {
        /// Human-readable description embedded in the offer.
        #[arg(long, default_value = "")]
        description: String,
        /// Initial number of single-use preimages to upload.
        #[arg(long, default_value_t = DEFAULT_OFFER_STOCK)]
        stock: u64,
        /// Offer lifetime in seconds from now.
        #[arg(long, default_value_t = DEFAULT_OFFER_EXPIRY_SECS)]
        expiry_secs: u64,
        /// Allow falling back to federation-generated MPC pool preimages once
        /// the offer's stock is exhausted.
        #[arg(long)]
        allow_pool: bool,
        /// Specific gateway API URLs to include in the offer. Defaults to the
        /// federation's vetted gateways.
        #[arg(long = "gateway")]
        gateways: Vec<SafeUrl>,
        /// Maximum gateway receive fee (`<base>,<ppm>`). Defaults to the
        /// component-wise max across the selected gateways.
        #[arg(long)]
        max_gateway_fee: Option<PaymentFee>,
    },
    /// List offers registered by this wallet together with their federation
    /// stock state.
    ListOffers,
    /// Upload additional single-use preimages for an existing offer.
    AddStock { offer_index: u64, count: u64 },
    /// Scan offer indices `0..max_index` on the federation to recover offers
    /// created before a restore or across index gaps.
    RescanOffers {
        #[arg(long, default_value_t = DEFAULT_RESCAN_MAX_INDEX)]
        max_index: u64,
    },
    /// Cast this guardian's admin vote to approve a gateway reservation key for
    /// federated BOLT12.
    ApproveGateway { gateway_key: PublicKey },
    /// Cast this guardian's admin vote to revoke approval of a gateway
    /// reservation key for federated BOLT12.
    RevokeGateway { gateway_key: PublicKey },
    /// Check whether a gateway reservation key currently has quorum approval.
    GatewayApproved { gateway_key: PublicKey },
}

#[derive(Serialize)]
struct Bolt12StatusOutput {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_key: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    registration_fee: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stock_item_fee: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    receive_fee: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pool_fee: Option<Amount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pool_target: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pool_batch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pool_available: Option<u64>,
}

#[derive(Serialize)]
struct Bolt12GatewayInfo {
    gateway: SafeUrl,
    gateway_key: PublicKey,
    receive_fee: PaymentFee,
    approved: bool,
    message_path: String,
}

#[derive(Serialize)]
struct Bolt12OfferSummary {
    index: u64,
    registration: RegistrationId,
    offer: Option<String>,
    state: Option<Registration>,
}

#[derive(Serialize)]
struct Bolt12CreatedOfferOutput {
    index: u64,
    registration: RegistrationId,
    offer: String,
    expires_at: u64,
    stock: u64,
    allow_pool: bool,
    max_gateway_fee: PaymentFee,
    gateways_used: usize,
}

#[derive(Serialize)]
struct Bolt12RescanOutput {
    discovered: u64,
    max_index: u64,
}

#[derive(Serialize)]
struct Bolt12GatewayVoteOutput {
    gateway_key: PublicKey,
    approve: bool,
}

#[derive(Serialize)]
struct Bolt12GatewayApprovedOutput {
    gateway_key: PublicKey,
    approved: bool,
}

async fn count_pool_items(lightning: &LightningClientModule) -> Result<u64, FederationError> {
    let mut min_index = 0u64;
    let mut count = 0u64;
    let max_pages =
        (usize::try_from(MAX_POOL_TARGET).unwrap_or(usize::MAX) / POOL_ITEMS_PAGE_SIZE) + 2;

    for _ in 0..max_pages {
        let page = lightning.module_api.bolt12_pool_items(min_index).await?;
        let page_len = page.len();
        count += page_len as u64;

        let Some((last_index, _)) = page.last() else {
            break;
        };

        if page_len < POOL_ITEMS_PAGE_SIZE {
            break;
        }

        let Some(next_index) = last_index.checked_add(1) else {
            break;
        };
        min_index = next_index;
    }

    Ok(count)
}

async fn bolt12_status(
    lightning: &LightningClientModule,
) -> Result<Bolt12StatusOutput, FederationError> {
    if let Some(cfg) = lightning.lightning_config().bolt12.as_ref() {
        let pool_available = if cfg.pool_target > 0 {
            count_pool_items(lightning).await?
        } else {
            0
        };

        Ok(Bolt12StatusOutput {
            enabled: true,
            signing_key: Some(cfg.signing_key),
            registration_fee: Some(cfg.registration_fee),
            stock_item_fee: Some(cfg.stock_item_fee),
            receive_fee: Some(cfg.receive_fee),
            pool_fee: Some(cfg.pool_fee),
            pool_target: Some(cfg.pool_target),
            pool_batch: Some(cfg.pool_batch),
            pool_available: Some(pool_available),
        })
    } else {
        Ok(Bolt12StatusOutput {
            enabled: false,
            signing_key: None,
            registration_fee: None,
            stock_item_fee: None,
            receive_fee: None,
            pool_fee: None,
            pool_target: None,
            pool_batch: None,
            pool_available: None,
        })
    }
}

async fn bolt12_gateways(
    lightning: &LightningClientModule,
    gateways: Vec<SafeUrl>,
    include_unapproved: bool,
) -> Result<Vec<Bolt12GatewayInfo>, CliCommandError> {
    let urls = if gateways.is_empty() {
        lightning.list_gateways(None).await?
    } else {
        gateways
    };

    let mut results = Vec::new();
    for url in urls {
        let Ok(Some(ingress)) = lightning
            .gateway_conn
            .bolt12_ingress(url.clone(), lightning.federation_id)
            .await
        else {
            continue;
        };

        if !ingress.verify(lightning.federation_id) || ingress.message_path().is_err() {
            continue;
        }

        let approved = lightning
            .module_api
            .bolt12_gateway_approved(ingress.gateway_key)
            .await?;

        if approved || include_unapproved {
            results.push(Bolt12GatewayInfo {
                gateway: url,
                gateway_key: ingress.gateway_key,
                receive_fee: ingress.receive_fee,
                approved,
                message_path: ingress.message_path,
            });
        }
    }

    Ok(results)
}

async fn bolt12_create_offer(
    lightning: &LightningClientModule,
    description: String,
    stock: u64,
    expiry_secs: u64,
    allow_pool: bool,
    gateways: Vec<SafeUrl>,
    max_gateway_fee: Option<PaymentFee>,
) -> Result<Bolt12CreatedOfferOutput, CliCommandError> {
    let urls = if gateways.is_empty() {
        lightning.list_gateways(None).await?
    } else {
        gateways
    };

    let usable = lightning.bolt12_gateways(&urls).await;
    if usable.is_empty() {
        return Err(CliCommandError::Bolt12(anyhow::anyhow!(
            "No approved federated BOLT12 gateways found"
        )));
    }

    let max_gateway_fee = max_gateway_fee.unwrap_or_else(|| {
        usable.iter().fold(
            PaymentFee {
                base: Amount::ZERO,
                parts_per_million: 0,
            },
            |acc, ingress| PaymentFee {
                base: acc.base.max(ingress.receive_fee.base),
                parts_per_million: acc
                    .parts_per_million
                    .max(ingress.receive_fee.parts_per_million),
            },
        )
    });

    let ingress = usable
        .iter()
        .map(fedimint_lnv2_common::gateway_api::Bolt12Ingress::message_path)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let gateways_used = ingress.len();

    let expires_at = duration_since_epoch().as_secs().saturating_add(expiry_secs);

    let (offer, record) = lightning
        .create_bolt12_offer(Bolt12OfferParams {
            ingress,
            description,
            expires_at,
            max_gateway_fee,
            stock,
            allow_pool,
        })
        .await?;

    Ok(Bolt12CreatedOfferOutput {
        index: record.index,
        registration: record.registration,
        offer: offer.to_string(),
        expires_at,
        stock,
        allow_pool,
        max_gateway_fee,
        gateways_used,
    })
}

async fn bolt12_list_offers(
    lightning: &LightningClientModule,
) -> Result<Vec<Bolt12OfferSummary>, CliCommandError> {
    let offers = lightning.bolt12_offers().await;
    let mut summaries = Vec::with_capacity(offers.len());

    for entry in offers {
        let state = lightning.bolt12_offer_state(entry.index).await?;
        summaries.push(Bolt12OfferSummary {
            index: entry.index,
            registration: entry.registration,
            offer: entry.offer,
            state,
        });
    }

    Ok(summaries)
}

async fn bolt12_set_gateway_vote(
    lightning: &LightningClientModule,
    gateway_key: PublicKey,
    approve: bool,
) -> Result<Bolt12GatewayVoteOutput, CliCommandError> {
    let auth = lightning
        .admin_auth
        .clone()
        .ok_or(CliCommandError::AdminAuthNotSet)?;

    lightning
        .module_api
        .bolt12_set_gateway_vote(auth, gateway_key, approve)
        .await?;

    Ok(Bolt12GatewayVoteOutput {
        gateway_key,
        approve,
    })
}

async fn handle_bolt12_command(
    lightning: &LightningClientModule,
    opts: Bolt12Opts,
) -> Result<serde_json::Value, CliCommandError> {
    let value = match opts {
        Bolt12Opts::Status => json(bolt12_status(lightning).await?),
        Bolt12Opts::Gateways {
            gateways,
            include_unapproved,
        } => json(bolt12_gateways(lightning, gateways, include_unapproved).await?),
        Bolt12Opts::CreateOffer {
            description,
            stock,
            expiry_secs,
            allow_pool,
            gateways,
            max_gateway_fee,
        } => json(
            bolt12_create_offer(
                lightning,
                description,
                stock,
                expiry_secs,
                allow_pool,
                gateways,
                max_gateway_fee,
            )
            .await?,
        ),
        Bolt12Opts::ListOffers => json(bolt12_list_offers(lightning).await?),
        Bolt12Opts::AddStock { offer_index, count } => {
            json(lightning.add_bolt12_stock(offer_index, count).await?)
        }
        Bolt12Opts::RescanOffers { max_index } => {
            let discovered = lightning.rescan_bolt12_offers_up_to(max_index).await?;
            json(Bolt12RescanOutput {
                discovered,
                max_index,
            })
        }
        Bolt12Opts::ApproveGateway { gateway_key } => {
            json(bolt12_set_gateway_vote(lightning, gateway_key, true).await?)
        }
        Bolt12Opts::RevokeGateway { gateway_key } => {
            json(bolt12_set_gateway_vote(lightning, gateway_key, false).await?)
        }
        Bolt12Opts::GatewayApproved { gateway_key } => {
            let approved = lightning
                .module_api
                .bolt12_gateway_approved(gateway_key)
                .await?;

            json(Bolt12GatewayApprovedOutput {
                gateway_key,
                approved,
            })
        }
    };

    Ok(value)
}

pub(crate) async fn handle_cli_command(
    lightning: &LightningClientModule,
    args: &[ffi::OsString],
) -> Result<serde_json::Value, CliCommandError> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("lnv2")).chain(args.iter()));

    let value = match opts {
        Opts::Send { gateway, invoice } => {
            json(lightning.send(invoice, gateway, Value::Null).await?)
        }
        Opts::AwaitSend { operation_id } => json(
            lightning
                .await_final_send_operation_state(operation_id)
                .await?,
        ),
        Opts::Receive { amount, gateway } => json(
            lightning
                .receive(
                    amount,
                    3600,
                    Bolt11InvoiceDescription::Direct(String::new()),
                    gateway,
                    Value::Null,
                )
                .await?,
        ),
        Opts::AwaitReceive { operation_id } => json(
            lightning
                .await_final_receive_operation_state(operation_id)
                .await?,
        ),
        Opts::Lnurl(lnurl_opts) => match lnurl_opts {
            LnurlOpts::Generate {
                recurringd,
                gateway,
            } => json(lightning.generate_lnurl(recurringd, gateway).await?),
        },
        Opts::Gateways(gateway_opts) => match gateway_opts {
            #[allow(clippy::unit_arg)]
            GatewaysOpts::Map => json(lightning.update_gateway_map().await),
            GatewaysOpts::Select { invoice } => json(lightning.select_gateway(invoice).await?.0),
            GatewaysOpts::List { peer } => json(lightning.list_gateways(peer).await?),
            GatewaysOpts::Add { gateway } => {
                let auth = lightning
                    .admin_auth
                    .clone()
                    .ok_or(CliCommandError::AdminAuthNotSet)?;

                json(lightning.module_api.add_gateway(auth, gateway).await?)
            }
            GatewaysOpts::Remove { gateway } => {
                let auth = lightning
                    .admin_auth
                    .clone()
                    .ok_or(CliCommandError::AdminAuthNotSet)?;

                json(lightning.module_api.remove_gateway(auth, gateway).await?)
            }
        },
        Opts::Bolt12(bolt12_opts) => handle_bolt12_command(lightning, bolt12_opts).await?,
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}

/// A failure of an `lnv2` module command.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CliCommandError {
    /// The payment could not be started.
    #[error(transparent)]
    Send(#[from] SendPaymentError),

    /// The operation to await could not be looked up.
    #[error(transparent)]
    OperationLookup(#[from] OperationLookupError),

    /// The invoice could not be created.
    #[error(transparent)]
    Receive(#[from] ReceiveError),

    /// The LNURL could not be generated.
    #[error(transparent)]
    GenerateLnurl(#[from] GenerateLnurlError),

    /// No gateway could be selected.
    #[error(transparent)]
    SelectGateway(#[from] SelectGatewayError),

    /// The vetted gateways could not be listed.
    #[error(transparent)]
    ListGateways(#[from] ListGatewaysError),

    /// The federation did not serve an admin request.
    #[error(transparent)]
    Federation(#[from] FederationError),

    /// A federated BOLT12 operation failed.
    #[error(transparent)]
    Bolt12(#[from] anyhow::Error),

    /// The client has no admin credentials, which adding or removing a vetted
    /// gateway needs.
    #[error("Admin auth not set")]
    AdminAuthNotSet,
}
