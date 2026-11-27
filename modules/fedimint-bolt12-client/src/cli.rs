use std::ffi;

use clap::Parser;
use fedimint_bolt12_common::bolt12::{MAX_POOL_TARGET, Registration, RegistrationId};
use fedimint_bolt12_common::gateway_api::PaymentFee;
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::SafeUrl;
use fedimint_core::{Amount, PeerId};
use serde::Serialize;
use serde_json::Value;

use crate::Bolt12ClientModule;
use crate::api::Bolt12FederationApi;
use crate::bolt12::Bolt12OfferParams;

#[cfg(test)]
mod tests;

const DEFAULT_OFFER_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_OFFER_STOCK: u64 = 8;
const DEFAULT_RESCAN_MAX_INDEX: u64 = 100;
const POOL_ITEMS_PAGE_SIZE: usize = 32;

#[derive(Parser, Serialize)]
enum Opts {
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
    /// Register a vetted gateway URL on this guardian (admin).
    AddGateway { gateway: SafeUrl },
    /// Remove a vetted gateway URL on this guardian (admin).
    RemoveGateway { gateway: SafeUrl },
    /// List vetted gateway URLs for this federation (optionally for one peer).
    ListGatewayUrls { peer: Option<PeerId> },
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
    /// federated BOLT12 (optionally also vetting its API URL).
    ApproveGateway {
        gateway_key: PublicKey,
        /// Optional gateway API URL to also register as a vetted gateway on
        /// this guardian.
        #[arg(long)]
        url: Option<SafeUrl>,
    },
    /// Cast this guardian's admin vote to revoke approval of a gateway
    /// reservation key for federated BOLT12.
    RevokeGateway { gateway_key: PublicKey },
    /// Check whether a gateway reservation key currently has quorum approval.
    GatewayApproved { gateway_key: PublicKey },
}

#[derive(Serialize)]
struct Bolt12StatusOutput {
    enabled: bool,
    signing_key: PublicKey,
    registration_fee: Amount,
    stock_item_fee: Amount,
    receive_fee: Amount,
    pool_fee: Amount,
    pool_target: u64,
    pool_batch: u64,
    pool_available: u64,
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

#[allow(clippy::too_many_lines)]
pub(crate) async fn handle_cli_command(
    bolt12: &Bolt12ClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<Value> {
    let opts = Opts::parse_from(std::iter::once(&ffi::OsString::from("bolt12")).chain(args.iter()));

    match opts {
        Opts::Status => handle_status(bolt12).await,
        Opts::Gateways {
            gateways,
            include_unapproved,
        } => handle_gateways(bolt12, gateways, include_unapproved).await,
        Opts::AddGateway { gateway } => {
            Ok(serde_json::to_value(bolt12.add_gateway(gateway).await?)?)
        }
        Opts::RemoveGateway { gateway } => {
            Ok(serde_json::to_value(bolt12.remove_gateway(gateway).await?)?)
        }
        Opts::ListGatewayUrls { peer } => match peer {
            Some(peer) => Ok(serde_json::to_value(
                bolt12.gateways_from_peer(peer).await?,
            )?),
            None => Ok(serde_json::to_value(bolt12.vetted_gateways().await?)?),
        },
        Opts::CreateOffer {
            description,
            stock,
            expiry_secs,
            allow_pool,
            gateways,
            max_gateway_fee,
        } => {
            handle_create_offer(
                bolt12,
                description,
                stock,
                expiry_secs,
                allow_pool,
                gateways,
                max_gateway_fee,
            )
            .await
        }
        Opts::ListOffers => handle_list_offers(bolt12).await,
        Opts::AddStock { offer_index, count } => {
            let registration = bolt12.add_bolt12_stock(offer_index, count).await?;
            Ok(serde_json::json!({
                "index": offer_index,
                "added": count,
                "state": registration,
            }))
        }
        Opts::RescanOffers { max_index } => {
            let recovered = bolt12.rescan_bolt12_offers_up_to(max_index).await?;
            Ok(serde_json::json!({
                "max_index": max_index,
                "recovered": recovered,
            }))
        }
        Opts::ApproveGateway { gateway_key, url } => {
            let auth = bolt12
                .admin_auth
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Admin auth not set"))?;
            if let Some(ref gateway_url) = url {
                bolt12.add_gateway(gateway_url.clone()).await?;
            }
            bolt12
                .module_api
                .bolt12_set_gateway_vote(auth, gateway_key, true)
                .await?;
            let approved = bolt12
                .module_api
                .bolt12_gateway_approved(gateway_key)
                .await?;
            Ok(serde_json::json!({
                "gateway_key": gateway_key,
                "url": url,
                "vote": true,
                "approved": approved,
            }))
        }
        Opts::RevokeGateway { gateway_key } => {
            let auth = bolt12
                .admin_auth
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Admin auth not set"))?;
            bolt12
                .module_api
                .bolt12_set_gateway_vote(auth, gateway_key, false)
                .await?;
            let approved = bolt12
                .module_api
                .bolt12_gateway_approved(gateway_key)
                .await?;
            Ok(serde_json::json!({
                "gateway_key": gateway_key,
                "vote": false,
                "approved": approved,
            }))
        }
        Opts::GatewayApproved { gateway_key } => {
            let approved = bolt12
                .module_api
                .bolt12_gateway_approved(gateway_key)
                .await?;
            Ok(serde_json::json!({
                "gateway_key": gateway_key,
                "approved": approved,
            }))
        }
    }
}

async fn count_pool_items(bolt12: &Bolt12ClientModule) -> anyhow::Result<u64> {
    let max_pages = (MAX_POOL_TARGET / POOL_ITEMS_PAGE_SIZE as u64).saturating_add(4);
    let mut min_index = 0u64;
    let mut total = 0u64;

    for _ in 0..max_pages {
        let page = bolt12.module_api.bolt12_pool_items(min_index).await?;
        let page_len = page.len();
        total = total.saturating_add(page_len as u64);

        let Some((last_idx, _)) = page.last() else {
            break;
        };

        if page_len < POOL_ITEMS_PAGE_SIZE {
            break;
        }

        min_index = last_idx.saturating_add(1);
    }

    Ok(total)
}

async fn handle_status(bolt12: &Bolt12ClientModule) -> anyhow::Result<Value> {
    let cfg = &bolt12.cfg.bolt12;
    let pool_available = count_pool_items(bolt12).await?;

    Ok(serde_json::to_value(Bolt12StatusOutput {
        enabled: true,
        signing_key: cfg.signing_key,
        registration_fee: cfg.registration_fee,
        stock_item_fee: cfg.stock_item_fee,
        receive_fee: cfg.receive_fee,
        pool_fee: cfg.pool_fee,
        pool_target: cfg.pool_target,
        pool_batch: cfg.pool_batch,
        pool_available,
    })?)
}

async fn resolve_gateway_urls(
    bolt12: &Bolt12ClientModule,
    gateways: Vec<SafeUrl>,
) -> anyhow::Result<Vec<SafeUrl>> {
    if !gateways.is_empty() {
        return Ok(gateways);
    }

    let vetted = bolt12.vetted_gateways().await?;
    anyhow::ensure!(
        !vetted.is_empty(),
        "No vetted gateways registered for bolt12; pass --gateway <url> explicitly or run add-gateway"
    );

    Ok(vetted)
}

async fn handle_gateways(
    bolt12: &Bolt12ClientModule,
    gateways: Vec<SafeUrl>,
    include_unapproved: bool,
) -> anyhow::Result<Value> {
    let urls = resolve_gateway_urls(bolt12, gateways).await?;
    let federation_id = bolt12
        .client_ctx
        .get_config()
        .await
        .calculate_federation_id();

    let mut rows = Vec::new();
    for url in urls {
        let Ok(Some(ingress)) = bolt12
            .gateway_conn
            .bolt12_ingress(url.clone(), federation_id)
            .await
        else {
            continue;
        };

        if !ingress.verify(federation_id) {
            continue;
        }

        let approved = bolt12
            .module_api
            .bolt12_gateway_approved(ingress.gateway_key)
            .await?;

        if approved || include_unapproved {
            rows.push(Bolt12GatewayInfo {
                gateway: url,
                gateway_key: ingress.gateway_key,
                receive_fee: ingress.receive_fee,
                approved,
                message_path: ingress.message_path,
            });
        }
    }

    Ok(serde_json::to_value(rows)?)
}

fn default_max_gateway_fee(fees: &[PaymentFee]) -> PaymentFee {
    fees.iter().fold(
        PaymentFee {
            base: Amount::ZERO,
            parts_per_million: 0,
        },
        |acc, fee| PaymentFee {
            base: acc.base.max(fee.base),
            parts_per_million: acc.parts_per_million.max(fee.parts_per_million),
        },
    )
}

#[allow(clippy::too_many_arguments)]
async fn handle_create_offer(
    bolt12: &Bolt12ClientModule,
    description: String,
    stock: u64,
    expiry_secs: u64,
    allow_pool: bool,
    gateways: Vec<SafeUrl>,
    max_gateway_fee: Option<PaymentFee>,
) -> anyhow::Result<Value> {
    let urls = resolve_gateway_urls(bolt12, gateways).await?;
    let approved_ingress = bolt12.bolt12_gateways(&urls).await;

    anyhow::ensure!(
        !approved_ingress.is_empty(),
        "No approved BOLT12 gateways found; approve a gateway reservation key first"
    );

    let mut paths = Vec::with_capacity(approved_ingress.len());
    let mut approved_fees = Vec::with_capacity(approved_ingress.len());
    for ingress in approved_ingress {
        paths.push(ingress.message_path()?);
        approved_fees.push(ingress.receive_fee);
    }

    let max_gateway_fee =
        max_gateway_fee.unwrap_or_else(|| default_max_gateway_fee(&approved_fees));
    let expires_at = duration_since_epoch()
        .as_secs()
        .checked_add(expiry_secs)
        .ok_or_else(|| anyhow::anyhow!("Offer expiry overflow"))?;

    let gateways_used = paths.len();
    let (offer, created) = bolt12
        .create_bolt12_offer(Bolt12OfferParams {
            ingress: paths,
            description,
            expires_at,
            max_gateway_fee,
            allow_pool,
            stock,
        })
        .await?;

    Ok(serde_json::to_value(Bolt12CreatedOfferOutput {
        index: created.index,
        registration: created.registration,
        offer: offer.to_string(),
        expires_at,
        stock,
        allow_pool,
        max_gateway_fee,
        gateways_used,
    })?)
}

async fn handle_list_offers(bolt12: &Bolt12ClientModule) -> anyhow::Result<Value> {
    let local = bolt12.bolt12_offers().await;
    let mut out = Vec::with_capacity(local.len());
    for entry in local {
        let state = bolt12.bolt12_offer_state(entry.index).await?;
        out.push(Bolt12OfferSummary {
            index: entry.index,
            registration: entry.registration,
            offer: entry.offer,
            state,
        });
    }

    Ok(serde_json::to_value(out)?)
}
