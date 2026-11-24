//! A federated BOLT12 payment over real Lightning: a payer's LDK node pays an
//! offer the federation issued, through a channel to the gateway's LDK node,
//! on a private regtest chain. The federation runs in-process.
//!
//! Needs a `bitcoind` binary, so it is ignored by default:
//!
//! ```sh
//! FM_TEST_BITCOIND=$(which bitcoind) cargo test -p fedimint-gateway-server \
//!     --test gatewayd-live-bolt12-tests -- --ignored --nocapture
//! ```

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr as _;
use std::sync::{Arc, Once};
use std::time::Duration;

use anyhow::{Context as _, Result, bail, ensure};
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::{Address, Network};
use bitcoincore_rpc::{Client, RpcApi as _};
use fedimint_api_client::api::FederationApiExt as _;
use fedimint_bip39::{Bip39RootSecretStrategy, Mnemonic};
use fedimint_client::ClientHandleArc;
use fedimint_client::secret::RootSecretStrategy as _;
use fedimint_client_module::module::ClientModule as _;
use fedimint_core::module::{AmountUnit, ApiAuth, ApiRequestErased};
use fedimint_core::secp256k1::PublicKey;
use fedimint_core::task::{TaskGroup, block_in_place, sleep};
use fedimint_core::time::duration_since_epoch;
use fedimint_core::util::{SafeUrl, backoff_util, retry};
use fedimint_core::{Amount, PeerId, sats};
use fedimint_dummy_client::{DummyClientInit, DummyClientModule};
use fedimint_dummy_server::DummyInit;
use fedimint_gateway_common::ChainSource;
use fedimint_gwv2_client::GatewayClientModuleV2;
use fedimint_lightning::ldk::{GatewayLdkClient, MnemonicSource};
use fedimint_lightning::{
    CreateInvoiceRequest, ILnRpcClient, InterceptPaymentResponse, InvoiceDescription,
    PaymentAction, Preimage, RouteHtlcStream,
};
use fedimint_lnv2_client::api::LightningFederationApi as _;
use fedimint_lnv2_client::bolt12::Bolt12OfferParams;
use fedimint_lnv2_client::{LightningClientInit, LightningClientModule};
use fedimint_lnv2_common::endpoint_constants::BOLT12_SET_GATEWAY_VOTE_ENDPOINT;
use fedimint_lnv2_common::gateway_api::PaymentFee;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use futures::StreamExt as _;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::payment::{PaymentKind, PaymentStatus};
use rand::rngs::OsRng;

const INVOICE_AMOUNT: Amount = Amount::from_sats(20_000);
const CHANNEL_SATS: u64 = 1_000_000;

fn enable_bolt12() {
    static ENABLE: Once = Once::new();

    ENABLE.call_once(|| {
        // SAFETY: runs once, before this test spawns any federation task that
        // reads the environment.
        unsafe { std::env::set_var("FM_ENABLE_FEDERATED_BOLT12", "1") };
    });
}

fn free_port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// A private regtest `bitcoind`, stopped when dropped.
struct Bitcoind {
    process: Child,
    rpc_port: u16,
    cookie: PathBuf,
}

impl Bitcoind {
    fn start(binary: &Path, dir: &Path) -> Result<Self> {
        let rpc_port = free_port()?;
        let datadir = dir.join("bitcoind");

        std::fs::create_dir_all(&datadir)?;

        let process = Command::new(binary)
            .args([
                "-regtest",
                "-server=1",
                "-listen=0",
                "-dnsseed=0",
                "-fallbackfee=0.0002",
                "-txindex=1",
                "-rpcworkqueue=256",
                "-rpcthreads=16",
                "-rpcbind=127.0.0.1",
                "-rpcallowip=127.0.0.1",
                &format!("-rpcport={rpc_port}"),
                &format!("-datadir={}", datadir.display()),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("cannot start bitcoind")?;

        Ok(Self {
            process,
            rpc_port,
            cookie: datadir.join("regtest/.cookie"),
        })
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }

    fn credentials(&self) -> Result<(String, String)> {
        let cookie = std::fs::read_to_string(&self.cookie)?;
        let (user, password) = cookie.trim().split_once(':').context("cookie format")?;

        Ok((user.to_string(), password.to_string()))
    }

    async fn client(&self, path: &str) -> Result<Client> {
        for _ in 0..300 {
            if let Ok((user, password)) = self.credentials() {
                let transport = bitcoincore_rpc::jsonrpc::simple_http::Builder::new()
                    .url(&format!("{}{path}", self.url()))?
                    .auth(user, Some(password))
                    .timeout(Duration::from_secs(120))
                    .build();
                let client = Client::from_jsonrpc(
                    bitcoincore_rpc::jsonrpc::Client::with_transport(transport),
                );

                if client.get_blockchain_info().is_ok() {
                    return Ok(client);
                }
            }

            sleep(Duration::from_millis(100)).await;
        }

        bail!("bitcoind did not start")
    }
}

impl Drop for Bitcoind {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Mine to a key nobody holds: blocks paying the wallet are slow to process.
fn mine(rpc: &Client, blocks: u64) -> Result<()> {
    let key = bitcoin::secp256k1::SecretKey::new(&mut rand::thread_rng());
    let address = Address::p2wpkh(
        &bitcoin::CompressedPublicKey(key.public_key(bitcoin::secp256k1::SECP256K1)),
        Network::Regtest,
    );

    rpc.generate_to_address(blocks, &address)
        .context("mining")?;

    Ok(())
}

fn send(rpc: &Client, address: &Address, sats: u64) -> Result<()> {
    rpc.send_to_address(
        address,
        bitcoin::Amount::from_sat(sats),
        None,
        None,
        None,
        None,
        None,
        None,
    )
    .context("sending")?;

    Ok(())
}

/// The payer: a plain LDK node, as any BOLT12 wallet would run.
fn payer_node(dir: &Path, bitcoind: &Bitcoind) -> Result<Arc<ldk_node::Node>> {
    let (user, password) = bitcoind.credentials()?;
    let mut builder = ldk_node::Builder::new();

    builder.set_network(Network::Regtest);
    builder.set_filesystem_logger(None, Some(ldk_node::logger::LogLevel::Debug));
    builder.set_storage_dir_path(dir.join("payer").display().to_string());
    builder
        .set_listening_addresses(vec![
            SocketAddress::from_str(&format!("127.0.0.1:{}", free_port()?))
                .map_err(|e| anyhow::anyhow!("address: {e:?}"))?,
        ])
        .map_err(|e| anyhow::anyhow!("listen: {e:?}"))?;
    builder.set_chain_source_bitcoind_rpc(
        "127.0.0.1".to_string(),
        bitcoind.rpc_port,
        user,
        password,
    );

    let node = Arc::new(builder.build()?);

    node.start()?;

    Ok(node)
}

fn fixtures() -> Fixtures {
    enable_bolt12();

    Fixtures::new_primary(DummyClientInit, DummyInit).with_module(
        LightningClientInit::default(),
        fedimint_lnv2_server::LightningInit,
    )
}

async fn approve(
    fed: &FederationTest,
    wallet: &ClientHandleArc,
    gateway_key: PublicKey,
) -> Result<()> {
    let module_id = wallet
        .get_first_instance(&LightningClientModule::kind())
        .context("lnv2 module")?;

    for peer in (0..3).map(PeerId::from) {
        fed.new_admin_api(peer)
            .await?
            .with_module(module_id)
            .request_admin::<()>(
                BOLT12_SET_GATEWAY_VOTE_ENDPOINT,
                ApiRequestErased::new((gateway_key, true)),
                ApiAuth::new("pass".to_string()),
            )
            .await?;
    }

    let api = wallet.get_first_module::<LightningClientModule>()?.api;

    retry(
        "gateway approval",
        backoff_util::aggressive_backoff(),
        || async {
            ensure!(
                api.bolt12_gateway_approved(gateway_key).await?,
                "not approved yet"
            );

            Ok(())
        },
    )
    .await
}

async fn fund(client: &ClientHandleArc, amount: Amount) -> Result<()> {
    client
        .get_first_module::<DummyClientModule>()?
        .mock_receive(amount, AmountUnit::BITCOIN)
        .await;

    Ok(())
}

/// The gateway's own LDK node, exactly as gatewayd builds it, so it can be
/// started again from the same directory and seed.
struct GatewayNode {
    dir: PathBuf,
    chain_source: ChainSource,
    port: u16,
    mnemonic: Mnemonic,
    runtime: Arc<tokio::runtime::Runtime>,
}

impl GatewayNode {
    async fn start(
        &self,
        task_group: &TaskGroup,
    ) -> Result<(RouteHtlcStream<'static>, Arc<dyn ILnRpcClient>)> {
        let client = GatewayLdkClient::new(
            &self.dir,
            self.chain_source.clone(),
            Network::Regtest,
            self.port,
            "federated bolt12 gateway".to_string(),
            self.mnemonic.clone(),
            MnemonicSource::Generated,
            self.runtime.clone(),
        )?;

        Ok(Box::new(client).route_htlcs(task_group).await?)
    }
}

/// A regtest bitcoind with a payer node and the gateway's node, joined by a
/// usable channel from the payer, both at the chain tip.
struct LiveNetwork {
    /// Kept if a test fails so the nodes' logs can be read.
    run_dir: PathBuf,
    bitcoind: Bitcoind,
    payer: Arc<ldk_node::Node>,
    gateway_node: GatewayNode,
    task_group: TaskGroup,
    htlcs: RouteHtlcStream<'static>,
    lnrpc: Arc<dyn ILnRpcClient>,
}

impl LiveNetwork {
    async fn start() -> Result<Self> {
        let binary = PathBuf::from(
            std::env::var("FM_TEST_BITCOIND")
                .context("set FM_TEST_BITCOIND to a bitcoind binary")?,
        );
        // Kept if the test fails so the nodes' logs can be read.
        let run_dir = tempfile::Builder::new()
            .prefix("fedimint-live-bolt12-")
            .tempdir()?
            .keep();

        println!("run directory: {}", run_dir.display());

        let dir = run_dir.as_path();
        let bitcoind = Bitcoind::start(&binary, dir)?;

        bitcoind
            .client("")
            .await?
            .create_wallet("miner", None, None, None, None)
            .context("creating the miner wallet")?;

        let miner = bitcoind.client("/wallet/miner").await?;

        // One mature coinbase pays for everything.
        let coinbase = miner
            .get_new_address(None, None)
            .context("new address")?
            .require_network(Network::Regtest)?;

        miner
            .generate_to_address(1, &coinbase)
            .context("mining the coinbase")?;
        mine(&miner, 100)?;

        // The gateway's own LDK node, exactly as gatewayd builds it.
        let (user, password) = bitcoind.credentials()?;
        let gateway_port = free_port()?;
        // LDK needs a runtime it owns; it lives as long as the test process.
        let ldk_runtime = Arc::new(tokio::runtime::Runtime::new()?);
        let gateway_node = GatewayNode {
            dir: dir.join("gateway-ldk"),
            chain_source: ChainSource::Bitcoind {
                username: user,
                password,
                server_url: SafeUrl::parse(&bitcoind.url())?,
            },
            port: gateway_port,
            mnemonic: Bip39RootSecretStrategy::<12>::random(&mut OsRng),
            runtime: ldk_runtime.clone(),
        };
        std::mem::forget(ldk_runtime);

        let task_group = TaskGroup::new();
        let (htlcs, lnrpc) = gateway_node.start(&task_group).await?;
        let gateway_node_id = lnrpc.info().await?.pub_key;

        let payer = payer_node(dir, &bitcoind)?;

        // Both nodes need coins: the payer to open the channel, the gateway to
        // keep the reserve LDK requires for accepting anchor channels.
        send(
            &miner,
            &payer.onchain_payment().new_address()?,
            2 * CHANNEL_SATS,
        )?;
        send(
            &miner,
            &Address::from_str(&lnrpc.get_ln_onchain_address().await?.address)?
                .require_network(Network::Regtest)?,
            100_000,
        )?;
        mine(&miner, 6)?;

        retry(
            "onchain funds",
            backoff_util::aggressive_backoff_long(),
            || async {
                block_in_place(|| payer.sync_wallets())?;
                lnrpc.sync_wallet()?;

                ensure!(
                    payer.list_balances().spendable_onchain_balance_sats >= CHANNEL_SATS,
                    "payer not funded yet"
                );

                Ok(())
            },
        )
        .await?;

        payer.open_channel(
            gateway_node_id,
            SocketAddress::from_str(&format!("127.0.0.1:{gateway_port}"))
                .map_err(|e| anyhow::anyhow!("address: {e:?}"))?,
            CHANNEL_SATS,
            None,
            None,
        )?;

        retry(
            "usable channel",
            backoff_util::aggressive_backoff_long(),
            || async {
                mine(&miner, 1)?;
                block_in_place(|| payer.sync_wallets())?;
                lnrpc.sync_wallet()?;

                ensure!(
                    payer
                        .list_channels()
                        .iter()
                        .any(|channel| channel.is_usable),
                    "channel not usable yet"
                );

                Ok(())
            },
        )
        .await?;

        // The payer sets its HTLC's expiry from its own view of the chain, and
        // the gateway checks it against its own; both must be at the tip, or the
        // gateway sees too little time left and fails the payment.
        retry(
            "nodes at the chain tip",
            backoff_util::aggressive_backoff_long(),
            || async {
                block_in_place(|| payer.sync_wallets())?;
                lnrpc.sync_wallet()?;

                let tip = u32::try_from(block_in_place(|| miner.get_block_count())?)?;
                let payer_height = payer.status().current_best_block.height;
                let gateway_height = lnrpc.info().await?.block_height;

                ensure!(
                    payer_height == tip && gateway_height == tip,
                    "tip {tip}, payer {payer_height}, gateway {gateway_height}"
                );

                Ok(())
            },
        )
        .await?;

        Ok(Self {
            run_dir,
            bitcoind,
            payer,
            gateway_node,
            task_group,
            htlcs,
            lnrpc,
        })
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs FM_TEST_BITCOIND"]
async fn payer_pays_a_federated_offer_over_lightning() -> Result<()> {
    // Logging starts with the fixtures, so create them first.
    let fixtures = fixtures();
    let LiveNetwork {
        run_dir,
        bitcoind,
        payer,
        task_group,
        mut htlcs,
        lnrpc,
        ..
    } = LiveNetwork::start().await?;

    // The federation and a gateway backed by the LDK node.
    let fed = fixtures.new_fed_not_degraded().await;
    let gateway = fixtures.new_gateway_with_lightning(lnrpc.clone()).await;

    fed.connect_gateway(&gateway).await;

    let gateway_client = gateway.select_client(fed.id()).await?.into_value();
    let gateway_key = gateway_client
        .get_first_module::<GatewayClientModuleV2>()?
        .keypair
        .public_key();

    fund(&gateway_client, sats(100_000)).await?;

    let wallet = fed.new_client().await;

    fund(&wallet, sats(1_000)).await?;
    approve(&fed, &wallet, gateway_key).await?;

    // What gatewayd does once it is connected to its Lightning node.
    gateway.spawn_bolt12_request_handler(&task_group, lnrpc.clone());

    let lightning_context = gateway.get_lightning_context().await?;
    let htlc_gateway = gateway.clone();

    task_group.spawn_cancellable("held payments", async move {
        while let Some(htlc) = htlcs.next().await {
            htlc_gateway
                .handle_lightning_payment(htlc, &lightning_context)
                .await;
        }
    });

    // The wallet registers an offer reachable through the gateway.
    let ingress = gateway
        .bolt12_ingress_v2(&fed.id())
        .await?
        .context("the LDK gateway serves federated BOLT12 offers")?;
    let lightning = wallet.get_first_module::<LightningClientModule>()?;
    let params = Bolt12OfferParams {
        ingress: vec![ingress.message_path()?],
        description: "Federated offline receive".to_string(),
        expires_at: duration_since_epoch().as_secs() + 3_600,
        max_gateway_fee: PaymentFee::RECEIVE_FEE_LIMIT,
        stock: 4,
        allow_pool: false,
    };
    let (offer, _) = retry(
        "offer registration",
        backoff_util::aggressive_backoff(),
        || lightning.create_bolt12_offer(params.clone()),
    )
    .await?;

    let balance_before = wallet.get_balance_for_btc().await?;

    // The payer pays the offer like any other.
    let payment_id =
        payer
            .bolt12_payment()
            .send_using_amount(&offer, INVOICE_AMOUNT.msats, None, None, None)?;

    let preimage = await_payment(&payer, &payment_id).await?;

    println!("paid; preimage {}", sha256::Hash::hash(&preimage.0));

    // The recipient's wallet claims the receive.
    retry(
        "wallet claim",
        backoff_util::aggressive_backoff_long(),
        || async {
            let balance = wallet.get_balance_for_btc().await?;

            ensure!(
                balance >= balance_before + sats(19_000),
                "balance is {balance}"
            );

            Ok(())
        },
    )
    .await?;

    // Both nodes still answer requests for offers they issued themselves:
    // the payer has no external handler installed, and the gateway's handler
    // leaves offers without the federated routing prefix to its node.
    let payer_offer =
        payer
            .bolt12_payment()
            .receive(1_000_000, "the payer's own offer", None, None)?;

    lnrpc
        .pay_offer(payer_offer.to_string(), None, None, None)
        .await
        .map_err(|e| anyhow::anyhow!("gateway paying the payer's offer: {e:?}"))?;

    let gateway_offer: ldk_node::lightning::offers::offer::Offer = lnrpc
        .create_offer(
            Some(Amount::from_sats(1_000)),
            Some("the gateway's own offer".to_string()),
            None,
            None,
        )
        .map_err(|e| anyhow::anyhow!("gateway offer: {e:?}"))?
        .parse()
        .map_err(|e| anyhow::anyhow!("gateway offer: {e:?}"))?;

    let payment_id = payer
        .bolt12_payment()
        .send(&gateway_offer, None, None, None)?;

    await_payment(&payer, &payment_id).await?;

    task_group
        .shutdown_join_all(Duration::from_secs(10))
        .await?;
    let _ = payer.stop();

    drop(bitcoind);
    std::fs::remove_dir_all(&run_dir)?;

    Ok(())
}

/// Wait for an outgoing BOLT12 payment to succeed and return its preimage.
async fn await_payment(
    payer: &ldk_node::Node,
    payment_id: &ldk_node::lightning::ln::channelmanager::PaymentId,
) -> Result<ldk_node::lightning_types::payment::PaymentPreimage> {
    for _ in 0..600 {
        let payment = payer.payment(payment_id).context("unknown payment")?;

        match (payment.status, payment.kind) {
            (
                PaymentStatus::Succeeded,
                PaymentKind::Bolt12Offer {
                    hash: Some(hash),
                    preimage: Some(preimage),
                    ..
                },
            ) => {
                ensure!(sha256::Hash::hash(&preimage.0).to_byte_array() == hash.0);

                return Ok(preimage);
            }
            (PaymentStatus::Failed, _) => bail!("the payment failed"),
            _ => sleep(Duration::from_millis(100)).await,
        }
    }

    bail!("the payment did not complete")
}

/// A payment the gateway's node holds must reach the gateway again after a
/// restart until the gateway has resolved it.
///
/// LNv2's relay depends on this: funding a receive and starting the operation
/// that settles the held payment are separate steps, and a gateway that
/// crashed between them finishes the second step only when the payment is
/// delivered again (`IncomingRelayPlan::AddCompletion`). The LDK backend
/// marks `PaymentClaimable` handled as soon as it queues it in memory, and
/// LDK emits that event once, so after a restart the node keeps holding the
/// payment until it fails it back near its deadline, while the gateway never
/// hears of it again.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs FM_TEST_BITCOIND"]
async fn held_payment_is_redelivered_after_a_gateway_restart() -> Result<()> {
    let _fixtures = fixtures();
    let LiveNetwork {
        run_dir,
        bitcoind,
        payer,
        gateway_node,
        task_group,
        mut htlcs,
        lnrpc,
    } = LiveNetwork::start().await?;

    // An LNv2-style invoice for a hash whose preimage the gateway learns only
    // later, from the federation.
    let preimage: [u8; 32] = rand::random();
    let payment_hash = sha256::Hash::hash(&preimage);

    let invoice = lnrpc
        .create_invoice(CreateInvoiceRequest {
            payment_hash: Some(payment_hash),
            amount_msat: 50_000_000,
            expiry_secs: 3_600,
            description: Some(InvoiceDescription::Direct("held".to_string())),
        })
        .await
        .map_err(|e| anyhow::anyhow!("invoice: {e:?}"))?
        .invoice;

    let payment_id = payer.bolt11_payment().send(&invoice.parse()?, None)?;

    // The node delivers the held payment to the gateway once.
    let held = htlcs
        .next()
        .await
        .context("the payment reaches the gateway")?;

    ensure!(held.payment_hash == payment_hash);

    // The gateway crashes before resolving it.
    drop(htlcs);
    drop(lnrpc);
    task_group
        .shutdown_join_all(Duration::from_secs(10))
        .await?;

    // It restarts from the same directory and seed.
    let task_group = TaskGroup::new();
    let (mut htlcs, lnrpc) = gateway_node.start(&task_group).await?;

    let redelivered = fedimint_core::runtime::timeout(Duration::from_secs(60), htlcs.next())
        .await
        .ok()
        .flatten()
        .is_some_and(|htlc| htlc.payment_hash == payment_hash);

    // The node did still hold the payment: settling it by hand succeeds.
    lnrpc
        .complete_htlc(InterceptPaymentResponse {
            incoming_chan_id: held.incoming_chan_id,
            htlc_id: held.htlc_id,
            payment_hash,
            action: PaymentAction::Settle(Preimage(preimage)),
        })
        .await
        .map_err(|e| anyhow::anyhow!("settling: {e:?}"))?;

    retry(
        "payer sees the payment succeed",
        backoff_util::aggressive_backoff_long(),
        || async {
            ensure!(
                payer.payment(&payment_id).map(|p| p.status) == Some(PaymentStatus::Succeeded),
                "not settled yet"
            );

            Ok(())
        },
    )
    .await?;

    ensure!(
        redelivered,
        "the restarted gateway was never told about a payment its node still held"
    );

    drop(htlcs);
    drop(lnrpc);
    task_group
        .shutdown_join_all(Duration::from_secs(10))
        .await?;
    let _ = payer.stop();

    drop(bitcoind);
    std::fs::remove_dir_all(&run_dir)?;

    Ok(())
}
