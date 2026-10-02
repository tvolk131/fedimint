//! A real four-guardian federation: TLS P2P, WebSocket API, Aleph consensus,
//! module initialization and RocksDB. Bitcoin RPC and funding are simulated;
//! exact ecash funding is covered by the separate transaction tests. Keep this
//! separate from fast contract-policy tests.
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use fedimint_api_client::api::{DynGlobalApi, FederationApiExt};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::envs::BitcoinRpcConfig;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::net::IP2PConnections;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::SafeUrl;
use fedimint_core::{ChainId, Feerate};
use fedimint_dummy_server::DummyInit;
use fedimint_rocksdb::RocksDb;
use fedimint_server::config::ServerConfig;
use fedimint_server::core::ServerModuleInitRegistry;
use fedimint_server::net::api::ApiSecrets;
use fedimint_server::net::p2p::{ReconnectP2PConnections, p2p_status_channels};
use fedimint_server::net::p2p_connector::{IP2PConnector, TlsTcpConnector};
use fedimint_server::{ConnectionLimits, consensus};
use fedimint_server_core::bitcoin_rpc::IServerBitcoinRpc;
use fedimint_simplicity_common::assets::AssetRecord;
use fedimint_testing_core::config::local_config_gen_params;
use tempfile::TempDir;

use super::*;
use crate::SimplicityInit;

mod wallet;

#[derive(Debug)]
struct Bitcoin;
#[async_trait::async_trait]
impl IServerBitcoinRpc for Bitcoin {
    fn get_bitcoin_rpc_config(&self) -> BitcoinRpcConfig {
        BitcoinRpcConfig {
            kind: "test".to_owned(),
            url: self.get_url(),
        }
    }
    fn get_url(&self) -> SafeUrl {
        "http://unused.invalid".parse().unwrap()
    }
    async fn get_block_count(&self) -> anyhow::Result<u64> {
        Ok(5)
    }
    async fn get_chain_id(&self) -> anyhow::Result<ChainId> {
        Ok(ChainId(bitcoin::BlockHash::all_zeros()))
    }
    async fn get_sync_progress(&self) -> anyhow::Result<Option<f64>> {
        Ok(Some(1.0))
    }
    async fn get_feerate(&self) -> anyhow::Result<Option<Feerate>> {
        Ok(Some(Feerate { sats_per_kvb: 1000 }))
    }
    async fn get_block_hash(&self, _: u64) -> anyhow::Result<bitcoin::BlockHash> {
        anyhow::bail!("not used by these modules")
    }
    async fn get_block(&self, _: &bitcoin::BlockHash) -> anyhow::Result<bitcoin::Block> {
        anyhow::bail!("not used by these modules")
    }
    async fn submit_transaction(&self, _: bitcoin::Transaction) -> anyhow::Result<()> {
        anyhow::bail!("not used by these modules")
    }
}

struct Federation {
    configs: BTreeMap<PeerId, ServerConfig>,
    guardians: BTreeMap<PeerId, Child>,
    directory: TempDir,
    port: u16,
    api: DynGlobalApi,
    decoders: ModuleDecoderRegistry,
    id: FederationId,
    simplicity: u16,
    dummy: u16,
    completed: bool,
}
impl Federation {
    async fn new() -> Self {
        fedimint_core::rustls::install_crypto_provider().await;
        let registry = registry();
        let peers: Vec<_> = (0..4).map(PeerId::from).collect();
        let port = fedimint_portalloc::port_alloc(12).unwrap();
        let params = local_config_gen_params(&peers, port, true, &registry).unwrap();
        let configs =
            ServerConfig::trusted_dealer_gen(&params, &registry, "simplicity-network-test");
        let first = &configs[&PeerId::from(0)];
        let simplicity = first
            .consensus
            .modules
            .iter()
            .find(|(_, cfg)| cfg.kind == fedimint_simplicity_common::KIND)
            .unwrap()
            .0
            .to_owned();
        let dummy = first
            .consensus
            .modules
            .iter()
            .find(|(_, cfg)| cfg.kind == fedimint_dummy_common::KIND)
            .unwrap()
            .0
            .to_owned();
        let decoders = registry.available_decoders(first.consensus.iter_module_instances());
        let api = DynGlobalApi::new(
            ConnectorRegistry::build_from_testing_env().bind().await,
            first
                .consensus
                .api_endpoints()
                .into_iter()
                .map(|(id, endpoint)| (id, endpoint.url))
                .collect(),
            None,
        );
        let mut fed = Self {
            id: first.calculate_federation_id(),
            configs,
            guardians: BTreeMap::new(),
            directory: tempfile::tempdir().unwrap(),
            port,
            api,
            decoders,
            simplicity,
            dummy,
            completed: false,
        };
        for peer in peers {
            fed.start(peer);
        }
        fed.wait_all_clock().await;
        fed
    }
    fn start(&mut self, peer: PeerId) {
        let path = self.directory.path().join(format!("peer-{peer}"));
        std::fs::create_dir_all(&path).unwrap();
        let config_path = path.join("config.json");
        std::fs::write(
            &config_path,
            serde_json::to_vec(&self.configs[&peer]).unwrap(),
        )
        .unwrap();
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.join("guardian.log"))
            .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::assets::network::four_guardians_submit_settle_and_recover_a_market_from_disk",
                "--nocapture",
            ])
            .env("FM_SIMPLICITY_TEST_GUARDIAN_CONFIG", config_path)
            .env("FM_SIMPLICITY_TEST_BASE_PORT", self.port.to_string())
            .env("FM_IN_DEVIMINT", "1")
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();
        self.guardians.insert(peer, child);
    }
    fn stop(&mut self, peer: PeerId) {
        let mut child = self.guardians.remove(&peer).unwrap();
        assert!(
            child.try_wait().unwrap().is_none(),
            "guardian exited prematurely"
        );
        // Kill without a graceful shutdown: reopening must recover committed
        // database writes and the interrupted Aleph session from disk.
        child.kill().unwrap();
        child.wait().unwrap();
    }
    async fn wait_all_clock(&self) {
        for peer in self.guardians.keys() {
            loop {
                let count: Result<u64, _> = self
                    .api
                    .with_module(self.simplicity)
                    .request_single_peer("block_count".to_owned(), ApiRequestErased::new(()), *peer)
                    .await;
                if matches!(count, Ok(5)) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    async fn submit(&self, tx: &Transaction) {
        let outcome = self
            .api
            .submit_transaction(tx.clone())
            .await
            .try_into_inner(&self.decoders)
            .unwrap();
        assert_eq!(outcome.0.unwrap(), tx.tx_hash());
        assert_eq!(self.api.await_transaction(tx.tx_hash()).await, tx.tx_hash());
    }
    async fn contract_on(&self, peer: PeerId, point: OutPoint) -> Option<StoredContract> {
        self.api
            .with_module(self.simplicity)
            .request_single_peer("contract".to_owned(), ApiRequestErased::new(point), peer)
            .await
            .unwrap()
    }
    async fn wait_contract(&self, point: OutPoint) -> StoredContract {
        for peer in self.guardians.keys() {
            let accepted: fedimint_core::TransactionId = self
                .api
                .request_single_peer(
                    fedimint_core::endpoint_constants::AWAIT_TRANSACTION_ENDPOINT.to_owned(),
                    ApiRequestErased::new(point.txid),
                    *peer,
                )
                .await
                .unwrap();
            assert_eq!(accepted, point.txid);
        }
        let expected = self.contract_on(PeerId::from(0), point).await.unwrap();
        for peer in self.guardians.keys() {
            assert_eq!(
                self.contract_on(*peer, point).await.as_ref(),
                Some(&expected)
            );
        }
        expected
    }
    fn output(&self, output: ContractOutput) -> DynOutput {
        DynOutput::from_typed(self.simplicity, output)
    }
    fn sponsored(&self, inputs: Vec<DynInput>, outputs: Vec<DynOutput>) -> (Transaction, Keypair) {
        let key = key();
        let mut tx = transaction(inputs, outputs);
        tx.inputs.push(DynInput::from_typed(
            self.dummy,
            DummyInput {
                amount: Amount::from_sats(1000),
                unit: AmountUnit::BITCOIN,
                pub_key: key.public_key(),
            },
        ));
        (tx, key)
    }
}
impl Drop for Federation {
    fn drop(&mut self) {
        for child in self.guardians.values_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // Timeout drops the fixture before the outer assertion panics.
        if !self.completed {
            for peer in self.configs.keys() {
                if let Ok(log) = std::fs::read_to_string(
                    self.directory
                        .path()
                        .join(format!("peer-{peer}/guardian.log")),
                ) {
                    eprintln!("guardian {peer}: {log}");
                }
            }
        }
    }
}

fn registry() -> ServerModuleInitRegistry {
    let mut registry = ServerModuleInitRegistry::default();
    registry.attach(fedimint_server_core::DynServerModuleInit::from(
        SimplicityInit,
    ));
    registry.attach(fedimint_server_core::DynServerModuleInit::from(DummyInit));
    registry
}

async fn run_guardian(config_path: std::path::PathBuf) {
    fedimint_core::rustls::install_crypto_provider().await;
    let cfg: ServerConfig = serde_json::from_slice(&std::fs::read(&config_path).unwrap()).unwrap();
    let base_port: u16 = std::env::var("FM_SIMPLICITY_TEST_BASE_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let port = base_port + u16::from(cfg.local.identity) * 3;
    let tasks = TaskGroup::new();
    let connector = TlsTcpConnector::new(
        cfg.tls_config(),
        format!("127.0.0.1:{port}").parse().unwrap(),
        cfg.local.p2p_endpoints.clone(),
        cfg.local.identity,
    )
    .await
    .into_dyn();
    let (senders, receivers) = p2p_status_channels(connector.peers());
    let connections =
        ReconnectP2PConnections::new(cfg.local.identity, connector, &tasks, senders, None)
            .into_dyn();
    let path = config_path.parent().unwrap().to_path_buf();
    let registry = registry();
    let decoders = registry.available_decoders(cfg.consensus.iter_module_instances());
    let db = Database::new(
        RocksDb::build(path.join("db")).open().await.unwrap(),
        decoders,
    );
    consensus::run(
        ConnectorRegistry::build_from_testing_env().bind().await,
        None,
        None,
        connections,
        receivers,
        format!("127.0.0.1:{}", port + 1).parse().unwrap(),
        None,
        vec![],
        cfg,
        db,
        registry,
        &tasks,
        ApiSecrets::default(),
        path,
        env!("CARGO_PKG_VERSION").to_owned(),
        "simplicity-network-test".to_owned(),
        Arc::new(Bitcoin),
        format!("127.0.0.1:{}", port + 2).parse().unwrap(),
        Box::new(|_| axum::Router::new()),
        1,
        Duration::from_secs(120),
        ConnectionLimits {
            max_connections: 1000,
            max_requests_per_connection: 100,
        },
        None,
    )
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_guardians_submit_settle_and_recover_a_market_from_disk() {
    let _ = fedimint_logging::TracingSetup::default().init();
    if let Some(config_path) = std::env::var_os("FM_SIMPLICITY_TEST_GUARDIAN_CONFIG") {
        run_guardian(config_path.into()).await;
        return;
    }
    // Bound startup, consensus, reconnect and catch-up failures rather than
    // leaving CI hanging inside retrying federation API methods.
    tokio::time::timeout(Duration::from_secs(180), network_market())
        .await
        .unwrap();
}

async fn network_market() {
    let mut fed = Federation::new().await;
    let creator = key();
    let oracle = key();
    let operator = key();
    let alice = key();
    let bob = key();
    let (creation, ids) = assets::creation(fed.id, fed.simplicity, &creator, vec![0, 0]).unwrap();
    let terms = market::BinaryMarket {
        federation: fed.id,
        module: fed.simplicity,
        yes: ids[0],
        no: ids[1],
        event: [7; 32],
        rules: [8; 32],
        oracle: oracle.x_only_public_key().0,
        resolution_start: 5,
        deadline: 10,
    };
    let program = terms.program().unwrap();
    let alice_program = market::owner_program(alice.x_only_public_key().0).unwrap();
    let bob_program = market::owner_program(bob.x_only_public_key().0).unwrap();
    let vault_output = |amount, state| {
        fed.output(
            program
                .asset_output(
                    Amount::from_msats(amount),
                    market::state(state).unwrap(),
                    vec![],
                    bundle(&[], &ids),
                )
                .unwrap(),
        )
    };
    let (mut genesis, sponsor) = fed.sponsored(
        vec![],
        vec![
            vault_output(0, 0),
            fed.output(
                assets::action_output(AssetActions {
                    creations: vec![creation],
                    ..Default::default()
                })
                .unwrap(),
            ),
        ],
    );
    assets::sign_creation(&mut genesis, fed.id, fed.simplicity, &creator).unwrap();
    sign_transaction(&mut genesis, &[sponsor]).unwrap();
    fed.submit(&genesis).await;
    let initial = fed.wait_contract(point(&genesis, 0)).await;
    assert_eq!(initial.creation_block_count, 5);
    let input = |point, action, state| {
        let signature = Value::byte_array(
            *SECP256K1
                .sign_schnorr_no_aux_rand(
                    &Message::from_digest(terms.attestation_message(1).unwrap()),
                    &oracle,
                )
                .as_ref(),
        );
        DynInput::from_typed(
            terms.module,
            program
                .input(
                    point,
                    operator.public_key(),
                    witnesses([
                        ("ACTION", Value::u8(action)),
                        ("OUTCOME", Value::u8(state)),
                        ("ORACLE_SIGNATURE", signature),
                    ]),
                )
                .unwrap(),
        )
    };
    let (mut issue, sponsor) = fed.sponsored(
        vec![input(point(&genesis, 0), 0, 1)],
        vec![
            vault_output(2000, 0),
            fed.output(
                alice_program
                    .asset_output(
                        Amount::ZERO,
                        [0; 32],
                        vec![],
                        bundle(&[(ids[0], 2), (ids[1], 2)], &[]),
                    )
                    .unwrap(),
            ),
            fed.output(
                assets::action_output(AssetActions {
                    issuance: values(&[(ids[0], 2), (ids[1], 2)]),
                    ..Default::default()
                })
                .unwrap(),
            ),
        ],
    );
    let issue_sponsor = sponsor;
    sign_transaction(&mut issue, &[operator, sponsor]).unwrap();
    fed.submit(&issue).await;
    fed.wait_contract(point(&issue, 0)).await;
    let owner_input = |program: &ContractProgram, point, owner: &Keypair, signature| {
        DynInput::from_typed(
            terms.module,
            program
                .input(
                    point,
                    owner.public_key(),
                    witnesses([("SIGNATURE", signature)]),
                )
                .unwrap(),
        )
    };
    let (mut trade, sponsor) = fed.sponsored(
        vec![owner_input(
            &alice_program,
            point(&issue, 1),
            &alice,
            placeholder_signature(),
        )],
        vec![
            fed.output(
                bob_program
                    .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[(ids[0], 2)], &[]))
                    .unwrap(),
            ),
            fed.output(
                alice_program
                    .asset_output(Amount::ZERO, [0; 32], vec![], bundle(&[(ids[1], 2)], &[]))
                    .unwrap(),
            ),
        ],
    );
    trade.inputs[0] = owner_input(
        &alice_program,
        point(&issue, 1),
        &alice,
        assets::signature_value(fed.id, fed.simplicity, &trade, &alice).unwrap(),
    );
    sign_transaction(&mut trade, &[alice, sponsor]).unwrap();
    fed.submit(&trade).await;
    fed.wait_contract(point(&trade, 0)).await;
    let (mut resolution, sponsor) = fed.sponsored(
        vec![input(point(&issue, 0), 2, 1)],
        vec![vault_output(2000, 1)],
    );
    sign_transaction(&mut resolution, &[operator, sponsor]).unwrap();
    // The remaining three guardians must make progress while one is down.
    fed.stop(PeerId::from(3));
    fed.submit(&resolution).await;
    let resolved = fed.wait_contract(point(&resolution, 0)).await;
    assert!(resolved.creation_session >= initial.creation_session);
    // Reopen the exact same RocksDB and catch up missed consensus history.
    fed.start(PeerId::from(3));
    fed.wait_all_clock().await;
    assert_eq!(fed.wait_contract(point(&resolution, 0)).await, resolved);
    for peer in fed.guardians.keys() {
        assert!(fed.contract_on(*peer, point(&issue, 0)).await.is_none());
        let mut records = vec![];
        for id in &ids {
            records.push(
                fed.api
                    .with_module(fed.simplicity)
                    .request_single_peer::<Option<AssetRecord>>(
                        "asset".to_owned(),
                        ApiRequestErased::new(*id),
                        *peer,
                    )
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        terms.validate_genesis(&records[0], &records[1]).unwrap();
    }
    let vault_output = fed.output(
        program
            .asset_output(
                Amount::ZERO,
                market::state(1).unwrap(),
                vec![],
                bundle(&[], &ids),
            )
            .unwrap(),
    );
    let (mut redeem, sponsor) = fed.sponsored(
        vec![
            input(point(&resolution, 0), 3, 1),
            owner_input(
                &bob_program,
                point(&trade, 0),
                &bob,
                placeholder_signature(),
            ),
        ],
        vec![
            vault_output,
            fed.output(
                bob_program
                    .asset_output(Amount::from_msats(2000), [0; 32], vec![], bundle(&[], &[]))
                    .unwrap(),
            ),
            fed.output(
                assets::action_output(AssetActions {
                    burns: values(&[(ids[0], 2)]),
                    ..Default::default()
                })
                .unwrap(),
            ),
        ],
    );
    redeem.inputs[1] = owner_input(
        &bob_program,
        point(&trade, 0),
        &bob,
        assets::signature_value(fed.id, fed.simplicity, &redeem, &bob).unwrap(),
    );
    sign_transaction(&mut redeem, &[operator, bob, sponsor]).unwrap();
    fed.submit(&redeem).await;
    assert_eq!(
        fed.wait_contract(point(&redeem, 0)).await.output.amount,
        Amount::ZERO
    );
    assert_eq!(
        fed.wait_contract(point(&redeem, 1)).await.output.amount,
        Amount::from_msats(2000)
    );
    // A different transaction cannot resurrect the spent vault after restart.
    let mut stale = issue.clone();
    stale.nonce = rand::random();
    sign_transaction(&mut stale, &[operator, issue_sponsor]).unwrap();
    let rejected = fed
        .api
        .submit_transaction(stale)
        .await
        .try_into_inner(&fed.decoders)
        .unwrap();
    assert!(format!("{}", rejected.0.unwrap_err()).contains("already spent"));
    for peer in (0..4).map(PeerId::from) {
        fed.stop(peer);
    }
    fed.completed = true;
}
