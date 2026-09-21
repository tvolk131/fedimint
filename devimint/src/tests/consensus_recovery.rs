//! Reproduce watchdog/backoff recovery failure with all four guardians online.
//!
//! The RPC proxy simulates Bitcoin Core's pruned-block error; it does not prune
//! the shared devimint node. A test-only delay floor speeds up the default run;
//! `--natural-backoff` keeps the normal exponential schedule. Both use real
//! units, backups, replay, signatures, and process exits.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use fedimint_api_client::api::{DynGlobalApi, FederationApiExt};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::PeerId;
use fedimint_core::module::ApiRequestErased;
use fedimint_core::util::SafeUrl;
use fedimint_logging::LOG_DEVIMINT;
use fedimint_server::consensus::engine::{
    FM_TEST_FAST_CONSENSUS_BACKOFF, TEST_BACKOFF_DELAY_MS, TEST_BACKOFF_EXTRA_ROUNDS,
};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};
use tracing::info;

use crate::cli::{CommonArgs, cleanup_on_exit, setup};
use crate::external::Bitcoind;
use crate::federation::Federation;
use crate::util::ProcessManager;

const PEERS: [u16; 4] = [0, 1, 2, 3];
const WATCHDOG: Duration = Duration::from_secs(12);
const LONG_WATCHDOG: Duration = Duration::from_secs(86400);
const RECOVERY_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(clap::Args)]
pub struct Options {
    /// Build backoff over a 25-minute outage using the normal delay schedule
    /// instead of the accelerated test-only delay floor.
    #[arg(long)]
    natural_backoff: bool,
    /// Diagnostic mode: succeed only after proving three identical watchdog
    /// stalls and recovery when only the watchdog is increased. Without this
    /// flag, a reproduced watchdog stall fails the regression test.
    #[arg(long)]
    expect_watchdog_stall: bool,
}

async fn round_timing(fed: &Federation, peer: u16) -> Result<(u64, u64)> {
    let vars = &fed.vars[&usize::from(peer)];
    let local: Value = serde_json::from_str(
        &tokio::fs::read_to_string(vars.FM_DATA_DIR.join("local.json")).await?,
    )?;
    let consensus: Value = serde_json::from_str(
        &tokio::fs::read_to_string(vars.FM_DATA_DIR.join("consensus.json")).await?,
    )?;
    Ok((
        local["broadcast_round_delay_ms"]
            .as_u64()
            .context("Missing round delay")?,
        consensus["broadcast_rounds_per_session"]
            .as_u64()
            .context("Missing round cutoff")?,
    ))
}

async fn await_fast_backoff(
    fed: &Federation,
    process_mgr: &ProcessManager,
    offsets: &[usize],
) -> Result<()> {
    let mut targets = Vec::new();
    for peer in PEERS {
        let (_, cutoff) = round_timing(fed, peer).await?;
        targets.push(cutoff + TEST_BACKOFF_EXTRA_ROUNDS as u64);
    }
    timeout(Duration::from_secs(180), async {
        loop {
            let mut rounds = Vec::new();
            for (peer, offset) in PEERS.into_iter().zip(offsets) {
                let log = guardian_log(process_mgr, peer).await?;
                let log = log.get(*offset..).context("Guardian log was truncated")?;
                rounds.push(log.lines().rev().find_map(|line| {
                    if !line.contains("Created a new unit") { return None; }
                    line.split_once(" at round ")?.1.strip_suffix('.')?.parse::<u64>().ok()
                }));
            }
            if rounds.iter().zip(&targets).all(|(round, target)| round.is_some_and(|r| r >= *target)) {
                info!(target: LOG_DEVIMINT, ?rounds, "All guardians reached the accelerated backoff");
                return Ok::<_, anyhow::Error>(());
            }
            sleep(Duration::from_millis(250)).await;
        }
    }).await.context("Aleph did not reach the accelerated backoff before the warmup deadline")?
}

#[derive(Clone)]
struct BlockRpcProxy {
    upstream: String,
    client: reqwest::Client,
    blocked: Arc<AtomicBool>,
    denied: Arc<AtomicUsize>,
}

impl BlockRpcProxy {
    async fn request(
        State(proxy): State<Self>,
        Json(request): Json<Value>,
    ) -> Result<(StatusCode, Json<Value>), (StatusCode, String)> {
        let get_block = request["method"] == "getblock";
        if get_block && proxy.blocked.load(Ordering::SeqCst) {
            proxy.denied.fetch_add(1, Ordering::SeqCst);
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "result": null,
                    "error": {"code": -1, "message": "Block not available (pruned data)"},
                    "id": request["id"],
                })),
            ));
        }

        let response = proxy
            .client
            .post(&proxy.upstream)
            .basic_auth("bitcoin", Some("bitcoin"))
            .json(&request)
            .send()
            .await
            .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
        let status = response.status();
        let body: Value = response
            .json()
            .await
            .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
        Ok((status, Json(body)))
    }
}

/// Abort the local proxy even when a test assertion fails.
struct ProxyTask(JoinHandle<std::io::Result<()>>);

impl Drop for ProxyTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn request(api: &DynGlobalApi, peer: u16, method: &str, params: Value) -> Result<Value> {
    timeout(
        Duration::from_secs(5),
        api.request_single_peer(
            method.to_owned(),
            ApiRequestErased::new(params),
            PeerId::from(peer),
        ),
    )
    .await
    .with_context(|| format!("Guardian {peer} timed out calling {method}"))?
    .with_context(|| format!("Guardian {peer} failed calling {method}"))
}

async fn counts(api: &DynGlobalApi) -> Result<Vec<u64>> {
    let mut counts = Vec::new();
    for peer in PEERS {
        counts.push(
            request(api, peer, "session_count", Value::Null)
                .await?
                .as_u64()
                .context("session_count must be an integer")?,
        );
    }
    Ok(counts)
}

async fn guardian_log(process_mgr: &ProcessManager, peer: u16) -> Result<String> {
    Ok(tokio::fs::read_to_string(
        process_mgr
            .globals
            .FM_LOGS_DIR
            .join(format!("fedimintd-default-{peer}.log")),
    )
    .await?)
}

async fn await_progress(api: &DynGlobalApi, baseline: &[u64]) -> Result<()> {
    loop {
        if let Ok(current) = counts(api).await
            && current.iter().zip(baseline).all(|(a, b)| a > b)
        {
            return Ok(());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

/// Repeated watchdog exits must not be mistaken for an unresolved block fetch
/// or slow replay: every attempt must reach signing and verify matching
/// outcomes, yet create no new Aleph units. The control changes only the
/// watchdog timeout.
async fn watchdog_recovery(
    fed: &mut Federation,
    process_mgr: &ProcessManager,
    api: &DynGlobalApi,
    stalled_session: u64,
    options: &Options,
) -> Result<()> {
    let mut first_rounds = Vec::new();
    for attempt in 0..3 {
        let mut offsets = Vec::new();
        for peer in PEERS {
            offsets.push(guardian_log(process_mgr, peer).await?.len());
            fed.vars
                .get_mut(&usize::from(peer))
                .expect("Guardian exists")
                .FM_SESSION_TIMEOUT_SECS = Some(WATCHDOG.as_secs().to_string());
            fed.start_server(process_mgr, usize::from(peer)).await?;
        }

        // A fix may complete this session or extend the watchdog to permit it.
        // Allow either outcome within the recovery budget. On affected code,
        // all processes exit early and we verify the reason before restarting.
        let mut outcomes_matched = false;
        let recovered = timeout(RECOVERY_TIMEOUT, async {
            tokio::select! {
                result = async {
                    for peer in PEERS {
                        fed.await_server_terminated(usize::from(peer)).await?;
                    }
                    Ok::<_, anyhow::Error>(false)
                } => result,
                result = async {
                    loop {
                        if let Ok(current) = counts(api).await {
                            if current.iter().all(|count| *count > stalled_session) {
                                return Ok(true);
                            }
                            if !outcomes_matched && current.iter().all(|count| *count == stalled_session) {
                                // Compare the final pending outcomes, not just
                                // an identical prefix while replay is ongoing.
                                let mut all_signing = true;
                                for (peer, offset) in PEERS.into_iter().zip(&offsets) {
                                    let log = guardian_log(process_mgr, peer).await?;
                                    let log = log.get(*offset..).context("Guardian log was truncated")?;
                                    all_signing &= log.contains(&format!(
                                        "Signing session header... session_index={stalled_session}"
                                    ));
                                }
                                if all_signing {
                                    let mut outcomes = Vec::new();
                                    for peer in PEERS {
                                        if let Ok(outcome) = request(api, peer, "session_status", json!(stalled_session)).await {
                                            outcomes.push(outcome);
                                        }
                                    }
                                    outcomes_matched = outcomes.len() == PEERS.len()
                                        && outcomes.windows(2).all(|pair| pair[0] == pair[1]);
                                }
                            }
                        }
                        sleep(Duration::from_millis(100)).await;
                    }
                } => result,
            }
        })
        .await
        .context("Guardians neither recovered nor exited within the watchdog recovery budget")??;
        if recovered {
            info!(target: LOG_DEVIMINT, attempt, stalled_session,
                "Consensus recovered with the short watchdog");
            fed.terminate_all_servers().await?;
            ensure!(
                !options.expect_watchdog_stall,
                "Expected a watchdog stall, but consensus recovered"
            );
            return Ok(());
        }
        ensure!(
            outcomes_matched,
            "Outcomes did not match before the short watchdog"
        );

        let mut rounds = Vec::new();
        for (peer, offset) in PEERS.into_iter().zip(offsets) {
            let log = guardian_log(process_mgr, peer).await?;
            let log = log.get(offset..).context("Guardian log was truncated")?;
            ensure!(
                log.contains("Consensus session timed out, exiting..."),
                "Guardian {peer} did not exit because of the watchdog"
            );
            ensure!(
                log.contains(&format!(
                    "Signing session header... session_index={stalled_session}"
                )),
                "Guardian {peer} did not reach signing; timeout may be interrupting replay, not just backoff"
            );
            ensure!(
                !log.contains("Completed consensus session"),
                "Guardian {peer} completed consensus despite the short watchdog"
            );
            ensure!(
                !log.contains("Created a new unit"),
                "Guardian {peer} advanced Aleph; build a longer backoff before testing the watchdog"
            );
            ensure!(
                !log.contains("Consensus Failure"),
                "Guardian {peer} reported a consensus failure"
            );
            let round: u64 = log
                .lines()
                .find_map(|line| line.split_once("Creator starting from round "))
                .context("Missing Aleph creator log; enable AlephBFT-creator=trace")?
                .1
                .parse()?;
            let (base_ms, cutoff) = round_timing(fed, peer).await?;
            // Devimint adds 0.5..1.5 jitter. Even the smallest scheduled
            // delay must exceed the watchdog, not just one lucky sample.
            let mut nominal_delay_ms =
                base_ms as f64 * 1.02_f64.powf(round.saturating_sub(cutoff) as f64);
            if !options.natural_backoff {
                ensure!(
                    round >= cutoff + TEST_BACKOFF_EXTRA_ROUNDS as u64,
                    "Guardian {peer} did not persist the accelerated backoff round"
                );
                nominal_delay_ms = nominal_delay_ms.max(TEST_BACKOFF_DELAY_MS as f64);
            }
            let minimum_delay_ms = (nominal_delay_ms * 0.5).round();
            ensure!(
                minimum_delay_ms > WATCHDOG.as_millis() as f64,
                "Guardian {peer} backoff minimum {minimum_delay_ms}ms does not exceed watchdog"
            );
            rounds.push(round);
            info!(target: LOG_DEVIMINT, attempt, peer, round, minimum_delay_ms,
                watchdog_secs = WATCHDOG.as_secs(), "Guardian reached signing but watchdog prevented its next unit");
        }
        if attempt == 0 {
            first_rounds = rounds;
        } else {
            ensure!(
                rounds == first_rounds,
                "Saved rounds advanced between watchdog attempts"
            );
        }
    }

    for peer in PEERS {
        fed.vars
            .get_mut(&usize::from(peer))
            .expect("Guardian exists")
            .FM_SESSION_TIMEOUT_SECS = Some(LONG_WATCHDOG.as_secs().to_string());
        fed.start_server(process_mgr, usize::from(peer)).await?;
    }
    let started = Instant::now();
    timeout(
        RECOVERY_TIMEOUT,
        await_progress(api, &[stalled_session; PEERS.len()]),
    )
    .await
    .context(
        "Increasing only the watchdog did not restore consensus within the control budget",
    )??;
    info!(target: LOG_DEVIMINT, stalled_session, elapsed_ms = started.elapsed().as_millis(),
        "Same databases recovered after increasing only the session watchdog");
    fed.terminate_all_servers().await?;
    ensure!(
        options.expect_watchdog_stall,
        "Consensus failed to recover across three watchdog restarts at unchanged Aleph rounds; \
         every guardian reached signing without creating another unit, and increasing only \
         the watchdog restored progress (session {stalled_session})"
    );
    Ok(())
}

pub(super) async fn run(common_args: CommonArgs, options: Options) -> Result<()> {
    ensure!(
        common_args.fed_size == PEERS.len() && common_args.offline_nodes == 0,
        "This test requires all four guardians online"
    );

    // Configure child processes before starting the test environment.
    unsafe {
        std::env::set_var(
            FM_TEST_FAST_CONSENSUS_BACKOFF,
            if options.natural_backoff { "0" } else { "1" },
        );
        std::env::set_var("FM_ENABLE_MODULE_WALLET", "1");
        std::env::set_var("FM_ENABLE_MODULE_WALLETV2", "0");
        std::env::set_var("FM_ENABLE_MODULE_MINT", "1");
        std::env::set_var("FM_ENABLE_MODULE_MINTV2", "0");
        std::env::set_var("FM_SESSION_TIMEOUT_SECS", WATCHDOG.as_secs().to_string());
        let log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned());
        std::env::set_var(
            "RUST_LOG",
            format!("{log},fm::consensus=info,AlephBFT-creator=trace,AlephBFT-backup-loader=debug"),
        );
    }
    let (process_mgr, task_group) = setup(common_args).await?;
    cleanup_on_exit(
        async {
            let bitcoind = Bitcoind::new(&process_mgr, false).await?;
            let mut fed = Federation::new(
                &process_mgr, bitcoind.clone(), false, false, false, 0, "default".to_owned(),
            ).await?;
            fed.await_block_sync().await?;
            let api = DynGlobalApi::new(
                ConnectorRegistry::build_from_testing_env().bind().await,
                fed.vars.iter().map(|(&peer, vars)| {
                    Ok((PeerId::from(peer as u16), SafeUrl::parse(&vars.FM_API_URL)?))
                }).collect::<Result<BTreeMap<_, _>>>()?,
                process_mgr.globals.FM_API_SECRET.as_deref(),
            );

            // A short timeout must not fail simply because healthy sessions
            // cannot complete within it.
            let baseline = counts(&api).await?;
            timeout(Duration::from_secs(90), await_progress(&api, &baseline)).await
                .context("Healthy federation failed with the short watchdog")??;
            info!(target: LOG_DEVIMINT, watchdog_secs = WATCHDOG.as_secs(),
                "Healthy four-guardian federation completed a session with the short watchdog");

            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let proxy_port = listener.local_addr()?.port();
            let proxy = BlockRpcProxy {
                upstream: format!("http://127.0.0.1:{}", process_mgr.globals.FM_PORT_BTC_RPC),
                client: reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?,
                blocked: Arc::new(AtomicBool::new(false)),
                denied: Arc::new(AtomicUsize::new(0)),
            };
            let app = Router::new().route("/", post(BlockRpcProxy::request)).with_state(proxy.clone());
            let _proxy_task = ProxyTask(tokio::spawn(async move { axum::serve(listener, app).await }));

            // All guardians use the same proxy. None is taken offline to
            // deprive the others of a signature: all four will be unable to
            // process the new block while their Aleph networking keeps running.
            fed.terminate_all_servers().await?;
            for vars in fed.vars.values_mut() {
                vars.FM_FORCE_BITCOIN_RPC_URL = format!("http://bitcoin:bitcoin@127.0.0.1:{proxy_port}");
                vars.FM_BITCOIND_URL = format!("http://127.0.0.1:{proxy_port}");
                vars.FM_SESSION_TIMEOUT_SECS = Some(LONG_WATCHDOG.as_secs().to_string());
            }
            fed.start_all_servers(&process_mgr).await?;
            for peer in PEERS {
                fed.await_peer(usize::from(peer)).await?;
            }
            let baseline = counts(&api).await?;
            timeout(Duration::from_secs(90), await_progress(&api, &baseline)).await
                .context("Guardians did not make progress through the unblocked RPC proxy")??;

            let mut offsets = Vec::new();
            for peer in PEERS {
                offsets.push(guardian_log(&process_mgr, peer).await?.len());
            }
            proxy.blocked.store(true, Ordering::SeqCst);
            bitcoind.mine_blocks(1).await?;
            timeout(Duration::from_secs(60), async {
                while proxy.denied.load(Ordering::SeqCst) == 0 {
                    sleep(Duration::from_millis(100)).await;
                }
            }).await.context("Guardians never requested the simulated pruned block")?;
            let stalled_session = counts(&api).await?[0];
            info!(target: LOG_DEVIMINT, stalled_session, natural_backoff = options.natural_backoff,
                "Blocked Bitcoin block reads for all four guardians; allowing Aleph rounds to advance");

            // A long watchdog during setup isolates the trapping condition.
            // This does not test reaching it with an unchanged watchdog.
            if options.natural_backoff {
                sleep(Duration::from_secs(1500)).await;
            } else {
                await_fast_backoff(&fed, &process_mgr, &offsets).await?;
            }
            let blocked_counts = counts(&api).await?;
            ensure!(
                blocked_counts.iter().all(|count| *count == stalled_session),
                "Expected all four guardians stalled in session {stalled_session}, got {blocked_counts:?}"
            );

            fed.terminate_all_servers().await?;
            // Repair Bitcoin access before restart to exclude a remaining RPC
            // retry delay. Only the watchdog changes between recovery attempts.
            proxy.blocked.store(false, Ordering::SeqCst);
            watchdog_recovery(&mut fed, &process_mgr, &api, stalled_session, &options).await
        },
        task_group,
    ).await
}
