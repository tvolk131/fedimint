//! Read-only developer tooling. Preflight reads sensitive material on stdin;
//! it never opens a wallet or initializes networking.
use std::collections::BTreeMap;
use std::io::{self, Read as _};
use std::process::ExitCode;

use anyhow::{anyhow, ensure};
use clap::{Parser, Subcommand};
use fedimint_core::OutPoint;
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::encoding::Decodable as _;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::module::{CommonModuleInit as _, ModuleConsensusVersion};
use fedimint_core::transaction::Transaction;
use fedimint_simplicity_client::common::{self, SimplicityCommonInit, StoredContract};
use fedimint_simplicity_client::preflight;
use fedimint_simplicity_client::pruning::PruningSnapshot;
use serde::Deserialize;

#[cfg(test)]
#[path = "diagnostics/tests.rs"]
mod tests;

const MAX_REQUEST_BYTES: u64 = 1_048_576;

#[derive(Parser)]
#[command(about = "Local Simplicity diagnostics; see the client RUNBOOK.md")]
struct Options {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read an exact candidate and observations as JSON from stdin. No network.
    Preflight,
    /// One-shot guardian observations. Read the invite code from stdin.
    Status {
        #[arg(long)]
        module: ModuleInstanceId,
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=300))]
        timeout_seconds: u64,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Deserialize)]
struct Request {
    federation_id: FederationId,
    transaction_hex: String,
    /// Every Simplicity instance must be identified, even if context is absent.
    modules: BTreeMap<ModuleInstanceId, Option<Snapshot>>,
}

#[derive(Deserialize)]
struct Snapshot {
    consensus_version: ModuleConsensusVersion,
    session_index: u64,
    block_count: u64,
    /// A list permits JSON encoding of composite outpoint keys.
    contracts: Vec<(OutPoint, StoredContract)>,
}

fn preflight() -> anyhow::Result<ExitCode> {
    // Bound local parser/decoder work independently of the transaction limits.
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    let report = analyze_request(&bytes)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(if report.has_failures() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn analyze_request(bytes: &[u8]) -> anyhow::Result<preflight::Report> {
    ensure!(
        bytes.len() as u64 <= MAX_REQUEST_BYTES,
        "diagnostic request exceeds 1 MiB"
    );
    // Parser errors can quote sensitive input. Print only fixed messages.
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| anyhow!("invalid diagnostic request JSON"))?;
    let decoders = ModuleDecoderRegistry::new(
        request
            .modules
            .keys()
            .map(|id| (*id, common::KIND, SimplicityCommonInit::decoder())),
    )
    .with_fallback();
    let transaction = Transaction::consensus_decode_hex(&request.transaction_hex, &decoders)
        .map_err(|_| anyhow!("invalid transaction encoding"))?;
    let mut snapshots = BTreeMap::new();
    for (module, snapshot) in request.modules {
        if let Some(snapshot) = snapshot {
            let count = snapshot.contracts.len();
            let contracts: BTreeMap<_, _> = snapshot.contracts.into_iter().collect();
            ensure!(contracts.len() == count, "duplicate context outpoint");
            snapshots.insert(
                module,
                PruningSnapshot {
                    consensus_version: snapshot.consensus_version,
                    session_index: snapshot.session_index,
                    block_count: snapshot.block_count,
                    contracts,
                },
            );
        }
    }
    Ok(preflight::analyze(
        &transaction,
        request.federation_id,
        &snapshots,
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    match Options::parse().command {
        Command::Preflight => preflight(),
        Command::Status {
            module,
            timeout_seconds,
            json,
        } => operator_status(module, timeout_seconds, json).await,
    }
}

async fn operator_status(
    module: ModuleInstanceId,
    timeout_seconds: u64,
    json: bool,
) -> anyhow::Result<ExitCode> {
    use std::time::Duration;

    use fedimint_api_client::download_from_invite_code;
    use fedimint_connectors::ConnectorRegistry;
    use fedimint_core::invite_code::InviteCode;
    use fedimint_core::runtime::timeout;
    use fedimint_simplicity_client::status;

    // Invites can contain API secrets, so accept them on stdin, not in argv.
    let mut bytes = Vec::new();
    io::stdin().lock().take(16_385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16_384, "invite exceeds 16 KiB");
    let text = std::str::from_utf8(&bytes).map_err(|_| anyhow!("invalid invite encoding"))?;
    let invite: InviteCode = text
        .trim()
        .parse()
        .map_err(|_| anyhow!("invalid invite code"))?;
    let limit = Duration::from_secs(timeout_seconds);
    let connectors = timeout(
        limit,
        ConnectorRegistry::build_from_client_defaults().bind(),
    )
    .await
    .map_err(|_| anyhow!("network initialization timed out"))?
    .map_err(|_| anyhow!("network initialization failed"))?;
    let (config, api) = timeout(limit, download_from_invite_code(&connectors, &invite))
        .await
        .map_err(|_| anyhow!("configuration query timed out"))?
        .map_err(|_| anyhow!("configuration query failed"))?;
    ensure!(
        config
            .modules
            .get(&module)
            .is_some_and(|config| config.kind() == &common::KIND),
        "selected instance is not a Simplicity module"
    );
    let report = status::query(&api, module, limit).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Guardian  Supported  Active  Sessions  Module blocks");
        for (peer, guardian) in &report.guardians {
            let session = match guardian.core.value() {
                Some(core) => core
                    .federation
                    .as_ref()
                    .map(|federation| federation.session_count.to_string())
                    .unwrap_or_else(|| "unavailable".to_owned()),
                None => display_query(&guardian.core, |_| String::new()),
            };
            println!(
                "{peer:<8}  {:<9}  {:<6}  {:<8}  {}",
                display_query(&guardian.supported_version, ToString::to_string),
                display_query(&guardian.active_version, ToString::to_string),
                session,
                display_query(&guardian.block_count, ToString::to_string)
            );
        }
        match report.quorum_active_version {
            Some(version) => println!(
                "Quorum-observed active version: {version} (threshold {})",
                report.quorum_size
            ),
            None => println!(
                "No active version established by this observation (threshold {}).",
                report.quorum_size
            ),
        }
        println!(
            "Observations are not atomic; equal counters do not prove full synchronization. Use --json for core status details."
        );
    }
    // Lack of version agreement is useful to scripts, but is not a diagnosis
    // of federation failure. Individual field failures remain in the report.
    Ok(if report.quorum_active_version.is_some() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn display_query<T>(
    query: &fedimint_simplicity_client::status::Query<T>,
    display: impl FnOnce(&T) -> String,
) -> String {
    use fedimint_simplicity_client::status::Query;
    match query {
        Query::Available { value } => display(value),
        Query::TimedOut => "timeout".to_owned(),
        Query::Unavailable => "unavailable".to_owned(),
    }
}
