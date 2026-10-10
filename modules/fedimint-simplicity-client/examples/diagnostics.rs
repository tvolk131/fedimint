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
    const MAX_REQUEST_BYTES: u64 = 1_048_576;
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_REQUEST_BYTES,
        "diagnostic request exceeds 1 MiB"
    );
    // Parser errors can quote sensitive input. Print only fixed messages.
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("invalid diagnostic request JSON"))?;
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
    let report = preflight::analyze(&transaction, request.federation_id, &snapshots);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(if report.has_failures() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    match Options::parse().command {
        Command::Preflight => preflight(),
    }
}
