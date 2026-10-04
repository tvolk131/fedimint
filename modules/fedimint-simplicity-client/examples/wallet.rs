//! Native SDK walkthrough; see ../RUNBOOK.md. The mnemonic is read from a pipe,
//! never command-line arguments, and is not stored separately from wallet data.
use std::io::{self, BufRead, IsTerminal};
use std::path::PathBuf;

use anyhow::{Context as _, ensure};
use clap::{Parser, Subcommand};
use fedimint_bip39::{Bip39RootSecretStrategy, Mnemonic};
use fedimint_client::secret::RootSecretStrategy as _;
use fedimint_client::{Client, ClientBuilder, ClientHandle, RootSecret};
use fedimint_connectors::ConnectorRegistry;
use fedimint_core::base32::{self, FEDIMINT_PREFIX};
use fedimint_core::core::OperationId;
use fedimint_core::db::Database;
use fedimint_core::invite_code::InviteCode;
use fedimint_core::{Amount, OutPoint, TransactionId};
use fedimint_mintv2_client::{FinalReceiveOperationState, MintClientInit, MintClientModule};
use fedimint_rocksdb::RocksDb;
use fedimint_simplicity_client::common::assets::AssetBundle;
use fedimint_simplicity_client::{SimplicityClientInit, SimplicityClientModule, SpendIntent};

#[derive(Parser)]
#[command(about = "Testnet-only Simplicity SDK walkthrough; mnemonic on stdin")]
struct Options {
    #[arg(long)]
    data_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Join {
        invite: InviteCode,
    },
    Recover {
        invite: InviteCode,
    },
    Status,
    /// Read Mint v2 ecash from the second line of stdin and reissue it.
    Receive,
    /// Lock existing ecash to a recoverable owner contract (amount in msat).
    Lock {
        msats: u64,
    },
    /// Spend an owner contract back to ecash, less fees.
    Release {
        txid: TransactionId,
        out_idx: u64,
    },
    /// Resume waiting after the process was interrupted.
    Wait {
        operation: OperationId,
    },
}

async fn builder() -> ClientBuilder {
    let mut builder = Client::builder().await;
    builder.with_module(MintClientInit);
    builder.with_module(SimplicityClientInit::default());
    builder
}

fn secret_line() -> anyhow::Result<String> {
    ensure!(
        !io::stdin().is_terminal(),
        "pipe the mnemonic using the hidden-read example in RUNBOOK.md"
    );
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    ensure!(!line.trim().is_empty(), "missing stdin line");
    Ok(line.trim().to_owned())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let options = Options::parse();
    let mnemonic: Mnemonic = secret_line()?.parse()?;
    let root =
        RootSecret::StandardDoubleDerive(Bip39RootSecretStrategy::<12>::to_root_secret(&mnemonic));
    let database = Database::new(
        RocksDb::build(options.data_dir.join("client.db"))
            .open()
            .await?,
        Default::default(),
    );
    let connectors = ConnectorRegistry::build_from_client_defaults().bind().await;
    let mut client = match &options.command {
        Command::Join { invite } => {
            builder()
                .await
                .preview(connectors.clone(), invite)
                .await?
                .join(database.clone(), root.clone())
                .await?
        }
        Command::Recover { invite } => {
            builder()
                .await
                .preview(connectors.clone(), invite)
                .await?
                .recover(database.clone(), root.clone(), None)
                .await?
        }
        _ => {
            builder()
                .await
                .open(connectors.clone(), database.clone(), root.clone())
                .await?
        }
    };
    // Opening an interrupted recovery resumes its durable progress. Unusable
    // modules become available only after recovery completes and we reopen.
    if client.has_pending_recoveries() || !client.all_modules_usable() {
        let recovery = client.wait_for_all_recoveries().await;
        client.shutdown().await;
        recovery?;
        client = builder().await.open(connectors, database, root).await?;
    }
    let result = run(&client, options.command).await;
    client.shutdown().await;
    result
}

async fn run(client: &ClientHandle, command: Command) -> anyhow::Result<()> {
    let wallet = client.get_first_module::<SimplicityClientModule>()?;
    match command {
        Command::Join { .. } | Command::Recover { .. } | Command::Status => {
            wallet.sync().await?;
            println!("ecash_msat={}", client.get_balance_for_btc().await?.msats);
            let mut cursor = None;
            loop {
                let page = wallet.contracts_page(cursor.as_ref(), 128).await?;
                for (point, contract) in page.entries {
                    // Do not serialize WalletContract: its descriptor can
                    // contain decrypted application secrets.
                    println!(
                        "{}:{} amount_msat={} spent={}",
                        point.txid,
                        point.out_idx,
                        contract.output.amount.msats,
                        contract.spent_by.is_some()
                    );
                }
                cursor = page.next;
                if cursor.is_none() {
                    break;
                }
            }
            let mut cursor = None;
            loop {
                let page = wallet.history_page(cursor.as_ref(), 128).await?;
                for entry in page.entries {
                    println!(
                        "session={} transaction={} consumed={} received={} sent={}",
                        entry.session,
                        entry.transaction.tx_hash(),
                        entry.consumed.len(),
                        entry.received.len(),
                        entry.sent.is_some()
                    );
                }
                cursor = page.next;
                if cursor.is_none() {
                    break;
                }
            }
        }
        Command::Receive => {
            let mint = client.get_first_module::<MintClientModule>()?;
            let ecash = base32::decode_prefixed(FEDIMINT_PREFIX, &secret_line()?)?;
            let operation = mint.receive(ecash, serde_json::Value::Null).await?;
            ensure!(
                mint.await_final_receive_operation_state(operation).await?
                    == FinalReceiveOperationState::Success,
                "ecash reissuance rejected"
            );
            println!("received");
        }
        Command::Lock { msats } => {
            ensure!(msats > 0, "amount must be positive");
            let output = wallet.receive(Amount::from_msats(msats), AssetBundle::default())?;
            let (operation, txid) = wallet.submit(vec![], vec![output], vec![]).await?;
            println!("operation={} contract={txid}:0", operation.fmt_full());
            wallet.await_operation(operation).await?;
        }
        Command::Release { txid, out_idx } => {
            wallet.sync().await?;
            let point = OutPoint { txid, out_idx };
            let mut cursor = None;
            let mut owned = false;
            loop {
                let page = wallet.contracts_page(cursor.as_ref(), 128).await?;
                owned |= page.entries.iter().any(|(outpoint, contract)| {
                    *outpoint == point
                        && contract.spent_by.is_none()
                        && contract.descriptor.template == "owner"
                });
                cursor = page.next;
                if owned || cursor.is_none() {
                    break;
                }
            }
            ensure!(owned, "expected an unspent owner contract");
            let (operation, _) = wallet
                .submit(vec![SpendIntent::owner(point)], vec![], vec![])
                .await?;
            println!("operation={}", operation.fmt_full());
            wallet.await_operation(operation).await?;
        }
        Command::Wait { operation } => wallet
            .await_operation(operation)
            .await
            .context("operation failed")?,
    }
    Ok(())
}
