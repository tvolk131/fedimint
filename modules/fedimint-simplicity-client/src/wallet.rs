//! Persistent wallet state reconstructed from authenticated federation
//! sessions. Spent contracts remain in this client database so terminal
//! interactions are recoverable even when the wallet has no remaining
//! Simplicity holdings.
pub(crate) mod db;
mod history;
mod pages;

use std::sync::Arc;

use anyhow::ensure;
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::session_outcome::{ConsensusItem, SessionOutcome, SessionStatus};
use fedimint_core::transaction::Transaction;
use fedimint_core::{OutPoint, TransactionId};
use fedimint_derive_secret::DerivableSecret;
use futures::StreamExt as _;
pub use history::SessionHistory;
pub use pages::{MAX_WALLET_PAGE_SIZE, PageError, WalletCursor, WalletPage};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::common::{ContractInput, ContractOutput};
use crate::descriptor::{ContractDescriptor, ContractTemplates, WalletKeys};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct WalletContract {
    pub output: ContractOutput,
    pub descriptor: ContractDescriptor,
    pub creation_session: u64,
    pub spent_by: Option<TransactionId>,
}

/// Original accepted transaction and the wallet's relationship to it. Retaining
/// the transaction preserves grouping, public application witnesses, asset
/// actions, and foreign outputs without guessing their application semantics.
#[derive(Debug, Clone, Eq, PartialEq, Encodable)]
pub struct HistoryEntry {
    pub transaction: Transaction,
    pub session: u64,
    pub consumed: Vec<OutPoint>,
    pub received: Vec<OutPoint>,
    /// Authenticated sent activity; never implies owning recipient outputs.
    pub sent: Option<crate::receipt::SenderReceipt>,
}

impl Decodable for HistoryEntry {
    fn consensus_decode_partial_from_finite_reader<R: std::io::Read>(
        reader: &mut R,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        // History can contain foreign modules this wallet does not implement.
        // Preserve their opaque bytes just as the authenticated session API does.
        let modules = &modules.clone().with_fallback();
        Ok(Self {
            transaction: Decodable::consensus_decode_partial_from_finite_reader(reader, modules)?,
            session: Decodable::consensus_decode_partial_from_finite_reader(reader, modules)?,
            consumed: Decodable::consensus_decode_partial_from_finite_reader(reader, modules)?,
            received: Decodable::consensus_decode_partial_from_finite_reader(reader, modules)?,
            sent: Decodable::consensus_decode_partial_from_finite_reader(reader, modules)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct WalletStore {
    pub(crate) db: Database,
    pub(crate) keys: WalletKeys,
    pub(crate) templates: Arc<dyn ContractTemplates>,
    pub(crate) federation: FederationId,
    pub(crate) module: ModuleInstanceId,
    pub(crate) sync_lock: Arc<Mutex<()>>,
}

impl WalletStore {
    /// `db` must be dedicated to this wallet/module. The identity check
    /// prevents accidentally opening existing state with a different
    /// mnemonic or scope.
    pub async fn open(
        db: Database,
        root: &DerivableSecret,
        federation: FederationId,
        module: ModuleInstanceId,
        templates: Arc<dyn ContractTemplates>,
    ) -> anyhow::Result<Self> {
        let keys = WalletKeys::new(root, federation, module);
        let identity = keys.identity();
        let mut dbtx = db.begin_transaction().await;
        if let Some(previous) = dbtx.get_value(&db::IdentityKey).await {
            ensure!(
                previous == identity,
                "wallet database belongs to another mnemonic or module"
            );
        } else {
            dbtx.insert_new_entry(&db::IdentityKey, &identity).await;
        }
        if dbtx.get_value(&db::ViewRevisionKey).await.is_none() {
            dbtx.insert_new_entry(&db::ViewRevisionKey, &rand::random::<[u8; 32]>())
                .await;
        }
        dbtx.commit_tx_result().await?;
        Ok(Self {
            db,
            keys,
            templates,
            federation,
            module,
            sync_lock: Arc::new(Mutex::new(())),
        })
    }

    pub async fn next_session(&self) -> u64 {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&db::NextSessionKey)
            .await
            .unwrap_or(0)
    }

    /// Capture a recovery boundary and resume from the saved session prefix.
    /// The current session is read through the quorum-authenticated status API;
    /// later syncs extend that prefix rather than skipping its remaining items.
    pub async fn sync(
        &self,
        history: &SessionHistory,
        progress: impl Fn(u64, u64),
    ) -> anyhow::Result<()> {
        let _lock = self.sync_lock.lock().await;
        let mut dbtx = self.db.begin_transaction().await;
        let target = if let Some(target) = dbtx.get_value(&db::RecoveryTargetKey).await {
            target
        } else {
            // Do not hold a write transaction while making network requests.
            drop(dbtx);
            let target = history.api.session_count().await?;
            dbtx = self.db.begin_transaction().await;
            dbtx.insert_entry(&db::RecoveryTargetKey, &target).await;
            target
        };
        dbtx.commit_tx_result().await?;
        let start = self.next_session().await;
        ensure!(target < u64::MAX, "session count overflow");
        // A crash may occur after committing the last complete session and
        // before removing the recovery target.
        ensure!(
            start <= target + 1,
            "wallet recovery cursor exceeds its target"
        );
        progress(start, target + 1);
        for index in start..=target {
            // Completed sessions are signed; the open prefix uses quorum
            // agreement without waiting for session closure.
            let status = history.session(index).await?;
            match status {
                SessionStatus::Complete(session) => {
                    self.apply_session(index, &session, true).await?
                }
                SessionStatus::Pending(items) => {
                    ensure!(index == target, "incomplete historical session");
                    self.apply_session(index, &SessionOutcome { items }, false)
                        .await?;
                }
                SessionStatus::Initial => {
                    ensure!(index == target, "missing historical session");
                    self.apply_session(index, &SessionOutcome { items: vec![] }, false)
                        .await?;
                }
            }
            progress(index + 1, target + 1);
        }
        let mut dbtx = self.db.begin_transaction().await;
        dbtx.remove_entry(&db::RecoveryTargetKey).await;
        dbtx.commit_tx_result().await?;
        Ok(())
    }

    pub async fn is_recovering(&self) -> bool {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&db::RecoveryTargetKey)
            .await
            .is_some()
    }

    /// Read one authenticated local record, including a spent contract.
    /// This does not query guardians or change the wallet's watch set.
    pub async fn contract(&self, point: OutPoint) -> Option<WalletContract> {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&db::ContractKey(point))
            .await
    }

    /// Allocate all contract records. Prefer `contracts_page` for large
    /// wallets.
    pub async fn contracts(&self) -> Vec<(OutPoint, WalletContract)> {
        self.db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&db::ContractPrefix)
            .await
            .map(|(key, value)| (key.0, value))
            .collect()
            .await
    }

    /// Allocate the complete history. Prefer `history_page` for large wallets.
    pub async fn history(&self) -> Vec<HistoryEntry> {
        let mut entries = self
            .db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&db::HistoryPrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        entries.sort_by_key(|(key, _)| (key.0, key.1));
        entries.into_iter().map(|(_, value)| value).collect()
    }

    pub(crate) async fn has_transaction(&self, txid: TransactionId) -> bool {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&db::ObservedTransactionKey(txid))
            .await
            .is_some()
    }

    /// Only authenticated, ordered sessions reach this method in production.
    /// The whole session and its cursor commit together, making retries and
    /// interruption safe without replaying wallet side effects.
    pub(crate) async fn apply_session(
        &self,
        index: u64,
        session: &SessionOutcome,
        complete: bool,
    ) -> anyhow::Result<()> {
        let mut dbtx = self.db.begin_transaction().await;
        let next = dbtx.get_value(&db::NextSessionKey).await.unwrap_or(0);
        if index < next {
            return Ok(());
        }
        ensure!(index == next, "missing session in wallet recovery");
        let (seen, hash) = dbtx
            .get_value(&db::OpenSessionKey)
            .await
            .unwrap_or((0, None));
        ensure!(
            seen <= session.items.len() as u64,
            "history prefix regressed"
        );
        if let Some(hash) = hash {
            ensure!(
                session.items[..seen as usize]
                    .to_vec()
                    .consensus_hash_sha256()
                    == hash,
                "history prefix changed"
            );
        }
        let mut changed = false;
        for (position, item) in session.items.iter().enumerate().skip(seen as usize) {
            let ConsensusItem::Transaction(tx) = &item.item else {
                continue;
            };
            let txid = tx.tx_hash();
            let mut consumed = vec![];
            let mut predecessors = vec![];
            for (input_index, input) in tx
                .inputs
                .iter()
                .filter(|input| input.module_instance_id() == self.module)
                .enumerate()
            {
                let input = input
                    .as_any()
                    .downcast_ref::<ContractInput>()
                    .ok_or_else(|| anyhow::anyhow!("wrong Simplicity input decoder"))?;
                if let Some(mut contract) = dbtx.get_value(&db::ContractKey(input.outpoint)).await {
                    ensure!(
                        contract.spent_by.is_none(),
                        "history spends a contract twice"
                    );
                    predecessors.push((input_index, input.outpoint, contract.clone()));
                    contract.spent_by = Some(txid);
                    dbtx.insert_entry(&db::ContractKey(input.outpoint), &contract)
                        .await;
                    dbtx.remove_entry(&db::ReservationKey(input.outpoint)).await;
                    consumed.push(input.outpoint);
                }
            }
            let mut received = vec![];
            let mut sent = None;
            for (out_idx, output) in tx.outputs.iter().enumerate() {
                if output.module_instance_id() != self.module {
                    continue;
                }
                let output = output
                    .as_any()
                    .downcast_ref::<ContractOutput>()
                    .ok_or_else(|| anyhow::anyhow!("wrong Simplicity output decoder"))?;
                if output.actions().is_some() {
                    if let Some(receipt) = crate::receipt::read(
                        &self.keys,
                        self.federation,
                        self.module,
                        tx,
                        &output.recovery,
                    )? {
                        ensure!(sent.is_none(), "multiple owned sender receipts");
                        sent = Some(receipt);
                    }
                    continue;
                }
                let descriptor = self.keys.decrypt(&output.recovery)?;
                let descriptor = if let Some(descriptor) = descriptor {
                    let (version, program) =
                        self.keys.program(&descriptor, self.templates.as_ref())?;
                    // Anybody can copy a public ciphertext onto an unrelated
                    // policy. It must neither create a false holding nor block
                    // recovery of the genuine wallet.
                    (version == output.version && program.cmr() == output.cmr).then_some(descriptor)
                } else {
                    None
                };
                let predecessor = predecessors.iter().find(|(input_index, _, old)| {
                    self.templates.is_successor(
                        &old.descriptor,
                        &old.output,
                        output,
                        crate::descriptor::SuccessorPosition {
                            input_index: *input_index,
                            output_index: out_idx,
                        },
                    )
                });
                if let Some((_, previous, _)) = predecessor {
                    let next = OutPoint {
                        txid,
                        out_idx: out_idx as u64,
                    };
                    let previous_link =
                        dbtx.insert_entry(&db::SuccessorKey(*previous), &next).await;
                    ensure!(
                        previous_link.is_none_or(|link| link == next),
                        "ambiguous public contract successor"
                    );
                }
                let descriptor =
                    descriptor.or_else(|| predecessor.map(|(_, _, old)| old.descriptor.clone()));
                let Some(descriptor) = descriptor else {
                    continue;
                };
                let outpoint = OutPoint {
                    txid,
                    out_idx: out_idx as u64,
                };
                dbtx.insert_new_entry(
                    &db::ContractKey(outpoint),
                    &WalletContract {
                        output: output.clone(),
                        descriptor,
                        creation_session: index,
                        spent_by: None,
                    },
                )
                .await;
                received.push(outpoint);
            }
            if !consumed.is_empty() || !received.is_empty() || sent.is_some() {
                changed = true;
                dbtx.insert_new_entry(&db::ObservedTransactionKey(txid), &())
                    .await;
                dbtx.insert_new_entry(
                    &db::HistoryKey(index, position as u64),
                    &HistoryEntry {
                        transaction: tx.clone(),
                        session: index,
                        consumed,
                        received,
                        sent,
                    },
                )
                .await;
            }
        }
        if changed {
            dbtx.insert_entry(&db::ViewRevisionKey, &rand::random::<[u8; 32]>())
                .await;
        }
        if complete {
            dbtx.insert_entry(
                &db::NextSessionKey,
                &index
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("session index overflow"))?,
            )
            .await;
            dbtx.remove_entry(&db::OpenSessionKey).await;
        } else {
            dbtx.insert_entry(
                &db::OpenSessionKey,
                &(
                    session.items.len() as u64,
                    Some(session.items.consensus_hash_sha256()),
                ),
            )
            .await;
        }
        dbtx.commit_tx_result().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
