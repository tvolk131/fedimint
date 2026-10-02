//! Durable semantic operations above the ordinary transaction state machine.
//! Only proven conflicts permit rebuilding. Network uncertainty never does.
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use anyhow::ensure;
use fedimint_core::core::OperationId;
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{Amount, OutPoint, TransactionId};
use futures::StreamExt as _;
use serde::{Deserialize, Serialize};

use crate::client::{SimplicityClientModule, SpendIntent, Submission};
use crate::common::ContractOutput;
use crate::wallet::{WalletContract, db};

mod market;
pub use market::MintPairs;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct Intent {
    pub template: String,
    pub version: u32,
    pub data: Vec<u8>,
}
impl fmt::Debug for Intent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Intent")
            .field("template", &self.template)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub enum RetryMode {
    Manual,
    Automatic,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct IntentPolicy {
    pub retry: RetryMode,
    /// Includes the initial submission. Manual retries share the same limit.
    pub max_attempts: u32,
    /// Maximum total transaction fee per attempt, including primary funding and
    /// change. Rejected funding may have its own module-specific refund costs.
    pub max_fee: Amount,
    /// Stop preparing new attempts at this authenticated session count. This
    /// cannot revoke a transaction that has already been signed/submitted.
    pub deadline_session: Option<u64>,
}
impl Default for IntentPolicy {
    fn default() -> Self {
        Self {
            retry: RetryMode::Manual,
            max_attempts: 3,
            max_fee: Amount::from_sats(100),
            deadline_session: None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub enum IntentStatus {
    Ready,
    Submitted,
    /// A proven conflict awaiting an explicit retry.
    Conflict,
    Backoff {
        until_ms: u64,
    },
    Complete(TransactionId),
    /// Construction/funding or a rejection without proof of a conflict.
    /// Explicit retry can recheck; it cannot bypass conflict proof or budgets.
    Attention(String),
    Failed(String),
    Cancelled,
}
impl IntentStatus {
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Ready | Self::Submitted | Self::Backoff { .. })
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub enum AttemptOutcome {
    Pending,
    Accepted,
    Rejected(String),
    Conflicted(TransactionId),
}
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct IntentAttempt {
    pub operation: OperationId,
    pub transaction: TransactionId,
    pub shared_inputs: Vec<OutPoint>,
    pub outcome: AttemptOutcome,
}
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct IntentRecord {
    pub intent: Intent,
    pub policy: IntentPolicy,
    pub status: IntentStatus,
    pub attempts: Vec<IntentAttempt>,
    pub cancel_requested: bool,
}

/// Handlers are trusted wallet software. They must preserve the meaning of
/// historical template versions and enforce quantities/destinations encoded in
/// the immutable intent. The engine handles persistence and submission safety.
pub trait IntentHandlers: fmt::Debug + Send + Sync {
    fn build(
        &self,
        wallet: &SimplicityClientModule,
        intent: &Intent,
        contracts: &BTreeMap<OutPoint, WalletContract>,
    ) -> anyhow::Result<IntentPlan>;
}

pub struct IntentPlan {
    pub spends: Vec<SpendIntent>,
    pub outputs: Vec<ContractOutput>,
    /// Only conflicts on these inputs authorize a rebuild. Ordinary owned
    /// inputs disappearing is not automatically a retryable shared-state race.
    pub shared_inputs: Vec<OutPoint>,
}
#[derive(Debug)]
pub struct BuiltinIntents;
impl IntentHandlers for BuiltinIntents {
    fn build(
        &self,
        wallet: &SimplicityClientModule,
        intent: &Intent,
        contracts: &BTreeMap<OutPoint, WalletContract>,
    ) -> anyhow::Result<IntentPlan> {
        ensure!(
            intent.template == "binary-market-mint-pairs" && intent.version == 1,
            "unsupported intent template or version"
        );
        MintPairs::consensus_decode_whole(&intent.data, &Default::default())?
            .build(wallet, contracts)
    }
}

impl IntentRecord {
    fn can_prepare(&self, session: u64) -> anyhow::Result<()> {
        ensure!(!self.cancel_requested, "intent cancelled");
        ensure!(
            self.attempts.len() < self.policy.max_attempts as usize,
            "intent attempt limit reached"
        );
        ensure!(
            self.policy
                .deadline_session
                .is_none_or(|limit| session < limit),
            "intent deadline reached"
        );
        ensure!(
            self.attempts
                .last()
                .is_none_or(|attempt| matches!(attempt.outcome, AttemptOutcome::Conflicted(_))),
            "previous attempt is not a proven conflict"
        );
        Ok(())
    }

    fn resolve(
        &mut self,
        result: Result<(), String>,
        contracts: &BTreeMap<OutPoint, WalletContract>,
    ) {
        let attempt = self
            .attempts
            .last_mut()
            .expect("submitted intent has an attempt");
        match result {
            Ok(()) => {
                attempt.outcome = AttemptOutcome::Accepted;
                self.status = IntentStatus::Complete(attempt.transaction);
            }
            Err(error) => {
                let conflict = attempt.shared_inputs.iter().find_map(|point| {
                    contracts
                        .get(point)
                        .and_then(|contract| contract.spent_by)
                        .filter(|txid| *txid != attempt.transaction)
                });
                attempt.outcome = conflict.map_or_else(
                    || AttemptOutcome::Rejected(error.clone()),
                    AttemptOutcome::Conflicted,
                );
                self.status = if self.cancel_requested {
                    IntentStatus::Cancelled
                } else if conflict.is_none() {
                    IntentStatus::Attention(error)
                } else if self.attempts.len() >= self.policy.max_attempts as usize {
                    IntentStatus::Failed("intent attempt limit reached".to_owned())
                } else if self.policy.retry == RetryMode::Manual {
                    IntentStatus::Conflict
                } else {
                    IntentStatus::Backoff {
                        until_ms: now_ms()
                            .saturating_add(backoff_ms(self.attempts.len(), rand::random())),
                    }
                };
            }
        }
    }
}

fn now_ms() -> u64 {
    fedimint_core::time::duration_since_epoch()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
fn backoff_ms(attempts: usize, jitter: u64) -> u64 {
    (250u64 << attempts.min(6)) + jitter % 250
}

impl SimplicityClientModule {
    pub async fn submit_intent(
        &self,
        intent: Intent,
        policy: IntentPolicy,
    ) -> anyhow::Result<OperationId> {
        ensure!(
            (1..=100).contains(&policy.max_attempts),
            "expected 1..=100 attempts"
        );
        ensure!(
            intent.data.len() <= 16_384 && intent.template.len() <= 128,
            "intent too large"
        );
        ensure!(
            !self.store.is_recovering().await,
            "wallet recovery must finish first"
        );
        let id = OperationId::new_random();
        let mut tx = self.store.db.begin_transaction().await;
        tx.insert_new_entry(
            &db::IntentKey(id),
            &IntentRecord {
                intent,
                policy,
                status: IntentStatus::Ready,
                attempts: vec![],
                cancel_requested: false,
            },
        )
        .await;
        tx.insert_new_entry(&db::ActiveIntentKey(id), &()).await;
        tx.commit_tx_result().await?;
        // The durable driver also resumes this if interrupted here. A stopped
        // core executor can still persist the first attempt for later startup.
        // Once persisted, always return the ID even if the first advancement
        // encounters a transient network failure. The driver owns resumption.
        let _ =
            fedimint_core::runtime::timeout(Duration::from_secs(10), self.advance_intent(id)).await;
        Ok(id)
    }

    pub async fn intent(&self, id: OperationId) -> Option<IntentRecord> {
        self.store
            .db
            .begin_transaction_nc()
            .await
            .get_value(&db::IntentKey(id))
            .await
    }

    /// Local operations, including completed ones, for rebuilding application
    /// UI after restart. Mnemonic recovery does not reconstruct this local
    /// queue.
    pub async fn intents(&self) -> Vec<(OperationId, IntentRecord)> {
        self.store
            .db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&db::IntentPrefix)
            .await
            .map(|(key, record)| (key.0, record))
            .collect()
            .await
    }

    /// Return at completion or when explicit user action is needed.
    pub async fn await_intent(&self, id: OperationId) -> anyhow::Result<IntentRecord> {
        let (record, _) = self
            .store
            .db
            .wait_key_check(&db::IntentKey(id), |record| match record {
                None => Some(Err(anyhow::anyhow!("unknown local intent"))),
                Some(record) if !record.status.is_running() => Some(Ok(record)),
                _ => None,
            })
            .await;
        record
    }

    pub async fn retry_intent(&self, id: OperationId) -> anyhow::Result<()> {
        let _guard = self.intent_lock.lock().await;
        let mut tx = self.store.db.begin_transaction().await;
        let mut record = tx
            .get_value(&db::IntentKey(id))
            .await
            .ok_or_else(|| anyhow::anyhow!("unknown local intent"))?;
        ensure!(!record.cancel_requested, "intent cancelled");
        ensure!(
            matches!(
                record.status,
                IntentStatus::Conflict | IntentStatus::Attention(_)
            ),
            "intent is not awaiting retry"
        );
        // A previously unproven rejection must be resolved again before a new
        // attempt is allowed. Missing results remain Submitted indefinitely.
        record.status = if record
            .attempts
            .last()
            .is_some_and(|a| matches!(a.outcome, AttemptOutcome::Rejected(_)))
        {
            IntentStatus::Submitted
        } else {
            IntentStatus::Ready
        };
        save_record(&mut tx.to_ref_nc(), id, &record).await;
        tx.commit_tx_result().await?;
        Ok(())
    }

    pub async fn cancel_intent(&self, id: OperationId) -> anyhow::Result<()> {
        let _guard = self.intent_lock.lock().await;
        let mut tx = self.store.db.begin_transaction().await;
        let mut record = tx
            .get_value(&db::IntentKey(id))
            .await
            .ok_or_else(|| anyhow::anyhow!("unknown local intent"))?;
        record.cancel_requested = true;
        if !matches!(
            record.status,
            IntentStatus::Submitted | IntentStatus::Complete(_)
        ) {
            record.status = IntentStatus::Cancelled;
        }
        save_record(&mut tx.to_ref_nc(), id, &record).await;
        tx.commit_tx_result().await?;
        Ok(())
    }

    pub(crate) async fn run_intents(&self) {
        loop {
            let ids = self
                .store
                .db
                .begin_transaction_nc()
                .await
                .find_by_prefix(&db::ActiveIntentPrefix)
                .await
                .map(|(key, ())| key.0)
                .collect::<Vec<_>>()
                .await;
            for id in ids {
                // Unavailable history must not stall cancellation or other
                // intents. Dropping a preparation rolls back its database tx.
                if let Ok(Err(error)) = fedimint_core::runtime::timeout(
                    Duration::from_secs(10),
                    self.advance_intent(id),
                )
                .await
                {
                    tracing::warn!(target: "fm::simplicity", ?id, %error, "Intent driver will retry local advancement");
                }
            }
            fedimint_core::runtime::sleep(Duration::from_millis(250)).await;
        }
    }

    async fn advance_intent(&self, id: OperationId) -> anyhow::Result<()> {
        let _guard = self.intent_lock.lock().await;
        let Some(mut record) = self.intent(id).await else {
            return Ok(());
        };
        let original = record.clone();
        if let IntentStatus::Backoff { until_ms } = record.status {
            if now_ms() < until_ms {
                return Ok(());
            }
        } else if !record.status.is_running() {
            return Ok(());
        }

        if record.status == IntentStatus::Submitted {
            let attempt = record
                .attempts
                .last()
                .expect("submitted intent has attempt");
            let result = self
                .store
                .db
                .begin_transaction_nc()
                .await
                .get_value(&db::OperationResultKey(attempt.operation))
                .await
                .flatten();
            let Some(result) = result else { return Ok(()) };
            if result.is_err() {
                self.sync().await?;
            }
            record.resolve(result, &self.contracts().await.into_iter().collect());
        } else {
            self.sync().await?;
            if let Err(error) = record.can_prepare(self.store.next_session().await) {
                record.status = IntentStatus::Failed(error.to_string());
            } else {
                let contracts = self.contracts().await.into_iter().collect();
                let plan = self
                    .intents
                    .build(self, &record.intent, &contracts)
                    .and_then(|plan| {
                        ensure!(
                            !plan.shared_inputs.is_empty()
                                && plan.shared_inputs.iter().all(|point| plan
                                    .spends
                                    .iter()
                                    .any(|spend| spend.outpoint == *point)),
                            "invalid shared input plan"
                        );
                        Ok(plan)
                    });
                match plan {
                    Err(error) => record.status = IntentStatus::Failed(error.to_string()),
                    Ok(plan) => {
                        let mut tx = self.store.db.begin_transaction().await;
                        // Compare-and-commit also protects independent handles
                        // sharing a database, beyond this process's driver lock.
                        ensure!(
                            tx.get_value(&db::IntentKey(id)).await.as_ref() == Some(&record),
                            "intent changed while preparing"
                        );
                        let submission = self
                            .submit_dbtx(
                                &mut tx.to_ref_nc(),
                                Submission {
                                    spends: plan.spends,
                                    outputs: plan.outputs,
                                    creations: vec![],
                                    requested_receipt: None,
                                    max_fee: Some(record.policy.max_fee),
                                },
                            )
                            .await;
                        match submission {
                            Ok((operation, transaction)) => {
                                record.attempts.push(IntentAttempt {
                                    operation,
                                    transaction,
                                    shared_inputs: plan.shared_inputs,
                                    outcome: AttemptOutcome::Pending,
                                });
                                record.status = IntentStatus::Submitted;
                                save_record(&mut tx.to_ref_nc(), id, &record).await;
                                tx.commit_tx_result().await?;
                                return Ok(());
                            }
                            Err(error) => {
                                record.status = IntentStatus::Attention(format!("{error:#}"))
                            }
                        }
                        // Failure must roll back reservations AND primary funding.
                        drop(tx);
                    }
                }
            }
        }
        let mut tx = self.store.db.begin_transaction().await;
        ensure!(
            tx.get_value(&db::IntentKey(id)).await.as_ref() == Some(&original),
            "intent changed while resolving"
        );
        save_record(&mut tx.to_ref_nc(), id, &record).await;
        tx.commit_tx_result().await?;
        Ok(())
    }
}

// Keep completed history out of the driver's hot polling path. Index and
// record updates share the same transaction, including submission transitions.
async fn save_record(tx: &mut DatabaseTransaction<'_>, id: OperationId, record: &IntentRecord) {
    tx.insert_entry(&db::IntentKey(id), record).await;
    if record.status.is_running() {
        tx.insert_entry(&db::ActiveIntentKey(id), &()).await;
    } else {
        tx.remove_entry(&db::ActiveIntentKey(id)).await;
    }
}

#[cfg(test)]
mod tests;
