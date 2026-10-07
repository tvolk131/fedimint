//! Local progress uses database notifications; timers only drive semantic
//! backoff and retry failed advancement (for example unavailable history).
use std::collections::BTreeSet;
use std::time::Duration;

use fedimint_core::TransactionId;
use fedimint_core::core::OperationId;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use futures::StreamExt as _;
use futures::stream::FuturesUnordered;

use super::now_ms;
use crate::client::SimplicityClientModule;
use crate::wallet::db;

pub(super) enum IntentWait {
    Changed,
    Outcome(OperationId),
    Funding(OperationId, TransactionId),
    Backoff(u64),
    Retry,
}

async fn active_intents(database: &Database) -> (u64, Vec<OperationId>) {
    let mut tx = database.begin_transaction_nc().await;
    let revision = tx.get_value(&db::IntentRevisionKey).await.unwrap_or(0);
    let ids = tx
        .find_by_prefix(&db::ActiveIntentPrefix)
        .await
        .map(|(key, ())| key.0)
        .collect()
        .await;
    (revision, ids)
}

pub(super) async fn changed_intents(database: &Database, revision: Option<u64>) -> u64 {
    database
        .wait_key_check(&db::IntentRevisionKey, |value| {
            (Some(value.unwrap_or(0)) != revision).then_some(value.unwrap_or(0))
        })
        .await
        .0
}

impl SimplicityClientModule {
    pub(crate) async fn run_intents(&self) {
        let mut running = BTreeSet::new();
        let mut workers = FuturesUnordered::new();
        loop {
            // Read the revision and index in one snapshot. Checking that
            // revision again when subscribing closes the scan/wakeup race.
            let (revision, ids) = active_intents(&self.store.db).await;
            for id in ids {
                if running.insert(id) {
                    workers.push(async move {
                        self.run_intent(id).await;
                        id
                    });
                }
            }
            tokio::select! {
                _ = changed_intents(&self.store.db, Some(revision)) => {},
                Some(id) = workers.next(), if !workers.is_empty() => {
                    running.remove(&id);
                }
            }
        }
    }

    async fn run_intent(&self, id: OperationId) {
        loop {
            let Some(record) = self.intent(id).await else {
                return;
            };
            if !record.status.is_running() {
                return;
            }
            // This deadline covers advancement, never waiting for local state.
            // Cancelling it rolls back uncommitted preparation and releases the
            // shared lock so an unavailable federation cannot monopolize it.
            let advance =
                fedimint_core::runtime::timeout(Duration::from_secs(10), self.advance_intent(id))
                    .await
                    .map_err(anyhow::Error::from)
                    .and_then(std::convert::identity);
            let wait = match advance {
                Ok(IntentWait::Changed) => continue,
                Ok(wait) => wait,
                Err(error) => {
                    tracing::warn!(
                        target: "fm::simplicity",
                        ?id,
                        %error,
                        "Retrying intent advancement"
                    );
                    IntentWait::Retry
                }
            };
            // Cancellation/manual retry or another handle's committed update
            // interrupts a wait. A notification never authorizes submission;
            // advancement always rechecks the durable record and funding.
            let key = db::IntentKey(id);
            tokio::select! {
                _ = self.store.db.wait_key_check(&key, |value| {
                    (value.as_ref() != Some(&record)).then_some(())
                }) => {},
                result = self.wait_for_intent(wait) => {
                    if let Err(error) = result {
                        tracing::warn!(target: "fm::simplicity", ?id, %error, "Retrying funding release wait");
                        fedimint_core::runtime::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
    }

    async fn wait_for_intent(&self, wait: IntentWait) -> anyhow::Result<()> {
        match wait {
            IntentWait::Changed => {}
            IntentWait::Outcome(operation) => {
                self.store
                    .db
                    .wait_key_check(&db::OperationResultKey(operation), |value| {
                        value.flatten().map(|_| ())
                    })
                    .await;
            }
            IntentWait::Funding(operation, txid) => {
                self.context
                    .await_funding_release_progress(operation, txid)
                    .await?;
            }
            IntentWait::Backoff(until_ms) => {
                fedimint_core::runtime::sleep(Duration::from_millis(
                    until_ms.saturating_sub(now_ms()),
                ))
                .await;
            }
            IntentWait::Retry => fedimint_core::runtime::sleep(Duration::from_secs(1)).await,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
