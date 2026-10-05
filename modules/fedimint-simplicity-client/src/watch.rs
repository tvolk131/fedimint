//! Authenticated discovery of public contracts and their unique successors.
use std::collections::BTreeMap;

use anyhow::ensure;
use fedimint_core::OutPoint;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::session_outcome::{ConsensusItem, SessionStatus};

use crate::SimplicityClientModule;
use crate::common::{ContractInput, ContractOutput};
use crate::descriptor::ContractDescriptor;
use crate::wallet::{HistoryEntry, WalletContract, db};

impl SimplicityClientModule {
    /// Track an authenticated creation outpoint and template-defined
    /// successors. This records the exact prefix already scanned, so
    /// importing a contract cannot miss a spend behind the wallet cursor. A
    /// closed contract returns `None` while retaining its history. Watching
    /// alone is local; accepted participation must carry encrypted metadata
    /// for mnemonic recovery.
    pub async fn watch_contract(
        &self,
        origin: OutPoint,
        descriptor: ContractDescriptor,
    ) -> anyhow::Result<Option<OutPoint>> {
        self.sync().await?;
        let _guard = self.store.sync_lock.lock().await;
        let (version, program) = self
            .store
            .keys
            .program(&descriptor, self.store.templates.as_ref())?;
        let cmr = program.cmr();
        let mut chain: BTreeMap<OutPoint, WalletContract> = BTreeMap::new();
        let mut additions = vec![];
        let mut tx = self.store.db.begin_transaction_nc().await;
        let next = tx.get_value(&db::NextSessionKey).await.unwrap_or(0);
        let open_len = tx
            .get_value(&db::OpenSessionKey)
            .await
            .map_or(0, |(n, _)| n);
        drop(tx);
        // Replay exactly the prefix already scanned by this wallet, then merge
        // atomically. Future ordinary sync starts after this prefix. Inserting
        // a live API UTXO directly could miss a spend already passed by the cursor.
        let history = self.session_history().await;
        for index in 0..=next {
            if index == next && open_len == 0 {
                break;
            }
            let status = history.session(index).await?;
            let items = match status {
                SessionStatus::Complete(session) => session.items,
                SessionStatus::Pending(items) if index == next => items,
                _ => anyhow::bail!("contract history has not caught up to wallet cursor"),
            };
            let count = if index == next {
                usize::try_from(open_len)?
            } else {
                items.len()
            };
            ensure!(items.len() >= count, "contract history prefix regressed");
            for (position, item) in items.into_iter().take(count).enumerate() {
                let ConsensusItem::Transaction(transaction) = item.item else {
                    continue;
                };
                let txid = transaction.tx_hash();
                let mut consumed = vec![];
                let mut received = vec![];
                for input in &transaction.inputs {
                    if input.module_instance_id() != self.store.module {
                        continue;
                    }
                    let input = input
                        .as_any()
                        .downcast_ref::<ContractInput>()
                        .ok_or_else(|| anyhow::anyhow!("wrong input decoder"))?;
                    if let Some(old) = chain.get_mut(&input.outpoint) {
                        ensure!(old.spent_by.is_none(), "contract history double spend");
                        old.spent_by = Some(txid);
                        consumed.push(input.outpoint);
                    }
                }
                for (out_idx, output) in transaction.outputs.iter().enumerate() {
                    if output.module_instance_id() != self.store.module {
                        continue;
                    }
                    let point = OutPoint {
                        txid,
                        out_idx: out_idx as u64,
                    };
                    let output = output
                        .as_any()
                        .downcast_ref::<ContractOutput>()
                        .ok_or_else(|| anyhow::anyhow!("wrong output decoder"))?;
                    if (point == origin && output.version == version && output.cmr == cmr)
                        || consumed.iter().any(|point| {
                            chain.get(point).is_some_and(|old| {
                                self.store.templates.is_successor(
                                    &old.descriptor,
                                    &old.output,
                                    output,
                                )
                            })
                        })
                    {
                        chain.insert(
                            point,
                            WalletContract {
                                output: output.clone(),
                                descriptor: descriptor.clone(),
                                creation_session: index,
                                spent_by: None,
                            },
                        );
                        received.push(point);
                    }
                }
                if !consumed.is_empty() || !received.is_empty() {
                    additions.push((
                        db::HistoryKey(index, position as u64),
                        HistoryEntry {
                            transaction,
                            session: index,
                            consumed,
                            received,
                            sent: None,
                        },
                    ));
                }
            }
        }
        ensure!(
            chain.contains_key(&origin),
            "contract origin not found or descriptor does not match"
        );
        let current = chain
            .iter()
            .filter(|(_, c)| c.spent_by.is_none())
            .map(|(p, _)| *p)
            .collect::<Vec<_>>();
        ensure!(current.len() <= 1, "ambiguous public contract successor");
        let current = current.first().copied();
        let mut tx = self.store.db.begin_transaction().await;
        let mut changed = false;
        for (point, mut contract) in chain {
            if let Some(existing) = tx.get_value(&db::ContractKey(point)).await {
                ensure!(
                    existing.output == contract.output && existing.spent_by == contract.spent_by,
                    "contract watch disagrees with wallet history"
                );
                contract.descriptor = existing.descriptor;
            }
            changed |= tx
                .insert_entry(&db::ContractKey(point), &contract)
                .await
                .as_ref()
                != Some(&contract);
        }
        for (key, mut entry) in additions {
            if let Some(existing) = tx.get_value(&key).await {
                ensure!(
                    existing.transaction == entry.transaction,
                    "contract watch history mismatch"
                );
                entry.consumed.extend(existing.consumed);
                entry.received.extend(existing.received);
                entry.sent = existing.sent;
                entry.consumed.sort();
                entry.consumed.dedup();
                entry.received.sort();
                entry.received.dedup();
            }
            tx.insert_entry(
                &db::ObservedTransactionKey(entry.transaction.tx_hash()),
                &(),
            )
            .await;
            changed |= tx.insert_entry(&key, &entry).await.as_ref() != Some(&entry);
        }
        if changed {
            tx.insert_entry(&db::ViewRevisionKey, &rand::random::<[u8; 32]>())
                .await;
        }
        tx.commit_tx_result().await?;
        Ok(current)
    }
}
