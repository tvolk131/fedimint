//! Authenticated discovery of public contracts and their unique successors.
use std::collections::BTreeMap;

use anyhow::ensure;
use fedimint_core::OutPoint;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::Encodable as _;
use fedimint_core::session_outcome::{ConsensusItem, SessionStatus};

use crate::SimplicityClientModule;
use crate::common::{ContractInput, ContractOutput};
use crate::descriptor::ContractDescriptor;
use crate::wallet::{HistoryEntry, SessionHistory, WalletContract, WalletStore, db};

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
        Ok(self
            .watch_contracts(vec![(origin, descriptor)])
            .await?
            .remove(&origin)
            .expect("requested origin has a result"))
    }

    /// Import public contract lineages with one authenticated replay.
    /// Each origin must match its descriptor. Compatible ancestor/descendant
    /// requests share a lineage. Duplicate origins, incompatible overlaps and
    /// ambiguous successors reject the entire atomic import.
    /// The 2048-origin client limit bounds the request size, not replay memory,
    /// which grows with imported history. It is not a guardian/consensus limit.
    pub async fn watch_contracts(
        &self,
        origins: Vec<(OutPoint, ContractDescriptor)>,
    ) -> anyhow::Result<BTreeMap<OutPoint, Option<OutPoint>>> {
        ensure!(origins.len() <= 2048, "too many public contract origins");
        if origins.is_empty() {
            return Ok(BTreeMap::new());
        }
        self.sync().await?;
        self.store
            .watch_contracts(&self.session_history().await, origins)
            .await
    }

    /// Import origins whose creation is at or after `first_session`.
    /// This is only a replay hint: every requested origin must still be found
    /// in authenticated history, with its descriptor checked, and all later
    /// spends are replayed. A hint after an origin fails atomically rather than
    /// accepting an incomplete lineage. Use zero when creation is unknown.
    pub async fn watch_contracts_from_session(
        &self,
        origins: Vec<(OutPoint, ContractDescriptor)>,
        first_session: u64,
    ) -> anyhow::Result<BTreeMap<OutPoint, Option<OutPoint>>> {
        ensure!(origins.len() <= 2048, "too many public contract origins");
        if origins.is_empty() {
            return Ok(BTreeMap::new());
        }
        self.sync().await?;
        self.store
            .watch_contracts_from_session(&self.session_history().await, origins, first_session)
            .await
    }
}

impl WalletStore {
    pub(crate) async fn watch_contracts(
        &self,
        history: &SessionHistory,
        origins: Vec<(OutPoint, ContractDescriptor)>,
    ) -> anyhow::Result<BTreeMap<OutPoint, Option<OutPoint>>> {
        self.watch_contracts_from_session(history, origins, 0).await
    }

    pub(crate) async fn watch_contracts_from_session(
        &self,
        history: &SessionHistory,
        origins: Vec<(OutPoint, ContractDescriptor)>,
        first_session: u64,
    ) -> anyhow::Result<BTreeMap<OutPoint, Option<OutPoint>>> {
        let _guard = self.sync_lock.lock().await;
        let mut requests = BTreeMap::new();
        for (origin, descriptor) in origins {
            let (version, program) = self.keys.program(&descriptor, self.templates.as_ref())?;
            ensure!(
                requests
                    .insert(origin, (descriptor, version, program.cmr()))
                    .is_none(),
                "duplicate public contract origin"
            );
        }
        let mut roots = BTreeMap::new();
        let mut chain: BTreeMap<OutPoint, WalletContract> = BTreeMap::new();
        let mut additions = vec![];
        let mut successors = BTreeMap::new();
        let mut tx = self.db.begin_transaction_nc().await;
        let next = tx.get_value(&db::NextSessionKey).await.unwrap_or(0);
        let (open_len, open_hash) = tx.get_value(&db::OpenSessionKey).await.unwrap_or((0, None));
        drop(tx);
        // Replay exactly the prefix already scanned by this wallet, then merge
        // atomically. Future ordinary sync starts after this prefix. Inserting
        // a live API UTXO directly could miss a spend already passed by the cursor.
        ensure!(
            first_session <= next,
            "contract replay hint is beyond wallet history"
        );
        for index in first_session..=next {
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
            if let Some(hash) = open_hash.filter(|_| index == next) {
                ensure!(
                    items[..count].to_vec().consensus_hash_sha256() == hash,
                    "contract history prefix changed"
                );
            }
            for (position, item) in items.into_iter().take(count).enumerate() {
                let ConsensusItem::Transaction(transaction) = item.item else {
                    continue;
                };
                let txid = transaction.tx_hash();
                let mut consumed = vec![];
                let mut received = vec![];
                let mut predecessors = vec![];
                for (input_index, input) in transaction
                    .inputs
                    .iter()
                    .filter(|input| input.module_instance_id() == self.module)
                    .enumerate()
                {
                    let input = input
                        .as_any()
                        .downcast_ref::<ContractInput>()
                        .ok_or_else(|| anyhow::anyhow!("wrong input decoder"))?;
                    if let Some(old) = chain.get_mut(&input.outpoint) {
                        ensure!(old.spent_by.is_none(), "contract history double spend");
                        old.spent_by = Some(txid);
                        consumed.push(input.outpoint);
                        predecessors.push((input_index, input.outpoint));
                    }
                }
                for (out_idx, output) in transaction.outputs.iter().enumerate() {
                    if output.module_instance_id() != self.module {
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
                    let matching = predecessors
                        .iter()
                        .filter(|(input_index, previous)| {
                            chain.get(previous).is_some_and(|old| {
                                self.templates.is_successor(
                                    &old.descriptor,
                                    &old.output,
                                    output,
                                    crate::descriptor::SuccessorPosition {
                                        input_index: *input_index,
                                        output_index: out_idx,
                                    },
                                )
                            })
                        })
                        .collect::<Vec<_>>();
                    ensure!(matching.len() <= 1, "overlapping public contract lineages");
                    let predecessor = matching.first().copied();
                    if let Some((_, previous)) = predecessor {
                        let old = successors.insert(*previous, point);
                        ensure!(
                            old.is_none_or(|old| old == point),
                            "ambiguous public contract successor"
                        );
                    }
                    let requested = requests.get(&point);
                    if let Some((_, version, cmr)) = requested {
                        ensure!(
                            output.version == *version && output.cmr == *cmr,
                            "contract origin descriptor does not match"
                        );
                    }
                    let root = if let Some((_, previous)) = predecessor {
                        Some(
                            *roots
                                .get(previous)
                                .expect("tracked predecessor has an origin"),
                        )
                    } else {
                        requested.map(|_| point)
                    };
                    if let Some(root) = root {
                        roots.insert(point, root);
                        if let Some((alias, _, _)) = requested {
                            let canonical =
                                &requests.get(&root).expect("tracked origin was requested").0;
                            ensure!(
                                alias.template == canonical.template
                                    && alias.template_version == canonical.template_version
                                    && alias.parameters == canonical.parameters,
                                "incompatible public contract origins"
                            );
                        }
                        let descriptor =
                            &requests.get(&root).expect("tracked origin was requested").0;
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
        let mut current = BTreeMap::new();
        for origin in requests.keys() {
            ensure!(
                chain.contains_key(origin),
                "contract origin not found or descriptor does not match"
            );
            current.insert(*origin, None);
        }
        for (point, contract) in &chain {
            if contract.spent_by.is_none() {
                let root = roots.get(point).expect("tracked contract has an origin");
                let previous = current.insert(*root, Some(*point));
                ensure!(
                    previous == Some(None),
                    "ambiguous public contract successor"
                );
            }
        }
        let mut tx = self.db.begin_transaction().await;
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
        for (previous, next) in successors {
            let old = tx.insert_entry(&db::SuccessorKey(previous), &next).await;
            ensure!(
                old.is_none_or(|old| old == next),
                "contract watch lineage mismatch"
            );
            changed |= old.is_none();
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
        Ok(requests
            .keys()
            .map(|origin| {
                let root = roots.get(origin).expect("requested origin was found");
                (*origin, current[root])
            })
            .collect())
    }
}
