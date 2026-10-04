use std::collections::BTreeMap;

use anyhow::ensure;
use fedimint_api_client::api::FederationApiExt as _;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::session_outcome::{ConsensusItem, SessionStatus};
use fedimint_core::{Amount, OutPoint};
use serde::{Deserialize, Serialize};

use super::{Intent, IntentPlan};
use crate::common::assets::{AssetActions, AssetAmount, AssetBundle, AssetRecord};
use crate::common::{ContractInput, ContractOutput};
use crate::compiler::{Value, ValueConstructible, witnesses};
use crate::descriptor::ContractDescriptor;
use crate::market::BinaryMarket;
use crate::wallet::{HistoryEntry, WalletContract, db};
use crate::{SimplicityClientModule, SpendIntent};

/// Buy complete pairs for exactly 1000 msat each. Recipient outputs (including
/// encrypted recovery metadata) are immutable across all attempts. NO and YES
/// can go to independent recipients. Call `watch_market` before submission.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct MintPairs {
    pub market: BinaryMarket,
    pub anchor: OutPoint,
    pub quantity: u64,
    pub yes_destination: ContractOutput,
    pub no_destination: ContractOutput,
}
impl MintPairs {
    pub fn into_intent(self) -> Intent {
        Intent {
            template: "binary-market-mint-pairs".to_owned(),
            version: 1,
            data: self.consensus_encode_to_vec(),
        }
    }

    pub(super) fn build(
        &self,
        wallet: &SimplicityClientModule,
        contracts: &BTreeMap<OutPoint, WalletContract>,
    ) -> anyhow::Result<IntentPlan> {
        ensure!(
            self.market.federation == wallet.store.federation
                && self.market.module == wallet.store.module,
            "market belongs to a different federation or module"
        );
        ensure!(self.quantity > 0, "zero pair quantity");
        let cost = self
            .quantity
            .checked_mul(1000)
            .ok_or_else(|| anyhow::anyhow!("pair cost overflow"))?;
        for (asset, output) in [
            (self.market.yes, &self.yes_destination),
            (self.market.no, &self.no_destination),
        ] {
            ensure!(
                output.version == crate::common::assets::ASSET_VERSION
                    && output.amount == Amount::ZERO
                    && output.bundle()
                        == Some(&AssetBundle {
                            balances: vec![AssetAmount {
                                asset,
                                quantity: self.quantity
                            }],
                            authorities: vec![]
                        }),
                "destination must receive exactly the requested positions"
            );
        }
        let (point, vault) = successor(self.anchor, &self.market, contracts)?;
        ensure!(
            vault.output.state == [0; 32],
            "market has resolved; pair issuance no longer matches intent"
        );
        let amount = vault
            .output
            .amount
            .msats
            .checked_add(cost)
            .ok_or_else(|| anyhow::anyhow!("vault collateral overflow"))?;
        let output = wallet.output(
            &vault.descriptor,
            Amount::from_msats(amount),
            [0; 32],
            vault
                .output
                .bundle()
                .expect("validated vault bundle")
                .clone(),
        )?;
        let mut issuance = vec![
            AssetAmount {
                asset: self.market.yes,
                quantity: self.quantity,
            },
            AssetAmount {
                asset: self.market.no,
                quantity: self.quantity,
            },
        ];
        issuance.sort_by_key(|a| a.asset);
        Ok(IntentPlan {
            spends: vec![SpendIntent {
                outpoint: point,
                signature_witness: None,
                witnesses: witnesses([
                    ("ACTION", Value::u8(0)),
                    ("OUTCOME", Value::u8(0)),
                    ("ORACLE_SIGNATURE", crate::placeholder_signature()),
                ]),
            }],
            outputs: vec![
                output,
                self.yes_destination.clone(),
                self.no_destination.clone(),
                ContractOutput::action_output(AssetActions {
                    issuance,
                    ..Default::default()
                }),
            ],
            shared_inputs: vec![point],
        })
    }
}

fn matches_market(output: &ContractOutput, market: &BinaryMarket, cmr: [u8; 32]) -> bool {
    let mut authorities = vec![market.yes, market.no];
    authorities.sort();
    output.version == crate::common::assets::ASSET_VERSION
        && output.cmr == cmr
        && output.bundle()
            == Some(&AssetBundle {
                balances: vec![],
                authorities,
            })
}

/// Match actual consuming transaction IDs as well as the unique authority
/// capability. An unrelated output with the same CMR is never a successor.
fn successor<'a>(
    mut point: OutPoint,
    market: &BinaryMarket,
    contracts: &'a BTreeMap<OutPoint, WalletContract>,
) -> anyhow::Result<(OutPoint, &'a WalletContract)> {
    let cmr = market.program()?.cmr();
    for _ in 0..=contracts.len() {
        let vault = contracts.get(&point).ok_or_else(|| {
            anyhow::anyhow!("unknown market anchor; watch its authenticated history first")
        })?;
        ensure!(
            matches_market(&vault.output, market, cmr),
            "invalid market vault"
        );
        let Some(spent_by) = vault.spent_by else {
            return Ok((point, vault));
        };
        let candidates = contracts
            .iter()
            .filter(|(p, c)| p.txid == spent_by && matches_market(&c.output, market, cmr))
            .collect::<Vec<_>>();
        ensure!(
            candidates.len() == 1,
            "missing or ambiguous market successor"
        );
        point = *candidates[0].0;
    }
    anyhow::bail!("cyclic market history")
}

impl SimplicityClientModule {
    /// Discover an existing public vault using immutable asset origins and
    /// authenticated session history. This one-time scan also handles a vault
    /// that has advanced before the wallet first learned about the market.
    /// Watching alone is local; an accepted interaction carries an encrypted
    /// descriptor so mnemonic recovery rediscovers that participation.
    pub async fn watch_market(&self, market: &BinaryMarket) -> anyhow::Result<OutPoint> {
        ensure!(
            market.federation == self.store.federation && market.module == self.store.module,
            "wrong market scope"
        );
        let mut origins = vec![];
        for asset in [market.yes, market.no] {
            let record: Option<AssetRecord> = self
                .context
                .module_api()
                .request_current_consensus("asset".to_owned(), ApiRequestErased::new(asset))
                .await?;
            origins.push(record.ok_or_else(|| anyhow::anyhow!("unknown market asset"))?);
        }
        market.validate_genesis(&origins[0], &origins[1])?;
        self.sync().await?;
        let _guard = self.store.sync_lock.lock().await;
        let origin = origins[0].authority_outpoint;
        let cmr = market.program()?.cmr();
        let descriptor = ContractDescriptor::binary_market(rand::random(), market);
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
                _ => anyhow::bail!("market history has not caught up to wallet cursor"),
            };
            let count = if index == next {
                usize::try_from(open_len)?
            } else {
                items.len()
            };
            ensure!(items.len() >= count, "market history prefix regressed");
            for (position, item) in items.into_iter().take(count).enumerate() {
                let ConsensusItem::Transaction(transaction) = item.item else {
                    continue;
                };
                let txid = transaction.tx_hash();
                let mut consumed = vec![];
                let mut received = vec![];
                for input in &transaction.inputs {
                    if input.module_instance_id() != market.module {
                        continue;
                    }
                    let input = input
                        .as_any()
                        .downcast_ref::<ContractInput>()
                        .ok_or_else(|| anyhow::anyhow!("wrong input decoder"))?;
                    if let Some(old) = chain.get_mut(&input.outpoint) {
                        ensure!(old.spent_by.is_none(), "market history double spend");
                        old.spent_by = Some(txid);
                        consumed.push(input.outpoint);
                    }
                }
                for (out_idx, output) in transaction.outputs.iter().enumerate() {
                    if output.module_instance_id() != market.module {
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
                    if (point == origin || !consumed.is_empty())
                        && matches_market(output, market, cmr)
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
        let (current, _) = successor(origin, market, &chain)?;
        let mut tx = self.store.db.begin_transaction().await;
        let mut changed = false;
        for (point, mut contract) in chain {
            if let Some(existing) = tx.get_value(&db::ContractKey(point)).await {
                ensure!(
                    existing.output == contract.output && existing.spent_by == contract.spent_by,
                    "market watch disagrees with wallet history"
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
                    "market watch history mismatch"
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

#[cfg(test)]
mod tests;
