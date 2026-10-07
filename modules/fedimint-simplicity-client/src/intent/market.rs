use std::collections::BTreeMap;

use anyhow::ensure;
use fedimint_api_client::api::FederationApiExt as _;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped as _;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ApiRequestErased;
use fedimint_core::{Amount, OutPoint};
use serde::{Deserialize, Serialize};

use super::{Intent, IntentPlan};
use crate::common::ContractOutput;
use crate::common::assets::{AssetActions, AssetAmount, AssetBundle, AssetRecord};
use crate::compiler::{Value, ValueConstructible, witnesses};
use crate::descriptor::ContractDescriptor;
use crate::market::BinaryMarket;
use crate::wallet::WalletContract;
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
            max_fee: None,
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
        self.watch_market_with_progress(market, &|_| {}).await
    }

    /// Observe catch-up for this market without changing its authentication or
    /// completion requirements.
    pub async fn watch_market_with_progress(
        &self,
        market: &BinaryMarket,
        progress: &(dyn Fn(crate::wallet::SyncProgress) + Send + Sync),
    ) -> anyhow::Result<OutPoint> {
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
        let descriptor = ContractDescriptor::binary_market(rand::random(), market);
        let origin = origins[0].authority_outpoint;
        // An authenticated stored genesis already has continuous scan coverage.
        // An owned successor alone is insufficient: importing must still replay
        // its origin to establish backing and preserve earlier public history.
        if self
            .store
            .db
            .begin_transaction_nc()
            .await
            .get_value(&crate::wallet::db::ContractKey(origin))
            .await
            .is_some()
        {
            self.sync_with_progress(progress).await?;
        } else {
            self.watch_contracts_from_session_with_progress(
                vec![(origin, descriptor)],
                0,
                progress,
            )
            .await?;
        }
        // Asset records authenticate the genesis policy, but only the complete
        // transaction establishes its exact balances and authority set.
        let contracts = self.contracts().await.into_iter().collect();
        Ok(successor(origin, market, &contracts)?.0)
    }
}

#[cfg(test)]
mod tests;
