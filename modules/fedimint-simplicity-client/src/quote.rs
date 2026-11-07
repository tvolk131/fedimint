//! Read-only quotes for complete transaction plans; finalization checks fees
//! again.
use std::collections::BTreeMap;

use fedimint_client_module::transaction::FeeQuoteRequest;
use fedimint_core::core::OperationId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped as _;
use fedimint_core::module::AmountUnit;
use fedimint_core::{Amount, OutPoint};

use crate::pruning::PruningSnapshot;
use crate::wallet::{WalletContract, db};
use crate::{LOG_CLIENT_SIMPLICITY_TIMING, SimplicityClientModule, TransactionPlan};

impl SimplicityClientModule {
    pub async fn consensus_block_count(&self) -> anyhow::Result<u64> {
        use fedimint_api_client::api::FederationApiExt as _;
        Ok(self
            .context
            .module_api()
            .request_current_consensus(
                "block_count".to_owned(),
                fedimint_core::module::ApiRequestErased::new(()),
            )
            .await?)
    }

    /// Authenticated wallet records for `points`, read in one database view.
    /// Unknown outpoints are omitted; preparation reports them. Use this to
    /// build the `contracts` argument of [`Self::plan_fee_request`].
    pub async fn contracts_for(
        &self,
        points: impl IntoIterator<Item = OutPoint>,
    ) -> BTreeMap<OutPoint, WalletContract> {
        let mut view = self.store.db.begin_transaction_nc().await;
        let mut contracts = BTreeMap::new();
        for point in points {
            if let Some(contract) = view.get_value(&db::ContractKey(point)).await {
                contracts.insert(point, contract);
            }
        }
        contracts
    }

    /// Calculate explicit amounts/fees and enforce consensus resource bounds,
    /// offline. This prepares exactly what submission does for the same plan:
    /// it compiles descriptors, applies draft witnesses, compares each wallet
    /// record with the federation snapshot, prunes, and adds the sender receipt
    /// output when needed. Output-only plans are supported. The request
    /// describes a quote only: it reserves no notes and authorizes no spend.
    pub fn plan_fee_request(
        &self,
        plan: &TransactionPlan,
        contracts: &BTreeMap<OutPoint, WalletContract>,
        snapshot: &PruningSnapshot,
    ) -> anyhow::Result<FeeQuoteRequest> {
        self.store
            .prepare_transaction(plan, contracts, snapshot)?
            .fee_request()
    }

    /// Use the core client's exact primary-module funding/change dry run on the
    /// current wallet records and a fresh pruning snapshot. This reserves
    /// nothing; note inventory may change before actual submission. A plan's
    /// `max_fee` is checked with the same boundary as finalization.
    pub async fn quote_transaction(&self, plan: &TransactionPlan) -> anyhow::Result<Amount> {
        let started = fedimint_core::time::now();
        let snapshot = self
            .pruning_snapshot(plan.spends.iter().map(|spend| spend.outpoint))
            .await?;
        let contracts = self
            .contracts_for(plan.spends.iter().map(|spend| spend.outpoint))
            .await;
        let request = self.plan_fee_request(plan, &contracts, &snapshot)?;
        tracing::debug!(
            target: LOG_CLIENT_SIMPLICITY_TIMING,
            operation = "quote_transaction", stage = "explicit_fee",
            elapsed_us = started.elapsed().unwrap_or_default().as_micros() as u64,
            "stage complete"
        );
        let fee = self.quote_fee_request(request).await?;
        plan.check_fee_ceiling(fee)?;
        Ok(fee)
    }

    /// Quote total fees from an already calculated request. Route planners can
    /// inspect the result of `plan_fee_request` before this funding dry run
    /// without preparing and decoding every input a second time. The request
    /// describes a quote only: it reserves no notes and authorizes no spend.
    /// Submission still constructs and validates the actual transaction; apply
    /// [`TransactionPlan::check_fee_ceiling`] to compare with a plan's ceiling.
    pub async fn quote_fee_request(&self, request: FeeQuoteRequest) -> anyhow::Result<Amount> {
        let started = fedimint_core::time::now();
        let quote = self
            .context
            .fee_quote(OperationId::new_random(), request)
            .await?;
        tracing::debug!(
            target: LOG_CLIENT_SIMPLICITY_TIMING,
            operation = "quote_fee_request", stage = "funding_fee",
            elapsed_us = started.elapsed().unwrap_or_default().as_micros() as u64,
            "stage complete"
        );
        Ok(quote
            .total()
            .get(&AmountUnit::BITCOIN)
            .copied()
            .unwrap_or_default())
    }
}
