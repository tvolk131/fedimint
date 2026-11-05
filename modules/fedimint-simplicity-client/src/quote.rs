//! Read-only quotes for complete spending plans; finalization checks fees
//! again.
use anyhow::{Context as _, ensure};
use fedimint_client_module::transaction::FeeQuoteRequest;
use fedimint_core::Amount;
use fedimint_core::core::{DynInput, DynOutput, OperationId};
use fedimint_core::module::{AmountUnit, Amounts};
use fedimint_core::transaction::{Transaction, TransactionSignature};

use crate::compiler::{TemplateProgramWitness, WitnessNameToValueMap, WitnessValues};
use crate::intent::{IntentContext, IntentPlan};
use crate::{LOG_CLIENT_SIMPLICITY_TIMING, SimplicityClientModule, common};

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

    /// Calculate explicit amounts/fees and enforce consensus resource bounds.
    /// Requires at least one tracked input, so submission adds no automatic
    /// sender receipt. The caller supplies the complete output list.
    pub fn plan_fee_request(
        &self,
        plan: &IntentPlan,
        context: &IntentContext,
        snapshot: &crate::pruning::PruningSnapshot,
    ) -> anyhow::Result<FeeQuoteRequest> {
        ensure!(
            !plan.spends.is_empty(),
            "fee quote requires a spending plan"
        );
        let mut input_amount = 0u64;
        let mut input_fee = 0u64;
        let mut inputs = vec![];
        let mut prepared = vec![];
        for spend in &plan.spends {
            let contract = context
                .contracts
                .get(&spend.outpoint)
                .context("unknown quote input")?;
            ensure!(contract.spent_by.is_none(), "quote input is spent");
            let (version, program) = self
                .store
                .keys
                .program(&contract.descriptor, self.store.templates.as_ref())?;
            let mut witnesses = spend.witnesses.as_inner().as_ref().clone();
            if let Some(name) = &spend.signature_witness {
                witnesses.insert(
                    TemplateProgramWitness::witness_from_str(name.as_str()),
                    crate::placeholder_signature(),
                );
            }
            let input = program.input(
                spend.outpoint,
                self.descriptor_key(&contract.descriptor).public_key(),
                WitnessValues::from_map(witnesses),
            )?;
            input_amount = input_amount
                .checked_add(contract.output.amount.msats)
                .context("quote amount overflow")?;
            let observed = snapshot
                .contracts
                .get(&spend.outpoint)
                .context("missing pruning input context")?;
            ensure!(
                observed.output == contract.output
                    && observed.creation_session == contract.creation_session,
                "pruning context differs from authenticated wallet history"
            );
            prepared.push(crate::authorization::PreparedSpend {
                outpoint: spend.outpoint,
                version,
                program,
                key: self.descriptor_key(&contract.descriptor),
                witnesses: spend.witnesses.clone(),
                signature_witness: spend.signature_witness.clone(),
            });
            inputs.push(DynInput::from_typed(self.store.module, input));
        }
        let mut output_amount = 0u64;
        let mut output_fee = 0u64;
        for output in &plan.outputs {
            output_amount = output_amount
                .checked_add(output.amount.msats)
                .context("quote amount overflow")?;
            output_fee = output_fee
                .checked_add(common::output_fee(output).msats)
                .context("quote fee overflow")?;
        }
        let mut draft = Transaction {
            inputs,
            outputs: plan
                .outputs
                .iter()
                .cloned()
                .map(|output| DynOutput::from_typed(self.store.module, output))
                .collect(),
            nonce: [0; 8],
            signatures: TransactionSignature::NaiveMultisig(vec![]),
        };
        let authorization = crate::authorization::Authorization {
            federation: self.store.federation,
            module: self.store.module,
            spends: prepared,
            creations: vec![],
            receipt: None,
            max_fee: None,
            snapshot: snapshot.clone(),
        };
        for (index, input) in authorization.pruned_inputs(&draft)? {
            input_fee = input_fee
                .checked_add(
                    common::runtime::input_fee(
                        input
                            .as_any()
                            .downcast_ref::<common::ContractInput>()
                            .expect("authorization returns Simplicity inputs"),
                    )?
                    .msats,
                )
                .context("quote fee overflow")?;
            draft.inputs[index] = input;
        }
        output_amount
            .checked_add(input_fee)
            .and_then(|value| value.checked_add(output_fee))
            .context("quote funding overflow")?;
        common::resources::check_transaction(&draft)?;
        Ok(FeeQuoteRequest {
            input_amount: Amounts::new_bitcoin(Amount::from_msats(input_amount)),
            output_amount: Amounts::new_bitcoin(Amount::from_msats(output_amount)),
            input_fee: Amounts::new_bitcoin(Amount::from_msats(input_fee)),
            output_fee: Amounts::new_bitcoin(Amount::from_msats(output_fee)),
        })
    }

    /// Use the core client's exact primary-module funding/change dry run. This
    /// reserves nothing; note inventory may change before actual submission.
    pub async fn quote_plan(
        &self,
        plan: &IntentPlan,
        context: &IntentContext,
    ) -> anyhow::Result<Amount> {
        let started = fedimint_core::time::now();
        let snapshot = self
            .pruning_snapshot(plan.spends.iter().map(|spend| spend.outpoint))
            .await?;
        let request = self.plan_fee_request(plan, context, &snapshot)?;
        tracing::debug!(
            target: LOG_CLIENT_SIMPLICITY_TIMING,
            operation = "quote_plan", stage = "explicit_fee",
            elapsed_us = started.elapsed().unwrap_or_default().as_micros() as u64,
            "stage complete"
        );
        self.quote_fee_request(request).await
    }

    /// Quote total fees from an already calculated request. Route planners can
    /// inspect the result of `plan_fee_request` before this funding dry run
    /// without preparing and decoding every input a second time. The request
    /// describes a quote only: it reserves no notes and authorizes no spend.
    /// Submission still constructs and validates the actual transaction.
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
