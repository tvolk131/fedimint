use std::fmt;

use fedimint_client_module::transaction::TransactionFinalizer;
use fedimint_core::OutPoint;
use fedimint_core::config::FederationId;
use fedimint_core::core::{DynInput, DynOutput, ModuleInstanceId};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::transaction::Transaction;

use crate::compiler::{TemplateProgramWitness, WitnessNameToValueMap, WitnessValues};
use crate::{ContractProgram, assets, common};

#[cfg(test)]
mod tests;

pub(crate) struct PreparedSpend {
    pub outpoint: OutPoint,
    pub version: u32,
    pub key: Keypair,
    pub program: ContractProgram,
    pub witnesses: WitnessValues,
    pub signature_witness: Option<String>,
}

pub(crate) struct Authorization {
    pub federation: FederationId,
    pub module: ModuleInstanceId,
    pub spends: Vec<PreparedSpend>,
    pub creations: Vec<Keypair>,
    pub receipt: Option<crate::receipt::ReceiptPlan>,
    pub max_fee: Option<fedimint_core::Amount>,
    pub snapshot: crate::pruning::PruningSnapshot,
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorization")
            .field("module", &self.module)
            .finish_non_exhaustive()
    }
}

impl TransactionFinalizer for Authorization {
    fn verify_fees(&self, fees: &fedimint_core::module::Amounts) -> Result<(), anyhow::Error> {
        if let Some(limit) = self.max_fee {
            for (unit, amount) in fees.clone() {
                if unit != fedimint_core::module::AmountUnit::BITCOIN || amount > limit {
                    return Err(anyhow::Error::msg("intent fee budget exceeded"));
                }
            }
        }
        Ok(())
    }

    fn prepare_outputs(&self, tx: &Transaction) -> Result<Vec<(usize, DynOutput)>, anyhow::Error> {
        self.receipt
            .as_ref()
            .map(|plan| {
                plan.prepare(tx)
                    .map(|output| vec![(plan.output_index, output)])
                    .map_err(anyhow::Error::msg)
            })
            .unwrap_or_else(|| Ok(vec![]))
    }

    fn verify_finalized(&self, tx: &Transaction) -> Result<(), anyhow::Error> {
        // Fail while construction/funding is still rollbackable, rather than
        // submitting an over-budget attempt with reserved notes.
        common::resources::check_transaction(tx).map_err(anyhow::Error::msg)?;
        if let Some(plan) = &self.receipt {
            plan.verify(tx).map_err(anyhow::Error::msg)?;
        }
        Ok(())
    }

    fn finalize_outputs(&self, tx: &Transaction) -> Result<Vec<(usize, DynOutput)>, anyhow::Error> {
        let mut signed = tx.clone();
        for key in &self.creations {
            assets::sign_creation(&mut signed, self.federation, self.module, key)
                .map_err(anyhow::Error::msg)?;
        }
        Ok(signed
            .outputs
            .into_iter()
            .enumerate()
            .filter(|(index, output)| *output != tx.outputs[*index])
            .collect())
    }

    fn finalize_inputs(&self, tx: &Transaction) -> Result<Vec<(usize, DynInput)>, anyhow::Error> {
        let inputs = self.pruned_inputs(tx)?;
        for (index, input) in &inputs {
            let fee = |input: &DynInput| -> anyhow::Result<_> {
                let input = input
                    .as_any()
                    .downcast_ref::<common::ContractInput>()
                    .ok_or_else(|| anyhow::anyhow!("invalid Simplicity input"))?;
                Ok(common::runtime::input_fee(input)?)
            };
            anyhow::ensure!(
                fee(input)? == fee(&tx.inputs[*index])?,
                "funding changed pruning fees; construct this contract with a complete transaction environment"
            );
        }
        Ok(inputs)
    }
}

impl Authorization {
    pub(crate) fn pruned_inputs(&self, tx: &Transaction) -> anyhow::Result<Vec<(usize, DynInput)>> {
        self.spends
            .iter()
            .enumerate()
            .map(|(index, spend)| {
                let mut witnesses = spend.witnesses.as_inner().as_ref().clone();
                if let Some(name) = &spend.signature_witness {
                    let signature = match spend.version {
                        common::EXECUTION_VERSION => {
                            crate::signature_value(self.federation, self.module, tx, &spend.key)
                        }
                        common::assets::ASSET_VERSION => {
                            assets::signature_value(self.federation, self.module, tx, &spend.key)
                        }
                        _ => return Err(anyhow::Error::msg("unsupported execution version")),
                    }
                    .map_err(anyhow::Error::msg)?;
                    witnesses.insert(
                        TemplateProgramWitness::witness_from_str(name.as_str()),
                        signature,
                    );
                }
                let input = spend
                    .program
                    .input_with_environment(
                        spend.outpoint,
                        spend.key.public_key(),
                        WitnessValues::from_map(witnesses),
                        &self
                            .snapshot
                            .environment(self.federation, self.module, tx, index)?,
                    )
                    .map_err(anyhow::Error::msg)?;
                Ok((index, DynInput::from_typed(self.module, input)))
            })
            .collect()
    }
}
