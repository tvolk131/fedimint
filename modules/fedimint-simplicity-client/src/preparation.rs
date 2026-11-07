//! Read-only transaction preparation shared by quotes and submission.
//!
//! Preparation turns a [`TransactionPlan`], the wallet's authenticated contract
//! records and one pruning snapshot into the explicit side of a transaction:
//! compiled programs, draft witnesses, pruned draft inputs, the sender receipt
//! output and the authorization finalization will use. It writes nothing,
//! reserves nothing and never touches the network. Submission adds reservations
//! and funding in its own database transaction and finalization re-validates
//! the funded transaction, so a prepared quote never authorizes a spend.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use anyhow::{Context as _, ensure};
use fedimint_client_module::transaction::{ClientInput, FeeQuoteRequest};
use fedimint_core::core::{DynInput, DynOutput};
use fedimint_core::module::Amounts;
use fedimint_core::secp256k1::Keypair;
use fedimint_core::transaction::{Transaction, TransactionSignature};
use fedimint_core::{Amount, OutPoint};

use crate::authorization::{Authorization, PreparedSpend};
use crate::common::{ContractInput, ContractOutput};
use crate::compiler::{TemplateProgramWitness, WitnessNameToValueMap, WitnessValues};
use crate::pruning::PruningSnapshot;
use crate::receipt::SenderReceipt;
use crate::wallet::{WalletContract, WalletStore};
use crate::{SpendIntent, common};

#[cfg(test)]
mod tests;

/// An owned, application-neutral description of the explicit side of one
/// Simplicity transaction. Quotes and submission start from the same plan, so a
/// quote prepares exactly what submission would. Semantic layers such as
/// intents build plans; nothing here knows about them.
#[derive(Clone, Default)]
pub struct TransactionPlan {
    /// Contracts to spend. An empty list is a direct send of owned funding.
    pub spends: Vec<SpendIntent>,
    /// Explicit outputs. A sender receipt output is added automatically when
    /// no owned contract makes the transaction recoverable.
    pub outputs: Vec<ContractOutput>,
    /// Fresh asset-creation keys. Only submission signs with them, after
    /// funding fixes the transaction; quotes never use them.
    pub creations: Vec<Keypair>,
    /// Include this encrypted sender receipt even when owned contracts already
    /// identify the transaction.
    pub receipt: Option<SenderReceipt>,
    /// Ceiling on the total fee of the funded transaction, enforced again by
    /// finalization after note selection.
    pub max_fee: Option<Amount>,
}

impl TransactionPlan {
    /// The rule finalization applies to the funded transaction's total fee:
    /// a fee equal to the ceiling is accepted. Quotes use the same boundary but
    /// remain point-in-time, since note inventory may change before submission.
    pub fn check_fee_ceiling(&self, total_fee: Amount) -> anyhow::Result<()> {
        if let Some(limit) = self.max_fee {
            ensure!(
                total_fee <= limit,
                "fee {total_fee} exceeds the fee ceiling {limit}"
            );
        }
        Ok(())
    }
}

/// Witnesses and creation keys are secret wallet material; show shape only.
impl fmt::Debug for TransactionPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransactionPlan")
            .field(
                "spends",
                &self
                    .spends
                    .iter()
                    .map(|spend| spend.outpoint)
                    .collect::<Vec<_>>(),
            )
            .field("outputs", &self.outputs.len())
            .field("creations", &self.creations.len())
            .field("receipt", &self.receipt.is_some())
            .field("max_fee", &self.max_fee)
            .finish()
    }
}

/// The explicit side of a plan, ready for core funding or for a fee quote.
///
/// Draft inputs carry signatures over a zero-nonce draft only so pruning can
/// execute the program. They size fees and are discarded: finalization prunes
/// and signs again against the funded transaction and checks that the fee did
/// not change.
pub(crate) struct PreparedTransaction {
    /// Pruned draft inputs in spend order, each with its claim key and amount.
    pub inputs: Vec<ClientInput<ContractInput>>,
    /// Explicit outputs including any sender receipt output.
    pub outputs: Vec<ContractOutput>,
    pub authorization: Authorization,
}

impl PreparedTransaction {
    /// Summarize explicit amounts and fees for the core funding dry run.
    pub(crate) fn fee_request(&self) -> anyhow::Result<FeeQuoteRequest> {
        let mut input_amount = 0u64;
        let mut input_fee = 0u64;
        for input in &self.inputs {
            input_amount = input_amount
                .checked_add(input.amounts.get_bitcoin().msats)
                .context("quote amount overflow")?;
            input_fee = input_fee
                .checked_add(common::runtime::input_fee(&input.input)?.msats)
                .context("quote fee overflow")?;
        }
        let mut output_amount = 0u64;
        let mut output_fee = 0u64;
        for output in &self.outputs {
            output_amount = output_amount
                .checked_add(output.amount.msats)
                .context("quote amount overflow")?;
            output_fee = output_fee
                .checked_add(common::output_fee(output).msats)
                .context("quote fee overflow")?;
        }
        output_amount
            .checked_add(input_fee)
            .and_then(|value| value.checked_add(output_fee))
            .context("quote funding overflow")?;
        Ok(FeeQuoteRequest {
            input_amount: Amounts::new_bitcoin(Amount::from_msats(input_amount)),
            output_amount: Amounts::new_bitcoin(Amount::from_msats(output_amount)),
            input_fee: Amounts::new_bitcoin(Amount::from_msats(input_fee)),
            output_fee: Amounts::new_bitcoin(Amount::from_msats(output_fee)),
        })
    }
}

impl WalletStore {
    /// Validate and prepare `plan` against authenticated wallet records and
    /// one pruning snapshot. `contracts` must hold a record for every spend;
    /// the snapshot's federation observation must agree with it.
    pub(crate) fn prepare_transaction(
        &self,
        plan: &TransactionPlan,
        contracts: &BTreeMap<OutPoint, WalletContract>,
        snapshot: &PruningSnapshot,
    ) -> anyhow::Result<PreparedTransaction> {
        ensure!(
            !plan.spends.is_empty() || !plan.outputs.is_empty(),
            "empty contract operation"
        );
        let mut seen = BTreeSet::new();
        for spend in &plan.spends {
            ensure!(
                seen.insert(spend.outpoint),
                "contract is spent twice in one transaction"
            );
        }
        for output in &plan.outputs {
            common::consensus::check_execution_version(output.version, snapshot.consensus_version)?;
        }
        let mut inputs = vec![];
        let mut prepared = vec![];
        let mut recoverable = false;
        for spend in &plan.spends {
            let contract = contracts.get(&spend.outpoint).context("unknown contract")?;
            ensure!(
                contract.spent_by.is_none(),
                "contract has already been spent"
            );
            recoverable |= self.has_recovery_descriptor(&contract.output)?;
            let observed = snapshot
                .contracts
                .get(&spend.outpoint)
                .context("missing pruning input context")?;
            ensure!(
                observed.output == contract.output
                    && observed.creation_session == contract.creation_session,
                "pruning context differs from authenticated wallet history"
            );
            common::consensus::check_execution_version(
                observed.output.version,
                snapshot.consensus_version,
            )?;
            let (version, program) = self
                .keys
                .program(&contract.descriptor, self.templates.as_ref())?;
            let key = self.keys.signing_key(&contract.descriptor);
            let mut witnesses = spend.witnesses.as_inner().as_ref().clone();
            if let Some(name) = &spend.signature_witness {
                witnesses.insert(
                    TemplateProgramWitness::witness_from_str(name.as_str()),
                    crate::placeholder_signature(),
                );
            }
            inputs.push(ClientInput {
                input: program.input(
                    spend.outpoint,
                    key.public_key(),
                    WitnessValues::from_map(witnesses),
                )?,
                keys: vec![key],
                amounts: Amounts::new_bitcoin(contract.output.amount),
            });
            prepared.push(PreparedSpend {
                outpoint: spend.outpoint,
                version,
                key,
                program,
                witnesses: spend.witnesses.clone(),
                signature_witness: spend.signature_witness.clone(),
            });
        }
        let mut outputs = plan.outputs.clone();
        let receipt = self.prepare_receipt(recoverable, &mut outputs, plan.receipt.clone())?;
        let authorization = Authorization {
            federation: self.federation,
            module: self.module,
            spends: prepared,
            creations: plan.creations.clone(),
            receipt,
            max_fee: plan.max_fee,
            snapshot: snapshot.clone(),
        };
        let mut draft = Transaction {
            inputs: inputs
                .iter()
                .map(|input| DynInput::from_typed(self.module, input.input.clone()))
                .collect(),
            outputs: outputs
                .iter()
                .cloned()
                .map(|output| DynOutput::from_typed(self.module, output))
                .collect(),
            nonce: [0; 8],
            signatures: TransactionSignature::NaiveMultisig(vec![]),
        };
        for (index, input) in authorization.pruned_inputs(&draft)? {
            inputs[index].input = input
                .as_any()
                .downcast_ref::<ContractInput>()
                .expect("authorization returns Simplicity inputs")
                .clone();
            draft.inputs[index] = input;
        }
        common::resources::check_transaction(&draft)?;
        Ok(PreparedTransaction {
            inputs,
            outputs,
            authorization,
        })
    }
}
