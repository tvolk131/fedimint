//! Stateless limits for the complete transaction, across every Simplicity
//! instance. These are consensus constants, not guardian-local timing limits.
use std::collections::{BTreeMap, BTreeSet};

use fedimint_core::core::{DynInputError, ModuleInstanceId};
use fedimint_core::transaction::{Transaction, TransactionError, TransactionSignature};
use simplicity::Cost;

use crate::assets::{ASSET_VERSION, MAX_ASSETS, validate_amounts};
use crate::{
    ContractError, ContractInput, ContractOutput, MAX_CONTRACTS, MAX_PROGRAM_BYTES,
    MAX_RECOVERY_BYTES, MAX_WITNESS_BYTES, runtime,
};

#[cfg(test)]
mod tests;

pub const MAX_TRANSACTION_MILLIWEIGHT: u32 = 2_000_000;
pub const MAX_TRANSACTION_REDEMPTION_BYTES: usize = 16_384;
/// Creation authorization runs outside the VM. Charge it conservatively in
/// the same budget; this is a resource charge, not a change to the asset fee.
pub const CREATION_SIGNATURE_MILLIWEIGHT: u32 = 100_000;

/// Check a transaction under construction, before outer signatures exist.
/// Counts, bytes and structural faults are checked before decoding redemption
/// programs. Decode sequentially and drop each result, bounding simultaneous
/// decoder allocations. Foreign modules do not consume the Simplicity budget.
/// This does not verify funding, signatures, UTXO existence or asset
/// accounting.
pub fn check_transaction(transaction: &Transaction) -> Result<(), ContractError> {
    transaction_cost(transaction).map(|_| ())
}

/// The same unsigned resource check, retaining the aggregate static cost for
/// local diagnostics. No program executes until this whole-kind check passes.
pub fn transaction_cost(transaction: &Transaction) -> Result<Cost, ContractError> {
    let cost = check_structure(transaction)?;
    check_programs(transaction, cost)
}

/// Complete signed resource check for callers without guardian state. Guardian
/// processing separates `check_signed_structure` from decoding after resolving
/// all contracts. The unsigned client finalizer uses `check_transaction`.
pub fn check_signed_transaction(
    transaction: &Transaction,
    error_instance: ModuleInstanceId,
) -> Result<(), TransactionError> {
    let cost = check_signed_structure(transaction, error_instance)?;
    check_programs(transaction, cost)
        .map(|_| ())
        .map_err(|error| TransactionError::Input(DynInputError::from_typed(error_instance, error)))
}

/// Cheap guardian checks before state resolution. Return the creation charge
/// so kind-wide preparation can add decoded costs to the same budget.
pub fn check_signed_structure(
    transaction: &Transaction,
    error_instance: ModuleInstanceId,
) -> Result<Cost, TransactionError> {
    let input_error =
        |error| TransactionError::Input(DynInputError::from_typed(error_instance, error));
    let cost = check_structure(transaction).map_err(input_error)?;
    match &transaction.signatures {
        TransactionSignature::NaiveMultisig(signatures) => {
            if signatures.len() != transaction.inputs.len() {
                return Err(TransactionError::InvalidWitnessLength);
            }
        }
        TransactionSignature::Default { variant, .. } => {
            return Err(TransactionError::UnsupportedSignatureScheme { variant: *variant });
        }
    }
    Ok(cost)
}

fn check_structure(transaction: &Transaction) -> Result<Cost, ContractError> {
    let mut counts = BTreeMap::new();
    let mut bytes = 0usize;
    let mut cost = Cost::from_milliweight(0);
    let limit = Cost::from_milliweight(MAX_TRANSACTION_MILLIWEIGHT);
    for input in &transaction.inputs {
        if let Some(contract) = input.as_any().downcast_ref::<ContractInput>() {
            let count = counts.entry(input.module_instance_id()).or_insert(0usize);
            *count += 1;
            bytes = bytes
                .checked_add(contract.program.len())
                .and_then(|bytes| bytes.checked_add(contract.witness.len()))
                .ok_or(ContractError::Limit)?;
            if *count > MAX_CONTRACTS
                || contract.program.len() > MAX_PROGRAM_BYTES
                || contract.witness.len() > MAX_WITNESS_BYTES
                || bytes > MAX_TRANSACTION_REDEMPTION_BYTES
            {
                return Err(ContractError::Limit);
            }
        }
    }
    let has_inputs = !counts.is_empty();
    counts.clear();
    let mut has_outputs = false;
    for output in &transaction.outputs {
        if let Some(contract) = output.as_any().downcast_ref::<ContractOutput>() {
            has_outputs = true;
            let count = counts.entry(output.module_instance_id()).or_insert(0usize);
            *count += 1;
            if *count > MAX_CONTRACTS {
                return Err(ContractError::Limit);
            }
            if let Some(actions) = contract.actions() {
                let signatures =
                    u32::try_from(actions.creations.len()).map_err(|_| ContractError::Limit)?;
                let charge = signatures
                    .checked_mul(CREATION_SIGNATURE_MILLIWEIGHT)
                    .ok_or(ContractError::Limit)?;
                cost = cost + Cost::from_milliweight(charge);
                if cost > limit {
                    return Err(ContractError::Limit);
                }
            }
        }
    }
    if (has_inputs || has_outputs) && transaction.outputs.len() > 128 {
        return Err(ContractError::Limit);
    }
    // Check all cheap bounds first, even when an earlier input is malformed.
    let mut spent = BTreeSet::new();
    for input in &transaction.inputs {
        if let Some(contract) = input.as_any().downcast_ref::<ContractInput>()
            && !spent.insert((input.module_instance_id(), contract.outpoint))
        {
            return Err(ContractError::UnknownContract);
        }
    }
    let mut action_instances = BTreeSet::new();
    for output in &transaction.outputs {
        if let Some(contract) = output.as_any().downcast_ref::<ContractOutput>() {
            check_output(contract)?;
            if contract.actions().is_some() && !action_instances.insert(output.module_instance_id())
            {
                return Err(ContractError::Assets);
            }
        }
    }
    // Destination indices are outer indices, but authorities must remain in
    // their own instance. Several ordinals may deliberately share one output.
    for output in &transaction.outputs {
        if let Some(actions) = output
            .as_any()
            .downcast_ref::<ContractOutput>()
            .and_then(ContractOutput::actions)
        {
            let mut creation_keys = BTreeSet::new();
            for creation in &actions.creations {
                if !creation_keys.insert(creation.key) {
                    return Err(ContractError::NamespaceUsed);
                }
                for index in &creation.authority_outputs {
                    let destination = transaction
                        .outputs
                        .get(*index as usize)
                        .filter(|destination| {
                            destination.module_instance_id() == output.module_instance_id()
                        })
                        .and_then(|destination| {
                            destination.as_any().downcast_ref::<ContractOutput>()
                        });
                    if destination.is_none_or(|destination| destination.bundle().is_none()) {
                        return Err(ContractError::Assets);
                    }
                }
            }
        }
    }
    Ok(cost)
}

fn check_programs(transaction: &Transaction, mut cost: Cost) -> Result<Cost, ContractError> {
    let limit = Cost::from_milliweight(MAX_TRANSACTION_MILLIWEIGHT);
    for input in &transaction.inputs {
        if let Some(contract) = input.as_any().downcast_ref::<ContractInput>() {
            cost = cost + runtime::decode_program(contract)?.bounds().cost;
            if cost > limit {
                return Err(ContractError::Limit);
            }
        }
    }
    Ok(cost)
}

/// Output-only structural rules, shared with snapshot-dependent guardian
/// validation. Asset conservation, namespace existence and creation signatures
/// are checked by the guardian later.
pub fn check_output(output: &ContractOutput) -> Result<(), ContractError> {
    if output.version > ASSET_VERSION
        || (output.version == 0 && output.extension.is_some())
        || (output.version == ASSET_VERSION && output.extension.is_none())
    {
        return Err(ContractError::Version);
    }
    if output.recovery.len() > MAX_RECOVERY_BYTES || output.amount.msats > 2_100_000_000_000_000_000
    {
        return Err(ContractError::Limit);
    }
    if let Some(bundle) = output.bundle() {
        validate_amounts(&bundle.balances)?;
        if bundle.authorities.len() > MAX_ASSETS
            || !bundle.authorities.windows(2).all(|pair| pair[0] < pair[1])
        {
            return Err(ContractError::Assets);
        }
    }
    if let Some(actions) = output.actions() {
        if output.amount.msats != 0 || output.cmr != [0; 32] || output.state != [0; 32] {
            return Err(ContractError::Assets);
        }
        validate_amounts(&actions.issuance)?;
        validate_amounts(&actions.burns)?;
        if actions.creations.len() > MAX_ASSETS
            || actions.creations.iter().any(|creation| {
                creation.authority_outputs.is_empty()
                    || creation.authority_outputs.len() > MAX_ASSETS
            })
            || actions
                .creations
                .iter()
                .map(|creation| creation.authority_outputs.len())
                .sum::<usize>()
                > MAX_ASSETS
        {
            return Err(ContractError::Limit);
        }
    }
    Ok(())
}
