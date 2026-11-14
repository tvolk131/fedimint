//! Stateless limits on a transaction's Simplicity items. Every limit applies
//! to each Simplicity module instance separately, except
//! [`MAX_TRANSACTION_OUTPUTS`], which counts all outer outputs. Fedimint
//! creates one instance per module kind, so in practice these are transaction
//! limits. These are consensus constants, not guardian-local timing limits.
use std::collections::{BTreeMap, BTreeSet};

use fedimint_core::core::{DynInputError, ModuleInstanceId};
use fedimint_core::transaction::{Transaction, TransactionError, TransactionSignature};
use simplicity::Cost;

use crate::assets::validate_amounts;
use crate::limits::{
    CREATION_SIGNATURE_MILLIWEIGHT, MAX_ASSETS, MAX_CONTRACTS, MAX_PROGRAM_BYTES,
    MAX_RECOVERY_BYTES, MAX_TRANSACTION_MILLIWEIGHT, MAX_TRANSACTION_OUTPUTS,
    MAX_TRANSACTION_REDEMPTION_BYTES, MAX_WITNESS_BYTES,
};
use crate::{
    ActionOutput, ContractError, ContractInput, ContractOutput, EXECUTION_VERSION,
    SimplicityOutput, runtime,
};

#[cfg(test)]
mod tests;

/// Static cost of each Simplicity instance's items in a transaction.
pub type InstanceCosts = BTreeMap<ModuleInstanceId, Cost>;

/// Check a transaction under construction, before outer signatures exist.
/// Counts, bytes and structural faults are checked before decoding redemption
/// programs. Decode sequentially and drop each result, bounding simultaneous
/// decoder allocations. Foreign modules do not consume the Simplicity budget.
/// This does not verify funding, signatures, UTXO existence or asset
/// accounting.
pub fn check_transaction(transaction: &Transaction) -> Result<(), ContractError> {
    transaction_cost(transaction).map(|_| ())
}

/// The same unsigned resource check, retaining each instance's static cost
/// for local diagnostics.
pub fn transaction_cost(transaction: &Transaction) -> Result<InstanceCosts, ContractError> {
    let costs = check_structure(transaction)?;
    check_programs(transaction, costs)
}

/// Complete signed resource check for callers without guardian state. Guardian
/// validation separates `check_signed_structure` from decoding, which follows
/// contract resolution. The unsigned client finalizer uses `check_transaction`.
pub fn check_signed_transaction(
    transaction: &Transaction,
    error_instance: ModuleInstanceId,
) -> Result<(), TransactionError> {
    check_signed_structure(transaction, error_instance)?;
    check_structure(transaction)
        .and_then(|costs| check_programs(transaction, costs))
        .map(|_| ())
        .map_err(|error| TransactionError::Input(DynInputError::from_typed(error_instance, error)))
}

/// Cheap guardian checks before state resolution. Returns `instance`'s
/// creation charge, so validation can add its decoded programs' costs to the
/// same budget.
pub fn check_signed_structure(
    transaction: &Transaction,
    instance: ModuleInstanceId,
) -> Result<Cost, TransactionError> {
    let input_error = |error| TransactionError::Input(DynInputError::from_typed(instance, error));
    let costs = check_structure(transaction).map_err(input_error)?;
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
    Ok(costs
        .get(&instance)
        .copied()
        .unwrap_or(Cost::from_milliweight(0)))
}

/// Add `cost` to an instance's running total and check it against the budget.
pub fn charge(
    costs: &mut InstanceCosts,
    instance: ModuleInstanceId,
    cost: Cost,
) -> Result<(), ContractError> {
    let total = costs.entry(instance).or_insert(Cost::from_milliweight(0));
    *total = *total + cost;
    if *total > Cost::from_milliweight(MAX_TRANSACTION_MILLIWEIGHT) {
        return Err(ContractError::Limit);
    }
    Ok(())
}

fn check_structure(transaction: &Transaction) -> Result<InstanceCosts, ContractError> {
    let mut counts = BTreeMap::new();
    let mut bytes = BTreeMap::<ModuleInstanceId, usize>::new();
    let mut costs = InstanceCosts::new();
    for input in &transaction.inputs {
        if let Some(contract) = input.as_any().downcast_ref::<ContractInput>() {
            let instance = input.module_instance_id();
            let count = counts.entry(instance).or_insert(0usize);
            *count += 1;
            let bytes = bytes.entry(instance).or_default();
            *bytes = bytes
                .checked_add(contract.program.len())
                .and_then(|bytes| bytes.checked_add(contract.witness.len()))
                .ok_or(ContractError::Limit)?;
            if *count > MAX_CONTRACTS
                || contract.program.len() > MAX_PROGRAM_BYTES
                || contract.witness.len() > MAX_WITNESS_BYTES
                || *bytes > MAX_TRANSACTION_REDEMPTION_BYTES
            {
                return Err(ContractError::Limit);
            }
            costs.entry(instance).or_insert(Cost::from_milliweight(0));
        }
    }
    counts.clear();
    for output in &transaction.outputs {
        if let Some(simplicity) = output.as_any().downcast_ref::<SimplicityOutput>() {
            let instance = output.module_instance_id();
            let count = counts.entry(instance).or_insert(0usize);
            *count += 1;
            if *count > MAX_CONTRACTS {
                return Err(ContractError::Limit);
            }
            let signatures = simplicity
                .actions()
                .map_or(Ok(0), |action| {
                    u32::try_from(action.actions.creations.len())
                })
                .map_err(|_| ContractError::Limit)?;
            let creation = signatures
                .checked_mul(CREATION_SIGNATURE_MILLIWEIGHT)
                .ok_or(ContractError::Limit)?;
            charge(&mut costs, instance, Cost::from_milliweight(creation))?;
        }
    }
    if !costs.is_empty() && transaction.outputs.len() > MAX_TRANSACTION_OUTPUTS {
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
        if let Some(simplicity) = output.as_any().downcast_ref::<SimplicityOutput>() {
            check_output(simplicity)?;
            if simplicity.actions().is_some()
                && !action_instances.insert(output.module_instance_id())
            {
                return Err(ContractError::Assets);
            }
        }
    }
    // Destination indices are outer indices, but authorities must remain in
    // their own instance. Several ordinals may deliberately share one output.
    for output in &transaction.outputs {
        if let Some(action) = output
            .as_any()
            .downcast_ref::<SimplicityOutput>()
            .and_then(SimplicityOutput::actions)
        {
            let mut creation_keys = BTreeSet::new();
            for creation in &action.actions.creations {
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
                            destination.as_any().downcast_ref::<SimplicityOutput>()
                        });
                    if destination.is_none_or(|destination| destination.contract().is_none()) {
                        return Err(ContractError::Assets);
                    }
                }
            }
        }
    }
    Ok(costs)
}

fn check_programs(
    transaction: &Transaction,
    mut costs: InstanceCosts,
) -> Result<InstanceCosts, ContractError> {
    for input in &transaction.inputs {
        if let Some(contract) = input.as_any().downcast_ref::<ContractInput>() {
            let cost = runtime::decode_program(contract)?.bounds().cost;
            charge(&mut costs, input.module_instance_id(), cost)?;
        }
    }
    Ok(costs)
}

/// Output-only structural rules, shared with snapshot-dependent guardian
/// validation. Asset conservation, namespace existence and creation signatures
/// are checked by the guardian later.
pub fn check_output(output: &SimplicityOutput) -> Result<(), ContractError> {
    match output {
        SimplicityOutput::Contract(contract) => check_contract_output(contract),
        SimplicityOutput::Actions(action) => check_action_output(action),
        SimplicityOutput::Default { .. } => Err(ContractError::Version),
    }
}

fn check_contract_output(output: &ContractOutput) -> Result<(), ContractError> {
    if output.version != EXECUTION_VERSION {
        return Err(ContractError::Version);
    }
    if output.recovery.len() > MAX_RECOVERY_BYTES || output.amount.msats > 2_100_000_000_000_000_000
    {
        return Err(ContractError::Limit);
    }
    validate_amounts(&output.assets.balances)?;
    if output.assets.authorities.len() > MAX_ASSETS
        || !output
            .assets
            .authorities
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    {
        return Err(ContractError::Assets);
    }
    Ok(())
}

fn check_action_output(output: &ActionOutput) -> Result<(), ContractError> {
    if output.recovery.len() > MAX_RECOVERY_BYTES {
        return Err(ContractError::Limit);
    }
    let actions = &output.actions;
    validate_amounts(&actions.issuance)?;
    validate_amounts(&actions.burns)?;
    if actions.creations.len() > MAX_ASSETS
        || actions.creations.iter().any(|creation| {
            creation.authority_outputs.is_empty() || creation.authority_outputs.len() > MAX_ASSETS
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
    Ok(())
}
