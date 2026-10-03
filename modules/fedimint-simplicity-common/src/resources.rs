//! Stateless limits for the complete transaction, across every Simplicity
//! instance. These are consensus constants, not guardian-local timing limits.
use std::collections::BTreeMap;

use fedimint_core::transaction::Transaction;
use simplicity::Cost;

use crate::{
    ContractError, ContractInput, ContractOutput, MAX_CONTRACTS, MAX_PROGRAM_BYTES,
    MAX_WITNESS_BYTES, runtime,
};

#[cfg(test)]
mod tests;

pub const MAX_TRANSACTION_MILLIWEIGHT: u32 = 2_000_000;
pub const MAX_TRANSACTION_REDEMPTION_BYTES: usize = 16_384;
/// Creation authorization runs outside the VM. Charge it conservatively in
/// the same budget; this is a resource charge, not a change to the asset fee.
pub const CREATION_SIGNATURE_MILLIWEIGHT: u32 = 100_000;

/// Check a fully decoded transaction before any cryptographic verification or
/// execution. Foreign modules' inputs/outputs do not consume this budget.
/// Counts and bytes are checked before decoding any redemption program. Decode
/// sequentially and drop each result, bounding simultaneous decoder
/// allocations. This does not verify funding, signatures, UTXO existence or
/// asset accounting.
pub fn check_transaction(transaction: &Transaction) -> Result<(), ContractError> {
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
    for input in &transaction.inputs {
        if let Some(contract) = input.as_any().downcast_ref::<ContractInput>() {
            cost = cost + runtime::decode_program(contract)?.bounds().cost;
            if cost > limit {
                return Err(ContractError::Limit);
            }
        }
    }
    Ok(())
}
