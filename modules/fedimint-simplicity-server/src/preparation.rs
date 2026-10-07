//! Read the snapshot first, then prepare every instance before any VM runs.
use std::collections::BTreeMap;
use std::sync::Arc;

use fedimint_core::core::{DynInputError, ModuleInstanceId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::transaction::TransactionError;
use fedimint_server_core::{ModuleTransactionContext, ModuleTransactionValidation};
use fedimint_simplicity_common::assets::ASSET_VERSION;
use fedimint_simplicity_common::{ContractError, ContractInput, resources, runtime};
use simplicity::{Cost, RedeemNode};

use crate::db::{ContractKey, StoredContract};

mod retention;
#[cfg(test)]
mod tests;

type Resolved = BTreeMap<usize, StoredContract>;

/// Local optimization only, not a consensus limit or a bound on process RSS.
/// The current decoder, accounting scratch space and VM are additional memory.
const RETENTION_BUDGET: usize = 8 * 1024 * 1024;

pub(crate) struct Prepared {
    pub contracts: Resolved,
    pub programs: BTreeMap<usize, Option<Arc<RedeemNode>>>,
}

fn input_error(instance: ModuleInstanceId, error: ContractError) -> TransactionError {
    TransactionError::Input(DynInputError::from_typed(instance, error))
}

pub(crate) async fn resolve(
    dbtx: &mut DatabaseTransaction<'_>,
    context: &ModuleTransactionContext<'_>,
) -> Result<ModuleTransactionValidation, TransactionError> {
    let mut contracts = Resolved::new();
    for (index, input) in context.transaction.inputs.iter().enumerate() {
        if input.module_instance_id() != context.module_instance_id {
            continue;
        }
        let error = |error| input_error(context.module_instance_id, error);
        let input = input
            .as_any()
            .downcast_ref::<ContractInput>()
            .ok_or_else(|| error(ContractError::Context))?;
        let stored = dbtx
            .get_value(&ContractKey(input.outpoint))
            .await
            .ok_or_else(|| error(ContractError::UnknownContract))?;
        if stored.output.version > ASSET_VERSION {
            return Err(error(ContractError::Version));
        }
        contracts.insert(index, stored);
    }
    Ok(ModuleTransactionValidation::new(contracts))
}

pub(crate) fn prepare(
    context: &ModuleTransactionContext<'_>,
    instances: BTreeMap<ModuleInstanceId, ModuleTransactionValidation>,
) -> Result<ModuleTransactionValidation, TransactionError> {
    prepare_with_budget(context, instances, RETENTION_BUDGET).map(ModuleTransactionValidation::new)
}

fn prepare_with_budget(
    context: &ModuleTransactionContext<'_>,
    instances: BTreeMap<ModuleInstanceId, ModuleTransactionValidation>,
    mut remaining: usize,
) -> Result<Prepared, TransactionError> {
    let mut contracts = Resolved::new();
    for (instance, resolved) in instances {
        contracts.extend(
            resolved
                .into_inner::<Resolved>()
                .map_err(|_| input_error(instance, ContractError::MissingContext))?,
        );
    }
    // Repeat the cheap check so this hook also has a safe standalone boundary.
    let mut cost =
        resources::check_signed_structure(context.transaction, context.module_instance_id)?;
    let mut programs = BTreeMap::new();
    for (index, input) in context.transaction.inputs.iter().enumerate() {
        let Some(contract) = input.as_any().downcast_ref::<ContractInput>() else {
            continue;
        };
        let error = |error| input_error(input.module_instance_id(), error);
        let stored = contracts
            .get(&index)
            .ok_or_else(|| error(ContractError::MissingContext))?;
        let program = runtime::decode_program(contract).map_err(error)?;
        cost = cost + program.bounds().cost;
        if cost > Cost::from_milliweight(resources::MAX_TRANSACTION_MILLIWEIGHT) {
            return Err(error(ContractError::Limit));
        }
        runtime::check_commitment(&program, &stored.output).map_err(error)?;
        // A cache miss changes only performance. Every input has already passed
        // decoding, cost, version and commitment checks before execution starts.
        let retained = retention::charge(&program, remaining).map(|charge| {
            remaining -= charge;
            program
        });
        programs.insert(index, retained);
    }
    Ok(Prepared {
        contracts,
        programs,
    })
}

pub(crate) fn get<'a>(
    context: &ModuleTransactionContext<'a>,
) -> Result<&'a Prepared, TransactionError> {
    context
        .preparation
        .and_then(ModuleTransactionValidation::get)
        .ok_or_else(|| input_error(context.module_instance_id, ContractError::MissingContext))
}
