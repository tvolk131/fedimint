//! Resolve every spent contract from the snapshot, then decode and check
//! every program, before any program runs.
use std::collections::BTreeMap;
use std::sync::Arc;

use fedimint_core::core::{DynInputError, ModuleInstanceId};
use fedimint_core::db::{DatabaseTransaction, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::transaction::TransactionError;
use fedimint_server_core::ModuleTransactionContext;
use fedimint_simplicity_common::consensus::check_execution_version;
use fedimint_simplicity_common::{ContractError, ContractInput, limits, runtime};
use simplicity::{Cost, RedeemNode};

use crate::db::{ContractKey, StoredContract};
use crate::executor::{Admission, Executor};

mod cache;
pub(crate) use cache::ProgramCache;
mod retention;
#[cfg(test)]
mod tests;

/// This instance's spent contracts, by outer input index.
pub(crate) type Resolved = BTreeMap<usize, StoredContract>;

/// Local optimization only, not a consensus limit or a bound on process RSS.
/// The current decoder, accounting scratch space and VM are additional memory.
const RETENTION_BUDGET: usize = 8 * 1024 * 1024;

pub(crate) struct Prepared {
    pub contracts: Resolved,
    pub programs: BTreeMap<usize, Option<Arc<RedeemNode>>>,
    /// Held until the programs are freed. Execution runs under it too.
    pub admission: Admission,
    /// Decodes programs that preparation did not retain.
    pub cache: Arc<ProgramCache>,
}

impl Drop for Prepared {
    fn drop(&mut self) {
        let programs = std::mem::take(&mut self.programs);
        if programs.values().any(Option::is_some) {
            self.admission.clone().release(programs);
        }
    }
}

fn input_error(instance: ModuleInstanceId, error: ContractError) -> TransactionError {
    TransactionError::Input(DynInputError::from_typed(instance, error))
}

pub(crate) async fn resolve(
    dbtx: &mut DatabaseTransaction<'_>,
    context: &ModuleTransactionContext<'_>,
    active: ModuleConsensusVersion,
) -> Result<Resolved, TransactionError> {
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
        check_execution_version(stored.output.version, active).map_err(error)?;
        contracts.insert(index, stored);
    }
    let output_error = |error| {
        TransactionError::Output(fedimint_core::core::DynOutputError::from_typed(
            context.module_instance_id,
            fedimint_simplicity_common::ContractOutputError(error),
        ))
    };
    for output in &context.transaction.outputs {
        if output.module_instance_id() == context.module_instance_id {
            let Some(output) = output
                .as_any()
                .downcast_ref::<fedimint_simplicity_common::SimplicityOutput>()
                .ok_or_else(|| output_error(ContractError::Context))?
                .contract()
            else {
                continue;
            };
            check_execution_version(output.version, active).map_err(output_error)?;
        }
    }
    Ok(contracts)
}

/// Decode this instance's programs and check their cost and commitments.
/// `cost` is the instance's creation charge from the structure check.
pub(crate) async fn prepare(
    executor: &Arc<Executor>,
    cache: &Arc<ProgramCache>,
    context: &ModuleTransactionContext<'_>,
    contracts: Resolved,
    cost: Cost,
) -> Result<Prepared, TransactionError> {
    let decoding = Decoding::new(context, contracts, cost);
    if decoding.inputs.is_empty() {
        return decoding.run(
            RETENTION_BUDGET,
            executor.unlimited(context.mode),
            cache.clone(),
        );
    }
    // Wait before decoding, so waiting submissions hold no programs.
    let admission = executor.admit(context.mode).await;
    let held = admission.clone();
    let cache = cache.clone();
    admission
        .run(move || decoding.run(RETENTION_BUDGET, held, cache))
        .await
}

/// Owned copy of everything decoding reads, so it can run off the async
/// runtime.
struct Decoding {
    instance: ModuleInstanceId,
    contracts: Resolved,
    /// Cost of the signed structure, before any program.
    cost: Cost,
    /// This instance's inputs with their transaction indices.
    inputs: Vec<(usize, ContractInput)>,
}

impl Decoding {
    fn new(context: &ModuleTransactionContext<'_>, contracts: Resolved, cost: Cost) -> Self {
        let inputs = context
            .transaction
            .inputs
            .iter()
            .enumerate()
            .filter(|(_, input)| input.module_instance_id() == context.module_instance_id)
            .filter_map(|(index, input)| {
                let contract = input.as_any().downcast_ref::<ContractInput>()?;
                Some((index, contract.clone()))
            })
            .collect();
        Self {
            instance: context.module_instance_id,
            contracts,
            cost,
            inputs,
        }
    }

    fn run(
        self,
        mut remaining: usize,
        admission: Admission,
        cache: Arc<ProgramCache>,
    ) -> Result<Prepared, TransactionError> {
        let Self {
            instance,
            contracts,
            mut cost,
            inputs,
        } = self;
        let error = |error| input_error(instance, error);
        let mut programs = BTreeMap::new();
        for (index, contract) in &inputs {
            let stored = contracts
                .get(index)
                .ok_or_else(|| error(ContractError::UnknownContract))?;
            let decoded = cache.decode(contract).map_err(error)?;
            cost = cost + decoded.program.bounds().cost;
            if cost > Cost::from_milliweight(limits::MAX_TRANSACTION_MILLIWEIGHT) {
                return Err(error(ContractError::Limit));
            }
            runtime::check_commitment(&decoded.program, &stored.output).map_err(error)?;
            // Only programs that match a stored contract enter the shared cache.
            let (program, charge) = cache.keep(decoded);
            // A cache miss changes only performance. Every input has already passed
            // decoding, cost, version and commitment checks before execution starts.
            let retained = charge.filter(|charge| *charge <= remaining).map(|charge| {
                remaining -= charge;
                program
            });
            programs.insert(*index, retained);
        }
        Ok(Prepared {
            contracts,
            programs,
            admission,
            cache,
        })
    }
}

impl ProgramCache {
    /// Decode an input that preparation did not retain. Preparation has
    /// already matched its program to a stored contract, so a fresh decoding
    /// may be cached.
    pub(crate) fn decode_matched(
        &self,
        input: &ContractInput,
    ) -> Result<Arc<RedeemNode>, ContractError> {
        self.decode(input).map(|decoded| self.keep(decoded).0)
    }
}
