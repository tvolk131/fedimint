use std::collections::BTreeSet;
use std::fmt::Debug;
use std::sync::Arc;

use fedimint_core::core::{DynInput, DynOutput, ModuleInstanceId};
use fedimint_core::task::{MaybeSend, MaybeSync};
use fedimint_core::transaction::Transaction;

use crate::error::ClientModuleError;

/// Complete module authorization after funding, change, and the nonce are
/// fixed, but before the outer signatures and state-machine txids are created.
/// Replacements use outer indices and may only replace this module's existing
/// items. They must preserve amounts and fees used when balancing the builder.
/// All output finalizers run before any input finalizer. Implementations must
/// not depend on authorization bytes installed by a later finalizer in the same
/// phase and must be safe to rerun after a client database transaction retry.
pub trait TransactionFinalizer: Debug + MaybeSend + MaybeSync {
    fn finalize_outputs(
        &self,
        _transaction: &Transaction,
    ) -> Result<Vec<(usize, DynOutput)>, ClientModuleError> {
        Ok(vec![])
    }

    fn finalize_inputs(
        &self,
        _transaction: &Transaction,
    ) -> Result<Vec<(usize, DynInput)>, ClientModuleError> {
        Ok(vec![])
    }
}

#[derive(Debug, Clone)]
pub(super) struct RegisteredFinalizer {
    pub module: ModuleInstanceId,
    pub finalizer: Arc<dyn TransactionFinalizer>,
}

pub(super) fn finalize(
    transaction: &mut Transaction,
    finalizers: &[RegisteredFinalizer],
) -> Result<(), ClientModuleError> {
    let mut replaced = BTreeSet::new();
    for registration in finalizers {
        for (index, output) in registration.finalizer.finalize_outputs(transaction)? {
            let Some(original) = transaction.outputs.get_mut(index) else {
                return Err(ClientModuleError::other(
                    "finalizer output index out of bounds",
                ));
            };
            if original.module_instance_id() != registration.module
                || output.module_instance_id() != registration.module
                || !replaced.insert(index)
            {
                return Err(ClientModuleError::other(
                    "invalid finalizer output replacement",
                ));
            }
            *original = output;
        }
    }
    replaced.clear();
    for registration in finalizers {
        for (index, input) in registration.finalizer.finalize_inputs(transaction)? {
            let Some(original) = transaction.inputs.get_mut(index) else {
                return Err(ClientModuleError::other(
                    "finalizer input index out of bounds",
                ));
            };
            if original.module_instance_id() != registration.module
                || input.module_instance_id() != registration.module
                || !replaced.insert(index)
            {
                return Err(ClientModuleError::other(
                    "invalid finalizer input replacement",
                ));
            }
            *original = input;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
