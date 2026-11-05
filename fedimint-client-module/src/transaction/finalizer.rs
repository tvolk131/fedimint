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
/// All output preparation runs before output authorization, which runs before
/// input authorization. Final checks run after all replacements.
/// Implementations must not depend on authorization bytes installed by a later
/// finalizer in the same phase and must be safe to rerun after a client
/// database transaction retry.
pub trait TransactionFinalizer: Debug + MaybeSend + MaybeSync {
    /// Enforce a wallet's fee budget after funding and denomination change.
    fn verify_fees(&self, _fees: &fedimint_core::module::Amounts) -> Result<(), ClientModuleError> {
        Ok(())
    }

    /// Populate reserved metadata before any signatures can commit to it.
    fn prepare_outputs(
        &self,
        _transaction: &Transaction,
    ) -> Result<Vec<(usize, DynOutput)>, ClientModuleError> {
        Ok(vec![])
    }

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

    /// Verify invariants against the completed inner transaction. No mutations.
    fn verify_finalized(&self, _transaction: &Transaction) -> Result<(), ClientModuleError> {
        Ok(())
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
    for prepare in [true, false] {
        let mut replaced = BTreeSet::new();
        for registration in finalizers {
            let outputs = if prepare {
                registration.finalizer.prepare_outputs(transaction)?
            } else {
                registration.finalizer.finalize_outputs(transaction)?
            };
            for (index, output) in outputs {
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
    }
    let mut replaced = BTreeSet::new();
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
    for registration in finalizers {
        registration.finalizer.verify_finalized(transaction)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
