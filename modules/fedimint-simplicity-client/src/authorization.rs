use std::fmt;

use fedimint_client_module::error::ClientModuleError;
use fedimint_client_module::transaction::TransactionFinalizer;
use fedimint_core::OutPoint;
use fedimint_core::config::FederationId;
use fedimint_core::core::{DynInput, DynOutput, ModuleInstanceId};
use fedimint_core::secp256k1::Keypair;
use fedimint_core::transaction::Transaction;

use crate::compiler::{TemplateProgramWitness, WitnessNameToValueMap, WitnessValues};
use crate::{ContractProgram, assets, common};

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
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authorization")
            .field("module", &self.module)
            .finish_non_exhaustive()
    }
}

impl TransactionFinalizer for Authorization {
    fn finalize_outputs(
        &self,
        tx: &Transaction,
    ) -> Result<Vec<(usize, DynOutput)>, ClientModuleError> {
        let mut signed = tx.clone();
        for key in &self.creations {
            assets::sign_creation(&mut signed, self.federation, self.module, key)
                .map_err(ClientModuleError::other)?;
        }
        Ok(signed
            .outputs
            .into_iter()
            .enumerate()
            .filter(|(index, output)| *output != tx.outputs[*index])
            .collect())
    }

    fn finalize_inputs(
        &self,
        tx: &Transaction,
    ) -> Result<Vec<(usize, DynInput)>, ClientModuleError> {
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
                        _ => return Err(ClientModuleError::other("unsupported execution version")),
                    }
                    .map_err(ClientModuleError::other)?;
                    witnesses.insert(
                        TemplateProgramWitness::witness_from_str(name.as_str()),
                        signature,
                    );
                }
                let input = spend
                    .program
                    .input(
                        spend.outpoint,
                        spend.key.public_key(),
                        WitnessValues::from_map(witnesses),
                    )
                    .map_err(ClientModuleError::other)?;
                Ok((index, DynInput::from_typed(self.module, input)))
            })
            .collect()
    }
}
