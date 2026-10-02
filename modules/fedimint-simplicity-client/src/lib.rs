//! Low-level prototype contract builder. This is not yet a persistent wallet.
pub mod assets;
pub mod descriptor;
pub mod market;

#[cfg(test)]
mod tests;

use anyhow::{anyhow, ensure};
use bitcoin::hashes::Hash;
pub use common::compiler;
use common::compiler::{Arguments, CompiledProgram, Value, ValueConstructible, WitnessValues};
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::secp256k1::{Keypair, Message, PublicKey, SECP256K1};
use fedimint_core::transaction::{Transaction, TransactionSignature};
use fedimint_core::{Amount, OutPoint};
pub use fedimint_simplicity_common as common;

/// Example contract: an owner authorizes every transition, with consensus
/// timelocks and a branch preserving the policy/state while adding collateral.
pub const TOP_UP_OR_RELEASE: &str = include_str!("../contracts/top_up_or_release.simf");

#[derive(Debug, Clone)]
pub struct ContractProgram(CompiledProgram);

impl ContractProgram {
    pub fn compile(source: &str, arguments: Arguments) -> anyhow::Result<Self> {
        compiler::compile(source, arguments)
            .map(Self)
            .map_err(|error| anyhow!(error))
    }

    pub fn cmr(&self) -> [u8; 32] {
        self.0.commit().cmr().to_byte_array()
    }

    pub fn output(
        &self,
        amount: Amount,
        state: [u8; 32],
        recovery: Vec<u8>,
    ) -> anyhow::Result<common::ContractOutput> {
        ensure!(
            recovery.len() <= common::MAX_RECOVERY_BYTES,
            "recovery annotation is too large"
        );
        Ok(common::ContractOutput {
            version: common::EXECUTION_VERSION,
            amount,
            cmr: self.cmr(),
            state,
            recovery,
            extension: None,
        })
    }

    pub fn input(
        &self,
        outpoint: OutPoint,
        claim_key: PublicKey,
        witnesses: WitnessValues,
    ) -> anyhow::Result<common::ContractInput> {
        let satisfied = self.0.satisfy(witnesses).map_err(|error| anyhow!(error))?;
        let (program, witness) = satisfied.redeem().to_vec_with_witness();
        let input = common::ContractInput {
            outpoint,
            claim_key,
            program,
            witness,
        };
        common::runtime::decode_program(&input)?;
        Ok(input)
    }
}

/// Sign the inner intent after assembling the desired outputs and claim keys.
/// Replacing placeholder program signatures does not change this message.
pub fn signature_value(
    federation: FederationId,
    module: ModuleInstanceId,
    transaction: &Transaction,
    key: &Keypair,
) -> anyhow::Result<Value> {
    let message = Message::from_digest(common::signature_hash(federation, module, transaction)?);
    let signature = SECP256K1.sign_schnorr_no_aux_rand(&message, key);
    Ok(Value::byte_array(*signature.as_ref()))
}

pub fn placeholder_signature() -> Value {
    Value::byte_array([0; 64])
}

/// Apply ordinary Fedimint signatures only after all embedded witnesses are
/// set. Callers supply one key for every outer input, in its actual transaction
/// order.
pub fn sign_transaction(transaction: &mut Transaction, keys: &[Keypair]) -> anyhow::Result<()> {
    ensure!(
        transaction.inputs.len() == keys.len(),
        "expected one key per transaction input"
    );
    let message = Message::from_digest(transaction.tx_hash().to_byte_array());
    transaction.signatures = TransactionSignature::NaiveMultisig(
        keys.iter()
            .map(|key| SECP256K1.sign_schnorr_no_aux_rand(&message, key))
            .collect(),
    );
    Ok(())
}
