//! Encrypted sender activity on non-spendable action outputs.
use anyhow::{Context as _, ensure};
use bitcoin::hashes::Hash;
use fedimint_core::config::FederationId;
use fedimint_core::core::{DynOutput, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::transaction::Transaction;
use serde::{Deserialize, Serialize};

use crate::common::assets::AssetExtension;
use crate::common::{ContractInput, ContractOutput, MAX_RECOVERY_BYTES};
use crate::descriptor::WalletKeys;

const ENVELOPE: &[u8; 4] = b"FMR1";
const VERSION: u16 = 1;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ReceiptContext {
    pub application: String,
    pub version: u32,
    pub data: Vec<u8>,
}

impl std::fmt::Debug for ReceiptContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReceiptContext")
            .field("application", &self.application)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct SenderReceipt {
    pub context: Option<ReceiptContext>,
}

/// This is a wallet recovery commitment, not a contract signature hash.
/// All inputs participate: Simplicity inputs use module/outpoint/claim key;
/// foreign inputs retain their full opaque encoding. Outputs retain all bytes
/// except FMR1 action annotations and creation signatures in every instance.
/// Programs/witnesses and outer signatures are authorization, excluded to avoid
/// circularity. Funding references prevent copying a receipt to another payer.
pub fn commitment(
    federation: FederationId,
    module: ModuleInstanceId,
    tx: &Transaction,
) -> [u8; 32] {
    let inputs = tx
        .inputs
        .iter()
        .map(|input| {
            if let Some(contract) = input.as_any().downcast_ref::<ContractInput>() {
                (
                    1u8,
                    input.module_instance_id(),
                    contract.outpoint,
                    contract.claim_key,
                )
                    .consensus_encode_to_vec()
            } else {
                (0u8, input).consensus_encode_to_vec()
            }
        })
        .collect::<Vec<_>>();
    let outputs = tx
        .outputs
        .iter()
        .map(|output| {
            let Some(contract) = output.as_any().downcast_ref::<ContractOutput>() else {
                return output.clone();
            };
            let mut contract = contract.clone();
            if let Some(AssetExtension::Actions(actions)) = &mut contract.extension {
                for creation in &mut actions.creations {
                    creation.signature =
                        Signature::from_slice(&[0; 64]).expect("fixed signature length");
                }
                if contract.recovery.starts_with(ENVELOPE) {
                    contract.recovery.clear();
                }
            }
            DynOutput::from_typed(output.module_instance_id(), contract)
        })
        .collect::<Vec<_>>();
    (
        "fedimint/simplicity/sender-receipt/v1".to_owned(),
        federation,
        module,
        inputs,
        tx.nonce,
        outputs,
    )
        .consensus_hash_sha256()
        .to_byte_array()
}

#[derive(Debug, Clone)]
pub(crate) struct ReceiptPlan {
    pub keys: WalletKeys,
    pub federation: FederationId,
    pub module: ModuleInstanceId,
    pub output_index: usize,
    pub receipt: SenderReceipt,
}

impl ReceiptPlan {
    pub fn placeholder(&self) -> anyhow::Result<Vec<u8>> {
        let plaintext = ([0u8; 32], VERSION, &self.receipt).consensus_encode_to_vec();
        let len = ENVELOPE.len() + 12 + 16 + plaintext.len();
        ensure!(
            len <= MAX_RECOVERY_BYTES,
            "sender receipt exceeds the recovery annotation limit"
        );
        let mut bytes = ENVELOPE.to_vec();
        bytes.resize(len, 0);
        Ok(bytes)
    }

    pub fn prepare(&self, tx: &Transaction) -> anyhow::Result<DynOutput> {
        let original = tx
            .outputs
            .get(self.output_index)
            .context("missing sender receipt output")?;
        ensure!(
            original.module_instance_id() == self.module,
            "wrong sender receipt module"
        );
        let mut output = original
            .as_any()
            .downcast_ref::<ContractOutput>()
            .context("wrong receipt output type")?
            .clone();
        ensure!(
            output.actions().is_some(),
            "sender receipt requires an action output"
        );
        let plaintext = (
            commitment(self.federation, self.module, tx),
            VERSION,
            &self.receipt,
        )
            .consensus_encode_to_vec();
        let mut annotation = ENVELOPE.to_vec();
        annotation.extend(fedimint_aead::encrypt(plaintext, &self.keys.receipt_key())?);
        ensure!(
            annotation.len() == output.recovery.len() && annotation.len() <= MAX_RECOVERY_BYTES,
            "sender receipt changed reserved size"
        );
        output.recovery = annotation;
        Ok(DynOutput::from_typed(self.module, output))
    }

    pub fn verify(&self, tx: &Transaction) -> anyhow::Result<()> {
        let output = tx
            .outputs
            .get(self.output_index)
            .context("missing receipt output")?
            .as_any()
            .downcast_ref::<ContractOutput>()
            .context("wrong receipt output type")?;
        ensure!(
            read(
                &self.keys,
                self.federation,
                self.module,
                tx,
                &output.recovery
            )?
            .as_ref()
                == Some(&self.receipt),
            "finalization changed the sender receipt commitment"
        );
        Ok(())
    }
}

pub(crate) fn read(
    keys: &WalletKeys,
    federation: FederationId,
    module: ModuleInstanceId,
    tx: &Transaction,
    annotation: &[u8],
) -> anyhow::Result<Option<SenderReceipt>> {
    if annotation.len() > MAX_RECOVERY_BYTES || !annotation.starts_with(ENVELOPE) {
        return Ok(None);
    }
    let mut ciphertext = annotation[ENVELOPE.len()..].to_vec();
    let Ok(plaintext) = fedimint_aead::decrypt(&mut ciphertext, &keys.receipt_key()) else {
        return Ok(None);
    };
    ensure!(
        plaintext.len() >= 32,
        "invalid authenticated sender receipt commitment"
    );
    // The stable commitment prefix is checked before interpreting the version:
    // copied future records must not poison unrelated history either.
    if plaintext.get(..32) != Some(commitment(federation, module, tx).as_slice()) {
        return Ok(None);
    }
    let (_, version, receipt) =
        <([u8; 32], u16, SenderReceipt)>::consensus_decode_whole(plaintext, &Default::default())
            .context("invalid authenticated sender receipt")?;
    ensure!(version == VERSION, "unsupported sender receipt version");
    Ok(Some(receipt))
}

#[cfg(test)]
mod tests;
