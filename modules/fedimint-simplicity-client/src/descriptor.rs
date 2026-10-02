//! Wallet-owned descriptors and encrypted annotations. Guardians only store
//! the resulting bytes; template interpretation is not a consensus rule.
use std::fmt;

use anyhow::{Context as _, ensure};
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::{Keypair, SECP256K1, XOnlyPublicKey};
use fedimint_derive_secret::DerivableSecret;
use serde::{Deserialize, Serialize};

use crate::compiler::{Value, ValueConstructible, arguments};
use crate::{ContractProgram, TOP_UP_OR_RELEASE, common, market};

const ENVELOPE: &[u8; 4] = b"FMS1";
const DESCRIPTOR_VERSION: u16 = 1;

/// A software-defined template plus the wallet-specific data needed to recover
/// it. Template identifiers and versions must keep their historical meaning.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ContractDescriptor {
    pub template: String,
    pub template_version: u32,
    pub parameters: Vec<u8>,
    /// Random derivation salt, carried inside the encrypted annotation. No
    /// sequential key counter or external address-book backup is required.
    pub key_nonce: [u8; 32],
    /// Application context or additional secrets, recoverable with the record.
    pub application_data: Vec<u8>,
}

impl fmt::Debug for ContractDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContractDescriptor")
            .field("template", &self.template)
            .field("template_version", &self.template_version)
            .finish_non_exhaustive()
    }
}

impl ContractDescriptor {
    pub fn owner(key_nonce: [u8; 32]) -> Self {
        Self {
            template: "owner".to_owned(),
            template_version: 1,
            parameters: vec![],
            key_nonce,
            application_data: vec![],
        }
    }

    pub fn top_up(key_nonce: [u8; 32], min_session: u64, min_block_count: u64) -> Self {
        Self {
            template: "top-up-or-release".to_owned(),
            parameters: (min_session, min_block_count).consensus_encode_to_vec(),
            ..Self::owner(key_nonce)
        }
    }

    pub fn binary_market(key_nonce: [u8; 32], market: &market::BinaryMarket) -> Self {
        Self {
            template: "binary-market".to_owned(),
            parameters: market.consensus_encode_to_vec(),
            ..Self::owner(key_nonce)
        }
    }
}

/// Wallet applications can provide additional templates without teaching
/// guardians their policy or storing contract source outside the federation.
pub trait ContractTemplates: fmt::Debug + Send + Sync {
    fn compile(
        &self,
        descriptor: &ContractDescriptor,
        owner: XOnlyPublicKey,
    ) -> anyhow::Result<(u32, ContractProgram)>;
}

#[derive(Debug)]
pub struct BuiltinTemplates;

impl ContractTemplates for BuiltinTemplates {
    fn compile(
        &self,
        descriptor: &ContractDescriptor,
        owner: XOnlyPublicKey,
    ) -> anyhow::Result<(u32, ContractProgram)> {
        ensure!(
            descriptor.template_version == 1,
            "unsupported template version"
        );
        match descriptor.template.as_str() {
            "owner" => {
                ensure!(
                    descriptor.parameters.is_empty(),
                    "unexpected owner parameters"
                );
                Ok((common::assets::ASSET_VERSION, market::owner_program(owner)?))
            }
            "top-up-or-release" => {
                let (min_session, min_block_count) = <(u64, u64)>::consensus_decode_whole(
                    &descriptor.parameters,
                    &Default::default(),
                )?;
                Ok((
                    common::EXECUTION_VERSION,
                    ContractProgram::compile(
                        TOP_UP_OR_RELEASE,
                        arguments([
                            ("OWNER", market::word(owner.serialize())),
                            ("MIN_SESSION", Value::u64(min_session)),
                            ("MIN_BLOCK_COUNT", Value::u64(min_block_count)),
                        ]),
                    )?,
                ))
            }
            "binary-market" => {
                let market = market::BinaryMarket::consensus_decode_whole(
                    &descriptor.parameters,
                    &Default::default(),
                )?;
                Ok((common::assets::ASSET_VERSION, market.program()?))
            }
            _ => anyhow::bail!("unsupported contract template: {}", descriptor.template),
        }
    }
}

/// Secrets are scoped to both federation and module even when callers supply
/// the same root. Spending and annotation encryption use separate derivations.
#[derive(Clone)]
pub struct WalletKeys {
    secret: DerivableSecret,
}

impl fmt::Debug for WalletKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletKeys").finish_non_exhaustive()
    }
}

impl WalletKeys {
    pub fn new(root: &DerivableSecret, federation: FederationId, module: ModuleInstanceId) -> Self {
        Self {
            secret: root.tweak(
                &(
                    "fedimint/simplicity/wallet/v1".to_owned(),
                    federation,
                    module,
                )
                    .consensus_encode_to_vec(),
            ),
        }
    }

    pub fn signing_key(&self, descriptor: &ContractDescriptor) -> Keypair {
        self.secret
            .tweak(b"spending")
            .tweak(&descriptor.key_nonce)
            .to_secp_key(SECP256K1)
    }

    fn encryption_key(&self) -> fedimint_aead::LessSafeKey {
        fedimint_aead::LessSafeKey::new(self.secret.tweak(b"recovery").to_chacha20_poly1305_key())
    }

    /// Receivers produce this annotation and hand it to senders along with the
    /// destination policy. Senders need neither a wallet identifier nor a view
    /// key. Reusing an annotation would link outputs; generate a fresh one for
    /// each receive request.
    pub fn encrypt(&self, descriptor: &ContractDescriptor) -> anyhow::Result<Vec<u8>> {
        let plaintext = (DESCRIPTOR_VERSION, descriptor.clone()).consensus_encode_to_vec();
        ensure!(
            plaintext.len() + ENVELOPE.len() + 12 + 16 <= common::MAX_RECOVERY_BYTES,
            "descriptor exceeds the recovery annotation limit"
        );
        let mut annotation = ENVELOPE.to_vec();
        annotation.extend(fedimint_aead::encrypt(plaintext, &self.encryption_key())?);
        Ok(annotation)
    }

    /// An unauthenticatable record belongs to another wallet (or is malformed)
    /// and is ignored. Once authenticated, an unknown or malformed descriptor
    /// is an error: do not silently finish recovery with missing owned state.
    pub fn decrypt(&self, annotation: &[u8]) -> anyhow::Result<Option<ContractDescriptor>> {
        if annotation.len() > common::MAX_RECOVERY_BYTES || !annotation.starts_with(ENVELOPE) {
            return Ok(None);
        }
        let mut ciphertext = annotation[ENVELOPE.len()..].to_vec();
        let Ok(plaintext) = fedimint_aead::decrypt(&mut ciphertext, &self.encryption_key()) else {
            return Ok(None);
        };
        // Version is inside the authenticated ciphertext so a future template
        // version owned by this wallet cannot be mistaken for somebody else's.
        let (version, descriptor) =
            <(u16, ContractDescriptor)>::consensus_decode_whole(plaintext, &Default::default())
                .context("invalid authenticated recovery descriptor")?;
        ensure!(
            version == DESCRIPTOR_VERSION,
            "unsupported recovery descriptor version"
        );
        Ok(Some(descriptor))
    }

    pub fn program(
        &self,
        descriptor: &ContractDescriptor,
        templates: &dyn ContractTemplates,
    ) -> anyhow::Result<(u32, ContractProgram)> {
        templates.compile(
            descriptor,
            self.signing_key(descriptor).x_only_public_key().0,
        )
    }
}

#[cfg(test)]
mod tests;
