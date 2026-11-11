//! Experimental PTLC settlement using ordinary BIP340 signatures and the
//! existing consensus block-count clock. Adaptor signing is entirely local.
//!
//! Both parties authorize the exact claim transaction. The funder supplies its
//! signature encrypted to the payment point; the claimant completes it with
//! the payment scalar and adds its own signature. A funder who retains the
//! encrypted signature can extract the scalar from the completed signature.
//! The funder alone can refund with its separate refund key at or after expiry.
//! This is an interactive protocol, not offline receiving or an integration
//! with a Lightning node.

use anyhow::{Context as _, ensure};
use bitcoin::hashes::{Hash as _, sha256};
use fedimint_core::secp256k1::schnorr::Signature;
use fedimint_core::secp256k1::{Keypair, PublicKey, SECP256K1, SecretKey, XOnlyPublicKey};
use schnorr_fun::adaptor::{Adaptor, EncryptedSign, EncryptedSignature};
use schnorr_fun::fun::{Point, Scalar};
use serde::{Deserialize, Serialize};

use crate::common::ContractOutput;
use crate::common::assets::AssetBundle;
use crate::compiler::{U256, Value, ValueConstructible, WitnessValues, arguments, witnesses};
use crate::{ContractProgram, placeholder_signature};

#[cfg(test)]
mod tests;

/// Public terms that both parties must authenticate before funding/signing.
/// The point commits to an exact scalar, including its sign; it is not x-only.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ptlc {
    /// Funder's claim-signing key, used only through adaptor signing.
    pub funder: XOnlyPublicKey,
    /// A separate key controlled by the funder, used only for refunds. It must
    /// differ from both claim keys to prevent cross-path signature reuse.
    pub refund: XOnlyPublicKey,
    /// Counterparty's claim-signing key.
    pub claimant: XOnlyPublicKey,
    /// Full point corresponding to the external payment scalar.
    pub payment_point: PublicKey,
    /// Agreed native bitcoin escrow, excluding its creation fee.
    pub amount: fedimint_core::Amount,
    /// Federation-agreed Bitcoin block count (tip height + 1).
    pub expiry_block_count: u64,
}

/// The selected policy branch; each branch uses a different funder key.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SpendPath {
    /// Both parties authorize collection before expiry.
    Claim,
    /// The funder's refund key authorizes collection at or after expiry.
    Refund,
}

impl Ptlc {
    /// Compile the policy after rejecting aliased signing roles or empty terms.
    pub fn program(&self) -> anyhow::Result<ContractProgram> {
        ensure!(
            self.funder != self.claimant
                && self.refund != self.funder
                && self.refund != self.claimant,
            "PTLC requires distinct claim and refund signing keys"
        );
        ensure!(self.amount.msats > 0, "PTLC amount must be positive");
        ensure!(self.expiry_block_count > 0, "PTLC expiry must be positive");
        ContractProgram::compile(
            include_str!("../contracts/ptlc.simf"),
            arguments([
                ("FUNDER", word(self.funder.serialize())),
                ("REFUNDER", word(self.refund.serialize())),
                ("CLAIMANT", word(self.claimant.serialize())),
                ("PAYMENT", word(self.payment_commitment())),
                ("EXPIRY", Value::u64(self.expiry_block_count)),
            ]),
        )
    }

    /// Commitment stored in the escrow's state and checked by both paths.
    pub fn payment_commitment(&self) -> [u8; 32] {
        sha256::Hash::hash(&self.payment_point.serialize()).to_byte_array()
    }

    /// Low-level output. Recovery bytes must be supplied by the application;
    /// the persistent wallet has no built-in PTLC descriptor.
    pub fn output(&self, recovery: Vec<u8>) -> anyhow::Result<ContractOutput> {
        self.program()?
            .output(self.amount, self.payment_commitment(), recovery)
    }

    /// Check the funded output against the agreed terms before completing a
    /// signature or making an external payment. Authenticate inclusion too.
    pub fn validate_output(&self, output: &ContractOutput) -> anyhow::Result<()> {
        ensure!(
            output.version == crate::common::EXECUTION_VERSION
                && output.bundle() == Some(&AssetBundle::default())
                && output.cmr == self.program()?.cmr()
                && output.state == self.payment_commitment()
                && output.amount == self.amount,
            "funded output does not match PTLC terms"
        );
        Ok(())
    }

    /// Assemble witnesses. `funder` is signed by the claim key for a claim or
    /// by the separate refund key for a refund. The latter ignores `claimant`.
    pub fn witnesses(path: SpendPath, funder: Value, claimant: Value) -> WitnessValues {
        witnesses([
            ("REFUND", Value::from(path == SpendPath::Refund)),
            ("FUNDER_SIGNATURE", funder),
            ("CLAIMANT_SIGNATURE", claimant),
        ])
    }

    /// Unauthorizing draft witnesses for sizing/preparation, never submission.
    pub fn placeholder_witnesses(path: SpendPath) -> WitnessValues {
        // Keep the two witnesses distinct during fee preparation, as actual
        // signatures under distinct keys will be. Always recheck the final fee.
        Self::witnesses(path, placeholder_signature(), Value::byte_array([1; 64]))
    }
}

/// Public off-chain transcript. Store it before handing it to the counterparty.
/// A completed signature reveals the payment scalar to transcript holders
/// immediately, even before transaction acceptance. Timeout margins matter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AdaptorSignature(EncryptedSignature);

impl AdaptorSignature {
    /// Sign an already domain-separated Fedimint inner digest. The underlying
    /// library includes the payment point in deterministic nonce derivation.
    pub fn encrypt(key: &Keypair, payment_point: PublicKey, digest: [u8; 32]) -> Self {
        let schnorr = schnorr_fun::new_with_deterministic_nonces::<sha2::Sha256>();
        let signing_key = schnorr.new_keypair(scalar(&key.secret_key()));
        Self(schnorr.encrypted_sign(
            &signing_key,
            &point(payment_point),
            schnorr_fun::Message::raw(&digest),
        ))
    }

    /// Check the encrypted signature's signer, exact point and inner digest.
    /// This does not approve the transaction's payout or prove its inclusion.
    pub fn verify(
        &self,
        signer: XOnlyPublicKey,
        payment_point: PublicKey,
        digest: [u8; 32],
    ) -> bool {
        let signer = Point::<schnorr_fun::fun::marker::EvenY>::from_xonly_bytes(signer.serialize())
            .expect("valid x-only secp256k1 public key");
        schnorr_fun::new_with_deterministic_nonces::<sha2::Sha256>().verify_encrypted_signature(
            &signer,
            &point(payment_point),
            schnorr_fun::Message::raw(&digest),
            &self.0,
        )
    }

    /// Verify the transcript and exact payment point before completion. The
    /// caller must separately approve outputs, funding, inclusion and
    /// deadlines.
    pub fn complete(
        &self,
        signer: XOnlyPublicKey,
        payment_point: PublicKey,
        digest: [u8; 32],
        secret: &SecretKey,
    ) -> anyhow::Result<Signature> {
        ensure!(
            self.verify(signer, payment_point, digest),
            "invalid adaptor signature"
        );
        ensure!(
            secret.public_key(SECP256K1) == payment_point,
            "wrong payment scalar"
        );
        let signature = schnorr_fun::new_with_deterministic_nonces::<sha2::Sha256>()
            .decrypt_signature(scalar(secret), self.0.clone());
        Ok(Signature::from_slice(&signature.to_bytes())?)
    }

    /// Recover the scalar from this transcript's completed signature. This is
    /// possible as soon as that signature is disclosed, without acceptance.
    pub fn extract(
        &self,
        signer: XOnlyPublicKey,
        payment_point: PublicKey,
        digest: [u8; 32],
        completed: &Signature,
    ) -> anyhow::Result<SecretKey> {
        ensure!(
            self.verify(signer, payment_point, digest),
            "invalid adaptor signature"
        );
        let signature = schnorr_fun::Signature::from_bytes(*completed.as_ref())
            .context("invalid completed signature encoding")?;
        let secret = schnorr_fun::new_with_deterministic_nonces::<sha2::Sha256>()
            .recover_decryption_key(&point(payment_point), &self.0, &signature)
            .context("signature does not complete this adaptor")?;
        Ok(SecretKey::from_slice(&secret.to_bytes())?)
    }
}

fn point(key: PublicKey) -> Point {
    Point::from_bytes(key.serialize()).expect("valid compressed secp256k1 public key")
}

fn word(bytes: [u8; 32]) -> Value {
    Value::u256(U256::from_byte_array(bytes))
}

fn scalar(key: &SecretKey) -> Scalar {
    Scalar::from_bytes(key.secret_bytes())
        .and_then(Scalar::non_zero)
        .expect("valid nonzero secp256k1 secret key")
}
