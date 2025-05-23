use std::io::{Error, Write};
use std::str::FromStr;

use bitcoin::secp256k1::{self, PublicKey, Secp256k1, Signing, Verification};
use fedimint_core::encoding::{Decodable, Encodable};
use miniscript::bitcoin::hashes::{hash160, ripemd160, sha256};
use miniscript::{MiniscriptKey, ToPublicKey, hash256};
use serde::{Deserialize, Serialize};

use crate::tweakable::{Contract, Tweakable};

#[derive(
    Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Serialize, Deserialize, Decodable,
)]
pub struct CompressedPublicKey {
    pub key: PublicKey,
}

impl CompressedPublicKey {
    pub fn new(key: PublicKey) -> Self {
        CompressedPublicKey { key }
    }
}

impl Encodable for CompressedPublicKey {
    fn consensus_encode<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        self.key.serialize().consensus_encode(writer)
    }
}

impl MiniscriptKey for CompressedPublicKey {
    fn is_uncompressed(&self) -> bool {
        false
    }

    fn num_der_paths(&self) -> usize {
        0
    }

    type Sha256 = miniscript::bitcoin::hashes::sha256::Hash;
    type Hash256 = miniscript::hash256::Hash;
    type Ripemd160 = miniscript::bitcoin::hashes::ripemd160::Hash;
    type Hash160 = miniscript::bitcoin::hashes::hash160::Hash;
}

impl ToPublicKey for CompressedPublicKey {
    fn to_public_key(&self) -> miniscript::bitcoin::PublicKey {
        miniscript::bitcoin::PublicKey {
            compressed: true,
            inner: self.key,
        }
    }

    fn to_sha256(hash: &<Self as MiniscriptKey>::Sha256) -> sha256::Hash {
        *hash
    }

    fn to_hash256(hash: &<Self as MiniscriptKey>::Hash256) -> hash256::Hash {
        *hash
    }

    fn to_ripemd160(hash: &<Self as MiniscriptKey>::Ripemd160) -> ripemd160::Hash {
        *hash
    }

    fn to_hash160(hash: &<Self as MiniscriptKey>::Hash160) -> hash160::Hash {
        *hash
    }
}

impl std::fmt::Display for CompressedPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.key, f)
    }
}

impl FromStr for CompressedPublicKey {
    type Err = secp256k1::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(CompressedPublicKey {
            key: PublicKey::from_str(s)?,
        })
    }
}

impl Tweakable for CompressedPublicKey {
    fn tweak<Ctx: Verification + Signing, Ctr: Contract>(
        &self,
        tweak: &Ctr,
        secp: &Secp256k1<Ctx>,
    ) -> Self {
        CompressedPublicKey {
            key: self.key.tweak(tweak, secp),
        }
    }
}

impl From<CompressedPublicKey> for bitcoin::PublicKey {
    fn from(key: CompressedPublicKey) -> Self {
        bitcoin::PublicKey {
            compressed: true,
            inner: key.key,
        }
    }
}
