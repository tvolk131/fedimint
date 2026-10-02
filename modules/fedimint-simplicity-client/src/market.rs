//! Example policy, not guardian-specific market logic. Quantities are integer
//! positions: winners pay 1000 msat/unit; INVALID pays 500 msat to either side.
use bitcoin::hashes::Hash;
use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::encoding::Encodable;
use fedimint_core::secp256k1::XOnlyPublicKey;

use crate::ContractProgram;
use crate::common::assets::AssetId;
use crate::compiler::{U256, Value, ValueConstructible, arguments};

pub const BINARY_MARKET: &str = include_str!("../contracts/binary_market.simf");
pub const ASSET_OWNER: &str = include_str!("../contracts/asset_owner.simf");

#[derive(Debug, Clone)]
pub struct BinaryMarket {
    pub federation: FederationId,
    pub module: ModuleInstanceId,
    pub yes: AssetId,
    pub no: AssetId,
    pub event: [u8; 32],
    pub rules: [u8; 32],
    pub oracle: XOnlyPublicKey,
    pub resolution_start: u64,
    pub deadline: u64,
}

impl BinaryMarket {
    /// Oracle signatures cannot be reused across markets, outcomes, rules,
    /// federations, module instances, or settlement windows.
    pub fn attestation_message(&self, outcome: u8) -> anyhow::Result<[u8; 32]> {
        anyhow::ensure!(
            (1..=3).contains(&outcome),
            "expected YES=1, NO=2, or INVALID=3"
        );
        let terms = (
            self.yes,
            self.no,
            self.event,
            self.rules,
            self.oracle,
            (self.resolution_start, self.deadline),
        )
            .consensus_hash_sha256()
            .to_byte_array();
        Ok((
            "fedimint/simplicity/binary-market/attestation/v1".to_owned(),
            self.federation,
            self.module,
            terms,
            outcome,
        )
            .consensus_hash_sha256()
            .to_byte_array())
    }

    /// Verify the immutable origins before treating these IDs as positions in
    /// this market. Records must come from the client's federation consensus
    /// API, not from an untrusted issuer or a current-vault-only inspection.
    pub fn validate_genesis(
        &self,
        yes: &crate::common::assets::AssetRecord,
        no: &crate::common::assets::AssetRecord,
    ) -> anyhow::Result<()> {
        use crate::common::assets::asset_id;
        let cmr = self.program()?.cmr();
        anyhow::ensure!(
            yes.authority_outpoint == no.authority_outpoint,
            "market authorities must originate together"
        );
        for (id, record) in [(self.yes, yes), (self.no, no)] {
            anyhow::ensure!(
                asset_id(
                    self.federation,
                    self.module,
                    record.creation_key,
                    record.ordinal
                ) == id,
                "asset origin does not match ID"
            );
            anyhow::ensure!(
                record.authority_cmr == cmr && record.authority_state == [0; 32],
                "asset was not created under the unresolved market policy"
            );
        }
        Ok(())
    }

    pub fn program(&self) -> anyhow::Result<ContractProgram> {
        anyhow::ensure!(
            self.yes != self.no && self.resolution_start < self.deadline,
            "invalid market terms"
        );
        ContractProgram::compile(
            BINARY_MARKET,
            arguments([
                ("YES", word(self.yes.0)),
                ("NO", word(self.no.0)),
                ("ORACLE", word(self.oracle.serialize())),
                ("YES_MESSAGE", word(self.attestation_message(1)?)),
                ("NO_MESSAGE", word(self.attestation_message(2)?)),
                ("INVALID_MESSAGE", word(self.attestation_message(3)?)),
                ("RESOLUTION_START", Value::u64(self.resolution_start)),
                ("DEADLINE", Value::u64(self.deadline)),
            ]),
        )
    }
}

pub fn word(bytes: [u8; 32]) -> Value {
    Value::u256(U256::from_byte_array(bytes))
}

pub fn owner_program(owner: XOnlyPublicKey) -> anyhow::Result<ContractProgram> {
    ContractProgram::compile(ASSET_OWNER, arguments([("OWNER", word(owner.serialize()))]))
}

pub fn state(outcome: u8) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(outcome <= 3, "unknown market state");
    let mut state = [0; 32];
    state[31] = outcome;
    Ok(state)
}
