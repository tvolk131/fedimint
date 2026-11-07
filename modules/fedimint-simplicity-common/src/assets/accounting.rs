//! Pure asset conservation and authority checks shared by guardians and local
//! diagnostics. Call after structural bounds, using one module instance only.
//!
//! Nothing here reads guardian ledger state. Callers must separately establish
//! that created namespaces and asset IDs are unused and that every other asset
//! already exists.
use std::collections::BTreeMap;

use fedimint_core::config::FederationId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::secp256k1::{Message, SECP256K1};

use super::{AssetActions, AssetCreation, AssetId, MAX_ASSETS, asset_id};
use crate::{ContractError, ContractOutput};

#[cfg(test)]
mod tests;

#[derive(Default)]
pub struct Balance {
    consumed: u128,
    created: u128,
    issued: u128,
    burned: u128,
    consumed_authorities: u32,
    created_authorities: u32,
}

pub fn balances<'a>(
    inputs: impl IntoIterator<Item = &'a ContractOutput>,
    outputs: impl IntoIterator<Item = &'a ContractOutput>,
    actions: &AssetActions,
) -> Result<BTreeMap<AssetId, Balance>, ContractError> {
    let mut balances = BTreeMap::<AssetId, Balance>::new();
    for input in inputs {
        if let Some(bundle) = input.bundle() {
            for value in &bundle.balances {
                balances.entry(value.asset).or_default().consumed += u128::from(value.quantity);
            }
            for id in &bundle.authorities {
                balances.entry(*id).or_default().consumed_authorities += 1;
            }
        }
    }
    for output in outputs {
        if let Some(bundle) = output.bundle() {
            for value in &bundle.balances {
                balances.entry(value.asset).or_default().created += u128::from(value.quantity);
            }
            for id in &bundle.authorities {
                balances.entry(*id).or_default().created_authorities += 1;
            }
        }
    }
    for value in &actions.issuance {
        balances.entry(value.asset).or_default().issued += u128::from(value.quantity);
    }
    for value in &actions.burns {
        balances.entry(value.asset).or_default().burned += u128::from(value.quantity);
    }
    if balances.len() > MAX_ASSETS {
        return Err(ContractError::Limit);
    }
    Ok(balances)
}

/// An original authority placed by a creation, as validated by
/// [`check_creation`].
#[derive(Debug)]
pub struct CreatedAuthority<'a> {
    pub id: AssetId,
    pub ordinal: u32,
    /// Outer output index holding the original authority.
    pub output_index: u32,
    pub output: &'a ContractOutput,
}

/// Verify one creation's signature, then derive each ordinal's asset ID and
/// check that its authority output carries it, returning the authorities in
/// ordinal order.
///
/// `intent` is the transaction's [`super::signature_hash`] and `output`
/// resolves an outer output index to this module instance's contract output.
/// The caller owns every check against other creations or ledger state, such
/// as namespace use, duplicate IDs and existing assets.
pub fn check_creation<'a>(
    federation: FederationId,
    module: ModuleInstanceId,
    creation: &AssetCreation,
    intent: [u8; 32],
    output: impl Fn(u32) -> Option<&'a ContractOutput>,
) -> Result<Vec<CreatedAuthority<'a>>, ContractError> {
    SECP256K1
        .verify_schnorr(
            &creation.signature,
            &Message::from_digest(intent),
            &creation.key.x_only_public_key().0,
        )
        .map_err(|_| ContractError::CreationSignature)?;
    creation
        .authority_outputs
        .iter()
        .enumerate()
        .map(|(ordinal, &output_index)| {
            let ordinal = ordinal as u32;
            let id = asset_id(federation, module, creation.key, ordinal);
            let authority = output(output_index)
                .filter(|candidate| {
                    candidate
                        .bundle()
                        .is_some_and(|bundle| bundle.authorities.contains(&id))
                })
                .ok_or(ContractError::Assets)?;
            Ok(CreatedAuthority {
                id,
                ordinal,
                output_index,
                output: authority,
            })
        })
        .collect()
}

impl Balance {
    /// `created` assets are born in this transaction and must start empty with
    /// one authority; any other asset follows the conservation rules. The
    /// caller must additionally establish that a non-created asset exists.
    pub fn check(&self, created: bool) -> Result<(), ContractError> {
        if created {
            self.check_genesis()
        } else {
            self.check_existing()
        }
    }

    fn check_genesis(&self) -> Result<(), ContractError> {
        // No balances or issuance may exist at genesis. Only one authority.
        if self.consumed != 0
            || self.created != 0
            || self.issued != 0
            || self.burned != 0
            || self.consumed_authorities != 0
            || self.created_authorities != 1
        {
            return Err(ContractError::Assets);
        }
        Ok(())
    }

    fn check_existing(&self) -> Result<(), ContractError> {
        if self.consumed_authorities > 1
            || self.created_authorities > self.consumed_authorities
            || (self.issued != 0 && self.consumed_authorities != 1)
        {
            return Err(ContractError::Assets);
        }
        if self.consumed + self.issued != self.created + self.burned {
            return Err(ContractError::Assets);
        }
        Ok(())
    }
}
