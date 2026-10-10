//! Pure asset conservation and authority checks shared by guardians and local
//! diagnostics. Call after structural bounds, using one module instance only.
use std::collections::BTreeMap;

use super::{AssetActions, AssetId, MAX_ASSETS};
use crate::{ContractError, ContractOutput};

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

impl Balance {
    pub fn check_genesis(&self) -> Result<(), ContractError> {
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

    /// The caller must additionally establish that the asset exists.
    pub fn check_existing(&self) -> Result<(), ContractError> {
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
