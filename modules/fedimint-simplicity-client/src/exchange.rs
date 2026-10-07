//! Limit orders and a single-provider conditional-token AMM. These are
//! client-authored covenants, with no exchange-specific guardian behavior.
use anyhow::{Context as _, ensure};
use bitcoin::hashes::Hash as _;
use fedimint_core::Amount;
use fedimint_core::core::{DynOutput, ModuleInstanceId};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

use crate::common::ContractOutput;
use crate::common::assets::{AssetAmount, AssetBundle, AssetId};
use crate::compiler::{Value, ValueConstructible, WitnessValues, arguments, witnesses};
use crate::market::{BinaryMarket, owner_program, word};
use crate::{ContractProgram, placeholder_signature};

mod partial;
pub use partial::{OrderState, PartialLimitOrder};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct LimitOrder {
    pub module: ModuleInstanceId,
    pub maker: XOnlyPublicKey,
    pub asset: AssetId,
    pub quantity: u64,
    pub price: Amount,
    /// True means the maker escrows sats to buy positions.
    pub buy: bool,
    pub close_block: u64,
    /// Exact recoverable payment to the maker. Its outer-output hash is in the
    /// covenant, so neither the taker nor another order can redirect payment.
    pub payment: ContractOutput,
}

impl LimitOrder {
    pub fn program(&self) -> anyhow::Result<ContractProgram> {
        ensure!(self.quantity > 0 && self.price.msats > 0, "empty order");
        ensure!(self.close_block > 0, "invalid order close");
        let expected = if self.buy {
            balances(&[(self.asset, self.quantity)], &[])
        } else {
            AssetBundle::default()
        };
        ensure!(
            self.payment.version == 1
                && self.payment.cmr == owner_program(self.maker)?.cmr()
                && self.payment.state == [0; 32]
                && self.payment.amount == if self.buy { Amount::ZERO } else { self.price }
                && self.payment.bundle() == Some(&expected),
            "order payment does not match its terms"
        );
        let hash = DynOutput::from_typed(self.module, self.payment.clone())
            .consensus_hash_sha256()
            .to_byte_array();
        ContractProgram::compile(
            include_str!("../contracts/limit_order.simf"),
            arguments([
                ("MAKER", word(self.maker.serialize())),
                ("PAYMENT", word(hash)),
                ("CLOSE", Value::u64(self.close_block)),
            ]),
        )
    }

    pub fn escrow(&self) -> (Amount, AssetBundle) {
        if self.buy {
            (self.price, AssetBundle::default())
        } else {
            (Amount::ZERO, balances(&[(self.asset, self.quantity)], &[]))
        }
    }

    pub fn validate_output(&self, output: &ContractOutput) -> anyhow::Result<()> {
        let (amount, bundle) = self.escrow();
        ensure!(
            output.version == 1
                && output.cmr == self.program()?.cmr()
                && output.amount == amount
                && output.bundle() == Some(&bundle),
            "order escrow does not match its terms"
        );
        Ok(())
    }

    pub fn witnesses(cancel: bool) -> WitnessValues {
        witnesses([
            ("CANCEL", Value::from(cancel)),
            ("SIGNATURE", placeholder_signature()),
        ])
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct ConstantProductPool {
    pub market: BinaryMarket,
    /// A unique issuance capability, used only as a non-copyable pool identity.
    /// No circulating LP token is created.
    pub identity: AssetId,
    pub provider: XOnlyPublicKey,
}

impl ConstantProductPool {
    pub fn program(&self) -> anyhow::Result<ContractProgram> {
        ensure!(
            self.identity != self.market.yes && self.identity != self.market.no,
            "pool identity overlaps market assets"
        );
        ContractProgram::compile(
            include_str!("../contracts/constant_product.simf"),
            arguments([
                ("POOL", word(self.identity.0)),
                ("YES", word(self.market.yes.0)),
                ("NO", word(self.market.no.0)),
                ("OWNER", word(self.provider.serialize())),
                ("VAULT", word(self.market.program()?.cmr())),
                ("CLOSE", Value::u64(self.market.resolution_start)),
            ]),
        )
    }

    pub fn reserves(&self, output: &ContractOutput) -> anyhow::Result<PoolReserves> {
        ensure!(
            output.version == 1 && output.cmr == self.program()?.cmr(),
            "wrong pool policy"
        );
        let bundle = output.bundle().context("pool is not an asset output")?;
        ensure!(
            bundle.authorities == [self.identity] && bundle.balances.len() == 2,
            "wrong pool identity or balances"
        );
        let quantity = |asset| {
            bundle
                .balances
                .iter()
                .find(|v| v.asset == asset)
                .map(|v| v.quantity)
                .context("missing pool asset")
        };
        let reserves = PoolReserves {
            yes: quantity(self.market.yes)?,
            no: quantity(self.market.no)?,
            fees: output.amount,
        };
        reserves.validate()?;
        Ok(reserves)
    }

    pub fn bundle(&self, reserves: PoolReserves) -> AssetBundle {
        balances(
            &[
                (self.market.yes, reserves.yes),
                (self.market.no, reserves.no),
            ],
            &[self.identity],
        )
    }

    /// Actions 0/1 buy YES/NO; 2/3 sell YES/NO; 4 scales liquidity; 5 closes.
    pub fn witnesses(action: u8, scale: u64) -> WitnessValues {
        witnesses([
            ("ACTION", Value::u8(action)),
            ("SCALE", Value::u64(scale)),
            ("SIGNATURE", placeholder_signature()),
        ])
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct PoolReserves {
    pub yes: u64,
    pub no: u64,
    pub fees: Amount,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PoolQuote {
    pub action: u8,
    /// Complete pairs issued or merged, each backed by one satoshi.
    pub collateral_sats: u64,
    pub positions: u64,
    /// Buy: collateral plus AMM fee. Sell: collateral less AMM fee.
    /// Federation fees are separate and bounded by the submission policy.
    pub trader_amount: Amount,
    pub fee: Amount,
    pub after: PoolReserves,
}

impl PoolReserves {
    pub fn validate(self) -> anyhow::Result<()> {
        ensure!(
            self.yes > 0 && self.no > 0 && self.yes < u64::MAX && self.no < u64::MAX,
            "pool reserves must be positive and below the integer limit"
        );
        Ok(())
    }

    fn quote(
        self,
        action: u8,
        collateral: u64,
        positions: u64,
        mut after: Self,
    ) -> anyhow::Result<PoolQuote> {
        ensure!(collateral > 0 && positions > 0, "trade is too small");
        let fee = collateral.checked_mul(3).context("fee overflow")?;
        after.fees = Amount::from_msats(
            self.fees
                .msats
                .checked_add(fee)
                .context("fee balance overflow")?,
        );
        after.validate()?;
        Ok(PoolQuote {
            action,
            collateral_sats: collateral,
            positions,
            trader_amount: Amount::from_msats(
                collateral
                    .checked_mul(if action < 2 { 1003 } else { 997 })
                    .context("trade amount overflow")?,
            ),
            fee: Amount::from_msats(fee),
            after,
        })
    }

    /// Buy using an exact collateral quantity. The 0.3% AMM fee is added to
    /// this amount. Round received positions down, preserving the product.
    pub fn buy(self, yes: bool, collateral_sats: u64) -> anyhow::Result<PoolQuote> {
        self.validate()?;
        let (selected, other) = if yes {
            (self.yes, self.no)
        } else {
            (self.no, self.yes)
        };
        let other_after = other
            .checked_add(collateral_sats)
            .context("reserve overflow")?;
        let product = u128::from(selected) * u128::from(other);
        let selected_after = u64::try_from(product.div_ceil(u128::from(other_after)))?;
        let positions = selected
            .checked_add(collateral_sats)
            .context("position overflow")?
            .checked_sub(selected_after)
            .context("invalid quote")?;
        let (y, n) = if yes {
            (selected_after, other_after)
        } else {
            (other_after, selected_after)
        };
        self.quote(
            if yes { 0 } else { 1 },
            collateral_sats,
            positions,
            Self {
                yes: y,
                no: n,
                fees: self.fees,
            },
        )
    }

    /// Sell an exact number of positions. Integer search finds the greatest
    /// safe collateral payout without relying on floating point or sqrt.
    pub fn sell(self, yes: bool, positions: u64) -> anyhow::Result<PoolQuote> {
        self.validate()?;
        let (selected, other) = if yes {
            (self.yes, self.no)
        } else {
            (self.no, self.yes)
        };
        let total = selected
            .checked_add(positions)
            .context("reserve overflow")?;
        let product = u128::from(selected) * u128::from(other);
        let (mut low, mut high) = (0, (other - 1).min(total - 1));
        while low < high {
            let mid = low + (high - low).div_ceil(2);
            if u128::from(total - mid) * u128::from(other - mid) >= product {
                low = mid;
            } else {
                high = mid - 1;
            }
        }
        let (y, n) = if yes {
            (total - low, other - low)
        } else {
            (other - low, total - low)
        };
        self.quote(
            if yes { 2 } else { 3 },
            low,
            positions,
            Self {
                yes: y,
                no: n,
                fees: self.fees,
            },
        )
    }

    /// Scale by basis points: 5000 removes half; 15000 adds half. Zero is a
    /// separate authorized close. Fees remain claimable by the sole provider.
    pub fn scale(self, basis_points: u64) -> anyhow::Result<Self> {
        self.validate()?;
        let result = Self {
            yes: u64::try_from(u128::from(self.yes) * u128::from(basis_points) / 10000)?,
            no: u64::try_from(u128::from(self.no) * u128::from(basis_points) / 10000)?,
            fees: self.fees,
        };
        result.validate()?;
        Ok(result)
    }
}

pub fn balances(values: &[(AssetId, u64)], authorities: &[AssetId]) -> AssetBundle {
    let mut balances = values
        .iter()
        .filter(|(_, q)| *q > 0)
        .map(|(asset, quantity)| AssetAmount {
            asset: *asset,
            quantity: *quantity,
        })
        .collect::<Vec<_>>();
    balances.sort_by_key(|v| v.asset);
    let mut authorities = authorities.to_vec();
    authorities.sort();
    AssetBundle {
        balances,
        authorities,
    }
}
