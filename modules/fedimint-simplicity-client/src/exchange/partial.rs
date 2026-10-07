//! Fixed-price orders whose unique successor accumulates the maker's proceeds.
use super::*;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct PartialLimitOrder {
    pub module: ModuleInstanceId,
    pub maker: XOnlyPublicKey,
    pub asset: AssetId,
    /// Exact millisatoshis per indivisible position; fees are separate.
    pub unit_price: Amount,
    pub buy: bool,
    pub close_block: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrderState {
    pub remaining: u64,
    pub bitcoin_proceeds: Amount,
    pub position_proceeds: u64,
}

impl OrderState {
    pub fn new(remaining: u64) -> Self {
        Self {
            remaining,
            bitcoin_proceeds: Amount::ZERO,
            position_proceeds: 0,
        }
    }
}

impl PartialLimitOrder {
    pub fn program(&self) -> anyhow::Result<ContractProgram> {
        ensure!(
            self.unit_price.msats > 0 && self.close_block > 0,
            "invalid order terms"
        );
        ContractProgram::compile(
            include_str!("../../contracts/partial_order.simf"),
            arguments([
                ("MAKER", word(self.maker.serialize())),
                ("ASSET", word(self.asset.0)),
                ("PRICE", Value::u64(self.unit_price.msats)),
                ("BUY", Value::from(self.buy)),
                ("CLOSE", Value::u64(self.close_block)),
            ]),
        )
    }

    pub fn payment(&self, quantity: u64) -> anyhow::Result<Amount> {
        ensure!(self.unit_price.msats > 0, "empty order price");
        Ok(Amount::from_msats(
            quantity
                .checked_mul(self.unit_price.msats)
                .context("order price overflow")?,
        ))
    }

    pub fn state(&self, output: &ContractOutput) -> anyhow::Result<OrderState> {
        ensure!(
            output.version == 1 && output.cmr == self.program()?.cmr() && output.state == [0; 32],
            "wrong order policy"
        );
        let bundle = output.bundle().context("missing order assets")?;
        ensure!(
            bundle.authorities.is_empty()
                && bundle.balances.iter().all(|v| v.asset == self.asset)
                && bundle.balances.len() <= 1,
            "unexpected order assets"
        );
        let positions = bundle.balances.first().map_or(0, |v| v.quantity);
        if self.buy {
            ensure!(
                output.amount.msats % self.unit_price.msats == 0,
                "inexact order escrow"
            );
            Ok(OrderState {
                remaining: output.amount.msats / self.unit_price.msats,
                bitcoin_proceeds: Amount::ZERO,
                position_proceeds: positions,
            })
        } else {
            Ok(OrderState {
                remaining: positions,
                bitcoin_proceeds: output.amount,
                position_proceeds: 0,
            })
        }
    }

    pub fn balances(&self, state: OrderState) -> anyhow::Result<(Amount, AssetBundle)> {
        ensure!(
            if self.buy {
                state.bitcoin_proceeds == Amount::ZERO
            } else {
                state.position_proceeds == 0
            },
            "wrong proceeds denomination"
        );
        Ok(if self.buy {
            (
                self.payment(state.remaining)?,
                balances(&[(self.asset, state.position_proceeds)], &[]),
            )
        } else {
            (
                state.bitcoin_proceeds,
                balances(&[(self.asset, state.remaining)], &[]),
            )
        })
    }

    pub fn fill(&self, before: OrderState, quantity: u64) -> anyhow::Result<OrderState> {
        ensure!(
            quantity > 0 && quantity <= before.remaining,
            "insufficient remaining order quantity"
        );
        self.balances(before)?;
        let mut after = before;
        after.remaining -= quantity;
        if self.buy {
            after.position_proceeds = after
                .position_proceeds
                .checked_add(quantity)
                .context("position proceeds overflow")?;
        } else {
            after.bitcoin_proceeds = Amount::from_msats(
                after
                    .bitcoin_proceeds
                    .msats
                    .checked_add(self.payment(quantity)?.msats)
                    .context("bitcoin proceeds overflow")?,
            );
        }
        self.balances(after)?;
        Ok(after)
    }

    pub fn witnesses(maker_action: bool, remaining: u64, fill: u64) -> WitnessValues {
        witnesses([
            ("MAKER_ACTION", Value::from(maker_action)),
            ("REMAINING", Value::u64(remaining)),
            ("FILL", Value::u64(fill)),
            ("SIGNATURE", placeholder_signature()),
        ])
    }
}
