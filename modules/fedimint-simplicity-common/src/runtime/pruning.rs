//! Match upstream Simplicity's CHECK_EXEC and CHECK_CASE anti-DoS rules.
//! Track during the one normal execution; do not prune/re-execute on guardians.
use std::collections::HashMap;

use simplicity::bit_machine::{ExecTracker, FrameIter, NodeOutput};
use simplicity::dag::{DagLike as _, InternalSharing};
use simplicity::node::Inner;
use simplicity::{Ihr, RedeemNode};

use crate::ContractError;

const EXECUTED: u8 = 1;
const LEFT: u8 = 2;
const RIGHT: u8 = 4;

#[derive(Default)]
pub(super) struct Execution {
    visits: HashMap<Ihr, u8>,
}

impl ExecTracker for Execution {
    fn visit_node(&mut self, node: &RedeemNode, mut input: FrameIter, _output: NodeOutput) {
        let flags = self.visits.entry(node.ihr()).or_default();
        *flags |= EXECUTED;
        if matches!(node.inner(), Inner::Case(..)) {
            *flags |= if input.next().expect("a case input starts with a sum tag") {
                RIGHT
            } else {
                LEFT
            };
        }
    }
}

impl Execution {
    pub(super) fn check(&self, program: &RedeemNode) -> Result<(), ContractError> {
        // Decoding enforces maximal sharing. IHR identifies a node including
        // its witness and types, not merely its policy commitment. Hidden
        // children of assertions are CMRs, not revealed RedeemNodes.
        for item in program.post_order_iter::<InternalSharing>() {
            let required = if matches!(item.node.inner(), Inner::Case(..)) {
                EXECUTED | LEFT | RIGHT
            } else {
                EXECUTED
            };
            if self.visits.get(&item.node.ihr()).copied().unwrap_or(0) != required {
                return Err(ContractError::Rejected);
            }
        }
        Ok(())
    }
}
