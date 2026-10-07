//! Conservative cache accounting for pinned Simplicity 0.9 decoder results.
//! This is not allocator instrumentation or a transaction-validity rule.
use std::collections::BTreeSet;
use std::mem::{size_of, size_of_val};

use simplicity::RedeemNode;
use simplicity::dag::{DagLike, InternalSharing};
use simplicity::node::{Inner, RedeemData};
use simplicity::types::{CompleteBound, Final};

pub(super) fn charge(program: &RedeemNode, allowance: usize) -> Option<usize> {
    if allowance == 0 {
        return None;
    }
    let mut remaining = allowance;
    let mut types = BTreeSet::new();
    for item in program.post_order_iter::<InternalSharing>() {
        let node = item.node;
        // Include generous allowances for Arc headers, traversal bookkeeping
        // and allocation alignment, not just the inline node/data payloads.
        remaining =
            remaining.checked_sub(size_of::<RedeemNode>() + size_of::<RedeemData>() + 128)?;
        let arrow = node.arrow();
        let mut pending = vec![arrow.source.as_ref(), arrow.target.as_ref()];
        let value = match node.inner() {
            Inner::Witness(value) => Some(value),
            Inner::Word(word) => Some(word.as_value()),
            Inner::Jet(jet) => {
                remaining = remaining.checked_sub(size_of_val(jet.as_ref()) + 64)?;
                None
            }
            _ => None,
        };
        if let Some(value) = value {
            // Only fresh decoder results enter this cache. In pinned 0.9 their
            // values own padded buffers of this width; pruned/sliced Value views
            // could retain larger backing buffers and must not use this charge.
            remaining = remaining.checked_sub(value.ty().bit_width().div_ceil(8) + 64)?;
            pending.push(value.ty());
        }
        while let Some(ty) = pending.pop() {
            // Pointer identity avoids assuming structurally equal types share
            // storage. Include value-owned types, not only the program arrows.
            if !types.insert(std::ptr::from_ref(ty)) {
                continue;
            }
            remaining = remaining.checked_sub(size_of::<Final>() + 192)?;
            match ty.bound() {
                CompleteBound::Unit => {}
                CompleteBound::Sum(left, right) | CompleteBound::Product(left, right) => {
                    pending.extend([left.as_ref(), right.as_ref()]);
                }
            }
        }
    }
    Some(allowance - remaining)
}
