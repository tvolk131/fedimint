//! Client-side pruning with fresh type inference for the retained DAG.
use std::sync::Arc;

use anyhow::Context as _;
use simplicity::dag::{InternalSharing, PostOrderIterItem};
use simplicity::jet::JetEnvironment;
use simplicity::node::{Construct, Converter, Inner, Redeem, RedeemData};
use simplicity::{ConstructNode, RedeemNode, Value};

/// Remove unused branches, then infer types without constraints contributed by
/// hidden children. Simplicity 0.9's pruning can retain those constraints (for
/// example an unused 512-bit signature), producing witness bytes its own
/// decoder rejects. Re-inference also permits canonical encoding to merge nodes
/// whose types/witnesses become identical. Guardians keep their strict decoder.
/// This performs one VM execution, always starting from the original template.
pub fn prune<JE: JetEnvironment>(
    program: &RedeemNode,
    env: &JE,
) -> anyhow::Result<Arc<RedeemNode>> {
    let pruned = program.prune(env)?;
    simplicity::types::Context::with_context(|ctx| {
        let retained = pruned.to_construct_node(&ctx);
        retained.set_arrow_to_program()?;
        retained.convert::<InternalSharing, _, _>(&mut Finalizer)
    })
}

struct Finalizer;

impl<'brand> Converter<Construct<'brand>, Redeem> for Finalizer {
    type Error = anyhow::Error;

    fn convert_witness(
        &mut self,
        data: &PostOrderIterItem<&ConstructNode>,
        witness: &Option<Value>,
    ) -> Result<Value, Self::Error> {
        let target = data.node.arrow().target.finalize()?;
        witness
            .as_ref()
            .context("missing pruning witness")?
            .prune(&target)
            .context("pruned witness does not match inferred type")
    }

    fn convert_disconnect(
        &mut self,
        _: &PostOrderIterItem<&ConstructNode>,
        right: Option<&Arc<RedeemNode>>,
        _: &Option<Arc<ConstructNode>>,
    ) -> Result<Arc<RedeemNode>, Self::Error> {
        right.cloned().context("missing pruning disconnect child")
    }

    fn convert_data(
        &mut self,
        data: &PostOrderIterItem<&ConstructNode>,
        inner: Inner<&Arc<RedeemNode>, &Arc<RedeemNode>, &Value>,
    ) -> Result<Arc<RedeemData>, Self::Error> {
        let inner = inner
            .map(|node| node.cached_data())
            .map_disconnect(|node| node.cached_data())
            .map_witness(Value::shallow_clone);
        Ok(Arc::new(RedeemData::new(
            data.node.arrow().finalize()?,
            inner,
        )))
    }
}
