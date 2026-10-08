//! Fixture-only signature bypass while selecting branches for invalid proofs.
use simplicity::jet::{Core, JetEnvironment};
use simplicity_sys::c_jets::frame_ffi::CFrameItem;

use super::*;

struct FixtureEnvironment<'a>(&'a Environment);
impl JetEnvironment for FixtureEnvironment<'_> {
    type Jet = FedimintJet;
    type CJetEnvironment = Environment;
    fn c_jet_env(&self) -> &Environment {
        self.0
    }
    fn c_jet_ptr(jet: &FedimintJet) -> fn(&mut CFrameItem, CFrameItem, &Environment) -> bool {
        match jet {
            FedimintJet::Core(Core::Bip0340Verify) => |_, _, _| true,
            _ => Environment::c_jet_ptr(jet),
        }
    }
}

pub(super) fn market(fixture: &mut Fixture) {
    for (input, environment) in fixture.inputs.iter_mut().zip(&fixture.environments) {
        let original = runtime::decode_program(input).expect("market program");
        let program = fedimint_simplicity_common::compiler::prune(
            &original,
            &FixtureEnvironment(environment),
        )
        .expect("fixture pruning");
        (input.program, input.witness) = program.to_vec_with_witness();
    }
    // The benchmark executes ordinary signature verification, including the
    // intentionally wrong oracle proof. Refresh outer signatures after pruning.
    fixture.finish();
}
