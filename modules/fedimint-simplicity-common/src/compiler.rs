//! Client-only SimplicityHL integration. Guardians decode bytecode directly.

mod pruning;
pub use pruning::prune;
use simplicity::jet::{Core, Jet};
use simplicityhl::ast::JetHinter;
use simplicityhl::jet::{JetHL, SourceJetClassification, TargetJetClassification};
pub use simplicityhl::num::U256;
pub use simplicityhl::value::ValueConstructible;
pub use simplicityhl::{
    Arguments, CompiledProgram, TemplateProgramWitness, Value, WitnessNameToValueMap, WitnessValues,
};

use crate::jet::{ContextJet, FedimintJet};

pub fn arguments(values: impl IntoIterator<Item = (&'static str, Value)>) -> Arguments {
    Arguments::from_map(
        values
            .into_iter()
            .map(|(name, value)| (TemplateProgramWitness::parameter_from_str(name), value))
            .collect(),
    )
}

pub fn witnesses(values: impl IntoIterator<Item = (&'static str, Value)>) -> WitnessValues {
    WitnessValues::from_map(
        values
            .into_iter()
            .map(|(name, value)| (TemplateProgramWitness::witness_from_str(name), value))
            .collect(),
    )
}

#[derive(Debug, Clone)]
pub struct FedimintJetHinter;

impl JetHL for FedimintJet {
    fn source_jet_classification(&self) -> SourceJetClassification {
        match self {
            Self::Core(core) => core.source_jet_classification(),
            Self::Context(
                ContextJet::InputAssetQuantity
                | ContextJet::OutputAssetQuantity
                | ContextJet::InputAuthority
                | ContextJet::OutputAuthority,
            ) => {
                use simplicityhl::types::UIntType::{U32, U256};
                SourceJetClassification::Custom(vec![simplicityhl::jet::tuple([U32, U256])])
            }
            Self::Context(
                ContextJet::InputAssetId
                | ContextJet::OutputAssetId
                | ContextJet::InputAuthorityId
                | ContextJet::OutputAuthorityId,
            ) => {
                use simplicityhl::types::UIntType::U32;
                SourceJetClassification::Custom(vec![simplicityhl::jet::tuple([U32, U32])])
            }
            Self::Context(_) => SourceJetClassification::Unary,
        }
    }
    fn target_jet_classification(&self) -> TargetJetClassification {
        match self {
            Self::Core(core) => core.target_jet_classification(),
            Self::Context(ContextJet::SigHashAll) => {
                TargetJetClassification::Custom(simplicityhl::types::BuiltinAlias::Message.into())
            }
            Self::Context(ContextJet::InputAuthority | ContextJet::OutputAuthority) => {
                TargetJetClassification::Custom(simplicityhl::jet::bool())
            }
            Self::Context(_) => TargetJetClassification::Unary,
        }
    }
    fn is_disabled(&self) -> bool {
        match self {
            Self::Core(core) => core.is_disabled(),
            Self::Context(_) => false,
        }
    }
    fn clone_box(&self) -> Box<dyn JetHL> {
        Box::new(*self)
    }
    fn as_jet(&self) -> &dyn Jet {
        self
    }
}

impl JetHinter for FedimintJetHinter {
    fn parse_jet(&self, name: &str) -> Option<Box<dyn JetHL>> {
        FedimintJet::parse(name)
            .ok()
            .map(|jet| Box::new(jet) as Box<dyn JetHL>)
    }
    fn construct_verify(&self) -> Box<dyn JetHL> {
        Box::new(FedimintJet::Core(Core::Verify))
    }
    fn conjure(&self, jet: &dyn Jet) -> Option<Box<dyn JetHL>> {
        jet.as_any()
            .downcast_ref::<FedimintJet>()
            .map(|jet| Box::new(*jet) as Box<dyn JetHL>)
    }
    fn clone_box(&self) -> Box<dyn JetHinter> {
        Box::new(self.clone())
    }
}

pub fn compile(source: &str, arguments: Arguments) -> Result<CompiledProgram, String> {
    CompiledProgram::new(source, arguments, false, Box::new(FedimintJetHinter))
}
