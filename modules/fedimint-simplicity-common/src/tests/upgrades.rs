use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::ModuleConsensusVersion;
use fedimint_core::module::registry::ModuleDecoderRegistry;

use crate::consensus::check_execution_version;
use crate::{MODULE_CONSENSUS_VERSION, SimplicityConsensusItem};

#[test]
fn consensus_envelope_preserves_future_votes_and_unknown_variants() {
    for item in [
        SimplicityConsensusItem::BlockCount(u64::MAX),
        SimplicityConsensusItem::ModuleConsensusVersion(ModuleConsensusVersion::new(
            u32::MAX,
            u32::MAX,
        )),
        SimplicityConsensusItem::Default {
            variant: 99,
            bytes: vec![0, 255, 13],
        },
    ] {
        let bytes = item.consensus_encode_to_vec();
        let decoded = SimplicityConsensusItem::consensus_decode_whole(
            &bytes,
            &ModuleDecoderRegistry::default(),
        )
        .unwrap();
        assert_eq!(item, decoded);
        assert_eq!(bytes, decoded.consensus_encode_to_vec());
    }
    // Fixed vectors protect the envelope future binaries must keep decoding.
    assert_eq!(
        SimplicityConsensusItem::BlockCount(100).consensus_encode_to_vec(),
        vec![0, 1, 100]
    );
    assert_eq!(
        SimplicityConsensusItem::ModuleConsensusVersion(MODULE_CONSENSUS_VERSION)
            .consensus_encode_to_vec(),
        vec![1, 2, 0, 2]
    );
}

#[test]
fn execution_versions_require_activation_and_unknown_versions_are_never_enabled() {
    for execution in [0, 1] {
        assert!(check_execution_version(execution, ModuleConsensusVersion::new(0, 1)).is_err());
        check_execution_version(execution, MODULE_CONSENSUS_VERSION).unwrap();
        check_execution_version(execution, ModuleConsensusVersion::new(0, 3)).unwrap();
    }
    assert!(check_execution_version(2, ModuleConsensusVersion::new(u32::MAX, u32::MAX)).is_err());
}
