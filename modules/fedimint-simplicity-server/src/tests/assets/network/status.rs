//! Read-only status against the actual guardian endpoints, including an outage.
use fedimint_simplicity_client::status;
use fedimint_simplicity_common::MODULE_CONSENSUS_VERSION;

use super::*;

#[tokio::test]
async fn operator_status_observes_four_guardians_and_a_missing_peer() {
    fedimint_core::runtime::timeout(Duration::from_secs(90), async {
        let mut fed = Federation::new().await;
        let report = status::query(&fed.api, fed.simplicity, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(report.quorum_active_version, Some(MODULE_CONSENSUS_VERSION));
        for guardian in report.guardians.values() {
            assert_eq!(
                guardian.supported_version.value(),
                Some(&MODULE_CONSENSUS_VERSION)
            );
            assert_eq!(
                guardian.active_version.value(),
                Some(&MODULE_CONSENSUS_VERSION)
            );
            assert_eq!(guardian.block_count.value(), Some(&5));
            assert!(guardian.core.value().unwrap().federation.is_some());
        }
        fed.stop(PeerId::from(3));
        let report = status::query(&fed.api, fed.simplicity, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(report.quorum_active_version, Some(MODULE_CONSENSUS_VERSION));
        assert!(
            report.guardians[&PeerId::from(3)]
                .active_version
                .value()
                .is_none()
        );
        assert_eq!(report.guardians.len(), 4);
        fed.completed = true;
    })
    .await
    .unwrap();
}
