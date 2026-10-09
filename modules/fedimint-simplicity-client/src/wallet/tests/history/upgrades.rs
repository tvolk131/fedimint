use fedimint_core::core::DynModuleConsensusItem;
use fedimint_core::module::ModuleConsensusVersion;

use super::*;
use crate::common::SimplicityConsensusItem;

#[tokio::test]
async fn mnemonic_recovery_authenticates_history_containing_upgrade_items() {
    let (store, mut api, txs) = fixture(Fault::None).await;
    let api_mut = Arc::get_mut(&mut api).unwrap();
    for (peer, version) in [(0, 3), (1, 3), (2, 3)] {
        api_mut.complete.items.insert(
            0,
            AcceptedItem {
                peer: peer.into(),
                item: ConsensusItem::Module(DynModuleConsensusItem::from_typed(
                    MODULE,
                    SimplicityConsensusItem::ModuleConsensusVersion(ModuleConsensusVersion::new(
                        0, version,
                    )),
                )),
            },
        );
    }
    // The envelope preserves unknown future variants when authenticating the
    // signed session, even when this wallet only recognizes original contracts.
    api_mut.complete.items.push(AcceptedItem {
        peer: 0.into(),
        item: ConsensusItem::Module(DynModuleConsensusItem::from_typed(
            MODULE,
            SimplicityConsensusItem::Default {
                variant: 99,
                bytes: vec![2, 7, 3],
            },
        )),
    });
    let source = api.history(
        VERSION_THAT_INTRODUCED_GET_SESSION_STATUS_V2,
        Some(public_keys()),
    );
    store.sync(&source, |_, _| {}).await.unwrap();
    assert_recovered(&store, &txs).await;
    // A fresh database, with only the original mnemonic and templates, finds
    // the same spent contract and complete confirmed interaction history.
    let recovered = wallet(database()).await;
    recovered.sync(&source, |_, _| {}).await.unwrap();
    assert_recovered(&recovered, &txs).await;
}
