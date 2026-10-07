use fedimint_core::TransactionId;
use fedimint_core::module::{ApiEndpointContext, ApiRequestErased};
use fedimint_simplicity_common::assets::{
    AssetAmount, AssetBundle, AssetExtension, AssetId, AssetRecord, MAX_ASSETS,
};
use fedimint_simplicity_common::{ContractOutput, resources};

use super::*;
use crate::db::AssetKey;

// Exercise the real typed endpoint wrappers, including parameter decoding and
// JSON serialization. These budgets concern valid stored records, not the
// transport's JSON parser or a bound on simultaneous requests.
#[tokio::test]
async fn point_queries_bound_records_and_handle_spent_contracts() {
    let peers = vec![0.into(), 1.into(), 2.into(), 3.into()];
    let module = Simplicity::new_for_testing(peers.clone()).unwrap();
    let db = Database::new(MemDatabase::new(), ModuleDecoderRegistry::default());
    let point = OutPoint {
        txid: TransactionId::from_raw_hash(sha256::Hash::hash(b"maximum-record")),
        out_idx: u64::MAX,
    };
    let ids: Vec<_> = (0..MAX_ASSETS)
        .map(|index| {
            let mut bytes = [255; 32];
            bytes[31] = 255 - (MAX_ASSETS - 1 - index) as u8;
            AssetId(bytes)
        })
        .collect();
    let output = ContractOutput {
        version: 1,
        amount: Amount::from_msats(2_100_000_000_000_000_000),
        cmr: [255; 32],
        state: [255; 32],
        recovery: vec![255; MAX_RECOVERY_BYTES],
        extension: Some(AssetExtension::Bundle(AssetBundle {
            balances: ids
                .iter()
                .map(|asset| AssetAmount {
                    asset: *asset,
                    quantity: u64::MAX,
                })
                .collect(),
            authorities: ids.clone(),
        })),
    };
    resources::check_output(&output).unwrap();
    let stored = StoredContract {
        output,
        creation_session: u64::MAX,
        creation_block_count: u64::MAX,
    };
    let origin = AssetRecord {
        creation_key: key().public_key(),
        ordinal: u32::MAX,
        authority_outpoint: point,
        authority_cmr: [255; 32],
        authority_state: [255; 32],
    };
    let mut dbtx = db.begin_transaction().await;
    dbtx.insert_new_entry(&ContractKey(point), &stored).await;
    dbtx.insert_new_entry(&AssetKey(ids[0]), &origin).await;
    for peer in peers {
        module
            .process_consensus_item(&mut dbtx.to_ref_nc(), BlockCountVote(u64::MAX), peer)
            .await
            .unwrap();
    }
    dbtx.commit_tx().await;
    let endpoints = module.api_endpoints();
    for (path, params, expected, max_bytes) in [
        (
            "contract",
            ApiRequestErased::new(point),
            serde_json::to_value(&stored).unwrap(),
            16_384,
        ),
        (
            "asset",
            ApiRequestErased::new(ids[0]),
            serde_json::to_value(&origin).unwrap(),
            1024,
        ),
        (
            "block_count",
            ApiRequestErased::new(()),
            serde_json::json!(u64::MAX),
            20,
        ),
    ] {
        let endpoint = endpoints
            .iter()
            .find(|endpoint| endpoint.path == path)
            .unwrap();
        let response =
            (endpoint.handler)(&module, ApiEndpointContext::new(db.clone(), false), params)
                .await
                .unwrap();
        assert_eq!(response, expected);
        assert!(
            serde_json::to_vec(&response).unwrap().len() <= max_bytes,
            "{path}"
        );
        let malformed = (endpoint.handler)(
            &module,
            ApiEndpointContext::new(db.clone(), false),
            ApiRequestErased::new(serde_json::json!({})),
        )
        .await
        .unwrap_err();
        assert_eq!(malformed.code, 400);
    }
    // Missing and spent contracts return null, with no historical descriptor
    // fallback or additional listing response. Asset origins remain available.
    let mut dbtx = db.begin_transaction().await;
    dbtx.remove_entry(&ContractKey(point)).await;
    dbtx.commit_tx().await;
    for (path, params, expected) in [
        (
            "contract",
            ApiRequestErased::new(point),
            serde_json::Value::Null,
        ),
        (
            "asset",
            ApiRequestErased::new(AssetId([0; 32])),
            serde_json::Value::Null,
        ),
        (
            "asset",
            ApiRequestErased::new(ids[0]),
            serde_json::to_value(&origin).unwrap(),
        ),
    ] {
        let endpoint = endpoints
            .iter()
            .find(|endpoint| endpoint.path == path)
            .unwrap();
        assert_eq!(
            (endpoint.handler)(&module, ApiEndpointContext::new(db.clone(), false), params)
                .await
                .unwrap(),
            expected
        );
    }
}
