//! Read-only views of BOLT12 consensus state, plus the admin endpoint through
//! which a guardian sets its gateway vote.

use fedimint_bolt12_common::endpoint_constants::{
    AWAIT_RECEIVES_ENDPOINT, CONTRACT_ENDPOINT, DECRYPTION_SHARES_ENDPOINT,
    GATEWAY_APPROVED_ENDPOINT, MPC_ENDPOINT, MPC_EVIDENCE_ENDPOINT, MPC_FETCH_ENDPOINT,
    MPC_RELAY_ENDPOINT, NEXT_POOL_ENDPOINT, NEXT_STOCK_ENDPOINT, NONCE_ENDPOINT,
    POOL_ITEMS_ENDPOINT, RECIPIENT_USED_ENDPOINT, REGISTRATION_BY_HANDLE_ENDPOINT,
    REGISTRATION_BY_RECIPIENT_ENDPOINT, RESERVATION_ENDPOINT, SET_GATEWAY_VOTE_ENDPOINT,
    SIGN_ENDPOINT, STOCK_ITEMS_ENDPOINT,
};
use fedimint_bolt12_common::protocol::{
    NonceRequest, NonceResponse, ReceiveContract, Registration, RegistrationId, Reservation,
    ReservationId, SignRequest, StockItem, StreamedReceive,
};
use fedimint_core::OutPoint;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::encoding::Encodable as _;
use fedimint_core::module::{
    ApiEndpoint, ApiError, ApiVersion, admin_api_endpoint, public_api_endpoint,
};
use fedimint_core::secp256k1::PublicKey;
use futures::StreamExt;
use tpe::DecryptionKeyShare;

use crate::Bolt12;
use crate::db::{
    Bolt12ContractKey, Bolt12DecryptionSharesKey, Bolt12GatewayDesiredVoteKey, Bolt12HandleKey,
    Bolt12PoolItemKey, Bolt12PoolItemPrefix, Bolt12RecipientKey, Bolt12RegistrationKey,
    Bolt12ReservationKey, Bolt12StockKey, Bolt12StockRegistrationPrefix, Bolt12StreamIndexKey,
    Bolt12StreamKey,
};
use crate::{signer, transport, worker};

/// Largest batch of receives returned by one stream request.
const MAX_RECEIVES_BATCH: usize = 128;

async fn registration(
    db: &Database,
    id: Option<RegistrationId>,
) -> Option<(RegistrationId, Registration)> {
    let id = id?;

    db.begin_transaction_nc()
        .await
        .get_value(&Bolt12RegistrationKey(id))
        .await
        .map(|registration| (id, registration))
}

async fn await_receives(db: Database, start: u64, n: usize) -> (Vec<StreamedReceive>, u64) {
    let filter = |next_index: Option<u64>| next_index.filter(|i| *i > start);

    let (mut next_index, mut dbtx) = db.wait_key_check(&Bolt12StreamIndexKey, filter).await;

    let mut receives = Vec::with_capacity(n.min(MAX_RECEIVES_BATCH));

    let range = Bolt12StreamKey(start)..Bolt12StreamKey(u64::MAX);

    for (key, receive) in dbtx
        .find_by_range(range)
        .await
        .take(n)
        .collect::<Vec<(Bolt12StreamKey, StreamedReceive)>>()
        .await
    {
        receives.push(receive);
        next_index = key.0 + 1;
    }

    (receives, next_index)
}

impl Bolt12 {
    pub(crate) fn bolt12_api_endpoints() -> Vec<ApiEndpoint<Self>> {
        let mut endpoints = Self::bolt12_registration_endpoints();
        endpoints.extend(Self::bolt12_receive_and_gateway_endpoints());
        endpoints
    }

    fn bolt12_registration_endpoints() -> Vec<ApiEndpoint<Self>> {
        vec![
            public_api_endpoint! {
                REGISTRATION_BY_HANDLE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, handle: [u8; 32]| -> Option<(RegistrationId, Registration)> {
                    let db = context.db();
                    let id = db.begin_transaction_nc().await.get_value(&Bolt12HandleKey(handle)).await;

                    Ok(registration(&db, id).await)
                }
            },
            public_api_endpoint! {
                REGISTRATION_BY_RECIPIENT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, claim_pk: PublicKey| -> Option<(RegistrationId, Registration)> {
                    let db = context.db();
                    let id = db.begin_transaction_nc().await.get_value(&Bolt12RecipientKey(claim_pk)).await;

                    Ok(registration(&db, id).await)
                }
            },
            public_api_endpoint! {
                RECIPIENT_USED_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, claim_pk: PublicKey| -> bool {
                    Ok(context
                        .db()
                        .begin_transaction_nc()
                        .await
                        .get_value(&Bolt12RecipientKey(claim_pk))
                        .await
                        .is_some())
                }
            },
            public_api_endpoint! {
                NEXT_STOCK_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, id: RegistrationId| -> Option<(u64, StockItem)> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    // Rows are ordered by index and exist only while unused.
                    let next = dbtx
                        .find_by_prefix(&Bolt12StockRegistrationPrefix(id))
                        .await
                        .next()
                        .await;

                    Ok(next.map(|(key, item)| (key.1, item)))
                }
            },
            public_api_endpoint! {
                STOCK_ITEMS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, params: (RegistrationId, u64)| -> Vec<(u64, StockItem)> {
                    let (id, min_index) = params;
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    let items = dbtx
                        .find_by_range(Bolt12StockKey(id, min_index)..Bolt12StockKey(id, u64::MAX))
                        .await
                        .take(32)
                        .map(|(key, item)| (key.1, item))
                        .collect()
                        .await;

                    Ok(items)
                }
            },
        ]
    }

    fn bolt12_receive_and_gateway_endpoints() -> Vec<ApiEndpoint<Self>> {
        vec![
            public_api_endpoint! {
                RESERVATION_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, id: ReservationId| -> Option<Reservation> {
                    let db = context.db();

                    Ok(db.begin_transaction_nc().await.get_value(&Bolt12ReservationKey(id)).await)
                }
            },
            public_api_endpoint! {
                CONTRACT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, outpoint: OutPoint| -> Option<ReceiveContract> {
                    let db = context.db();

                    Ok(db.begin_transaction_nc().await.get_value(&Bolt12ContractKey(outpoint)).await)
                }
            },
            public_api_endpoint! {
                AWAIT_RECEIVES_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, params: (u64, usize)| -> (Vec<StreamedReceive>, u64) {
                    if params.1 == 0 || params.1 > MAX_RECEIVES_BATCH {
                        return Err(ApiError::bad_request(format!(
                            "Batch size must be in 1..={MAX_RECEIVES_BATCH}"
                        )));
                    }

                    Ok(await_receives(context.db(), params.0, params.1).await)
                }
            },
            public_api_endpoint! {
                GATEWAY_APPROVED_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Bolt12, context, gateway: PublicKey| -> bool {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    Ok(crate::consensus::gateway_is_approved(&mut dbtx, &module.cfg, gateway).await)
                }
            },
            admin_api_endpoint! {
                SET_GATEWAY_VOTE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, params: (PublicKey, bool)| -> () {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction().await;

                    dbtx.insert_entry(&Bolt12GatewayDesiredVoteKey(params.0), &params.1).await;
                    dbtx.commit_tx().await;

                    Ok(())
                }
            },
        ]
    }

    /// Views of the pool of generated preimages and of funded receives'
    /// decryption shares.
    pub(crate) fn bolt12_pool_endpoints() -> Vec<ApiEndpoint<Self>> {
        vec![
            public_api_endpoint! {
                NEXT_POOL_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, _params: ()| -> Option<(u64, [u8; 32])> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    // Rows are ordered by index and exist only while unused.
                    let next = dbtx.find_by_prefix(&Bolt12PoolItemPrefix).await.next().await;

                    Ok(next.map(|(key, item)| (key.0, item.payment_hash)))
                }
            },
            public_api_endpoint! {
                POOL_ITEMS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, min_index: u64| -> Vec<(u64, [u8; 32])> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;

                    let items = dbtx
                        .find_by_range(Bolt12PoolItemKey(min_index)..Bolt12PoolItemKey(u64::MAX))
                        .await
                        .take(32)
                        .map(|(key, item)| (key.0, item.payment_hash))
                        .collect()
                        .await;

                    Ok(items)
                }
            },
            public_api_endpoint! {
                DECRYPTION_SHARES_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Bolt12, context, outpoint: OutPoint| -> Vec<DecryptionKeyShare> {
                    // Long-polls like the LNv2 share endpoint: the shares are
                    // written atomically with the funding.
                    Ok(context.db().wait_key_exists(&Bolt12DecryptionSharesKey(outpoint)).await)
                }
            },
        ]
    }

    /// MPC generation transport, relay, and evidence endpoints.
    fn bolt12_mpc_endpoints() -> Vec<ApiEndpoint<Self>> {
        vec![
            public_api_endpoint! {
                MPC_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Bolt12, _context, packet: String| -> () {
                    let worker = module
                        .worker
                        .as_ref()
                        .ok_or_else(|| ApiError::bad_request("Preimage generation is disabled".to_string()))?;

                    transport::decode_packet(&packet)
                        .and_then(|packet| worker.receive(&packet))
                        .map_err(|e| ApiError::bad_request(e.to_string()))
                }
            },
            public_api_endpoint! {
                MPC_FETCH_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Bolt12, _context, request: String| -> transport::PacketPage {
                    let worker = module
                        .worker
                        .as_ref()
                        .ok_or_else(|| ApiError::bad_request("Preimage generation is disabled".to_string()))?;

                    let request = transport::decode_fetch_request(&request)
                        .map_err(|e| ApiError::bad_request(e.to_string()))?;

                    worker
                        .serve_packets(&request)
                        .map(|(total_chunks, packets)| transport::PacketPage {
                            total_chunks,
                            packets: packets
                                .into_iter()
                                .map(|packet| packet.consensus_encode_to_hex())
                                .collect(),
                        })
                        .map_err(|e| ApiError::bad_request(e.to_string()))
                }
            },
            public_api_endpoint! {
                MPC_RELAY_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Bolt12, _context, request: String| -> transport::PacketPage {
                    let worker = module
                        .worker
                        .as_ref()
                        .ok_or_else(|| ApiError::bad_request("Preimage generation is disabled".to_string()))?;

                    let request = transport::decode_relay_request(&request)
                        .map_err(|e| ApiError::bad_request(e.to_string()))?;

                    worker
                        .relay(&request)
                        .await
                        .map(|(total_chunks, packets)| transport::PacketPage {
                            total_chunks,
                            packets: packets
                                .into_iter()
                                .map(|packet| packet.consensus_encode_to_hex())
                                .collect(),
                        })
                        .map_err(|e| ApiError::bad_request(e.to_string()))
                }
            },
            public_api_endpoint! {
                MPC_EVIDENCE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Bolt12, context, request: String| -> String {
                    let bolt12 = &module.cfg.consensus.bolt12;

                    let request = worker::decode_evidence_request(&request)
                        .map_err(|e| ApiError::bad_request(e.to_string()))?;

                    if request.target != module.our_peer_id {
                        return Err(ApiError::bad_request(
                            "Evidence request is for another guardian".to_string(),
                        ));
                    }

                    let requester_pk = bolt12
                        .transport_keys
                        .get(&request.requester)
                        .ok_or_else(|| ApiError::bad_request("Unknown guardian requester".to_string()))?;

                    if !request.verify(requester_pk) {
                        return Err(ApiError::bad_request("Invalid evidence request signature".to_string()));
                    }

                    worker::serve_evidence(&context.db(), request.run, request.from_round, request.from_peer)
                        .await
                        .map(|page| page.consensus_encode_to_hex())
                        .map_err(|e| ApiError::bad_request(e.to_string()))
                }
            },
        ]
    }

    /// Invoice signing and generation runs. Not consensus: each guardian
    /// answers for itself.
    pub(crate) fn bolt12_signing_endpoints() -> Vec<ApiEndpoint<Self>> {
        let mut endpoints = Self::bolt12_mpc_endpoints();
        endpoints.extend([
            public_api_endpoint! {
                NONCE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Bolt12, context, request: NonceRequest| -> NonceResponse {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    let now = module.consensus_unix_time(&mut dbtx).await;

                    let approval = signer::approve(&mut dbtx, &module.cfg, &request, now)
                        .await
                        .map_err(|e| ApiError::bad_request(e.to_string()))?;

                    module
                        .signer
                        .lock()
                        .await
                        .prepare(&module.cfg, &db, (request.reservation, request.attempt), approval, now)
                        .await
                        .map_err(|e| ApiError::bad_request(e.to_string()))
                }
            },
            public_api_endpoint! {
                SIGN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Bolt12, context, request: SignRequest| -> Vec<u8> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    let now = module.consensus_unix_time(&mut dbtx).await;

                    // Only the gateway that holds a live reservation may spend
                    // the nonce we issued for it.
                    let authorized = dbtx
                        .get_value(&Bolt12ReservationKey(request.reservation))
                        .await
                        .is_some_and(|reservation| {
                            reservation.expires_at() > now && request.verify(&reservation.gateway)
                        });

                    if !authorized {
                        return Err(ApiError::bad_request(
                            "Reservation is unknown, expired, funded or not yours".to_string(),
                        ));
                    }

                    module
                        .signer
                        .lock()
                        .await
                        .sign(&module.cfg, &db, &request)
                        .await
                        .map_err(|e| ApiError::bad_request(e.to_string()))
                }
            },
        ]);
        endpoints
    }
}
