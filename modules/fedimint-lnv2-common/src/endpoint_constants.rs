// Federation endpoints
pub const ADD_GATEWAY_ENDPOINT: &str = "add_gateway";
pub const AWAIT_INCOMING_CONTRACT_ENDPOINT: &str = "await_incoming_contract";
pub const AWAIT_PREIMAGE_ENDPOINT: &str = "await_preimage";
pub const AWAIT_INCOMING_CONTRACTS_ENDPOINT: &str = "await_incoming_contracts";
pub const DECRYPTION_KEY_SHARE_ENDPOINT: &str = "decryption_key_share";
pub const CONSENSUS_BLOCK_COUNT_ENDPOINT: &str = "consensus_block_count";
pub const GATEWAYS_ENDPOINT: &str = "gateways";
pub const OUTGOING_CONTRACT_EXPIRATION_ENDPOINT: &str = "outgoing_contract_expiration";
pub const REMOVE_GATEWAY_ENDPOINT: &str = "remove_gateway";

// Federated BOLT12 federation endpoints
pub const BOLT12_REGISTRATION_BY_HANDLE_ENDPOINT: &str = "bolt12_registration_by_handle";
pub const BOLT12_REGISTRATION_BY_RECIPIENT_ENDPOINT: &str = "bolt12_registration_by_recipient";
pub const BOLT12_NEXT_STOCK_ENDPOINT: &str = "bolt12_next_stock";
pub const BOLT12_RESERVATION_ENDPOINT: &str = "bolt12_reservation";
pub const BOLT12_AWAIT_RECEIVES_ENDPOINT: &str = "bolt12_await_receives";
pub const BOLT12_CONTRACT_ENDPOINT: &str = "bolt12_contract";
pub const BOLT12_GATEWAY_APPROVED_ENDPOINT: &str = "bolt12_gateway_approved";
pub const BOLT12_SET_GATEWAY_VOTE_ENDPOINT: &str = "bolt12_set_gateway_vote";
pub const BOLT12_NONCE_ENDPOINT: &str = "bolt12_nonce";
pub const BOLT12_SIGN_ENDPOINT: &str = "bolt12_sign";
pub const BOLT12_NEXT_POOL_ENDPOINT: &str = "bolt12_next_pool";
pub const BOLT12_RECIPIENT_USED_ENDPOINT: &str = "bolt12_recipient_used";
pub const BOLT12_DECRYPTION_SHARES_ENDPOINT: &str = "bolt12_decryption_shares";
pub const BOLT12_MPC_ENDPOINT: &str = "bolt12_mpc";
pub const BOLT12_MPC_FETCH_ENDPOINT: &str = "bolt12_mpc_fetch";
pub const BOLT12_MPC_RELAY_ENDPOINT: &str = "bolt12_mpc_relay";
pub const BOLT12_MPC_EVIDENCE_ENDPOINT: &str = "bolt12_mpc_evidence";

// Gateway endpoints
pub const CREATE_BOLT11_INVOICE_ENDPOINT: &str = "/create_bolt11_invoice";
pub const VERIFY_BOLT11_PREIMAGE_ENDPOINT: &str = "/verify_bolt11_preimage";
pub const ROUTING_INFO_ENDPOINT: &str = "/routing_info";
pub const BOLT12_INGRESS_ENDPOINT: &str = "/bolt12_ingress";
pub const SEND_PAYMENT_ENDPOINT: &str = "/send_payment";
