use clap::Parser as _;
use fedimint_core::secp256k1::{PublicKey, SECP256K1, SecretKey};

use super::Opts;

fn sample_pubkey() -> PublicKey {
    let sk = SecretKey::from_slice(&[7u8; 32]).expect("valid secret key");
    PublicKey::from_secret_key(SECP256K1, &sk)
}

#[test]
fn parses_bolt12_subcommands() {
    let pk = sample_pubkey();

    let status = Opts::try_parse_from(["bolt12", "status"]).expect("status parses");
    assert!(matches!(status, Opts::Status));

    let create = Opts::try_parse_from([
        "bolt12",
        "create-offer",
        "--description",
        "Coffee",
        "--stock",
        "4",
        "--expiry-secs",
        "3600",
        "--allow-pool",
        "--gateway",
        "http://127.0.0.1:8175",
        "--max-gateway-fee",
        "1000msat,5000",
    ])
    .expect("create-offer parses");
    match create {
        Opts::CreateOffer {
            description,
            stock,
            expiry_secs,
            allow_pool,
            gateways,
            max_gateway_fee,
        } => {
            assert_eq!(description, "Coffee");
            assert_eq!(stock, 4);
            assert_eq!(expiry_secs, 3600);
            assert!(allow_pool);
            assert_eq!(gateways.len(), 1);
            assert!(max_gateway_fee.is_some());
        }
        _ => panic!("unexpected variant"),
    }

    let approve = Opts::try_parse_from([
        "bolt12",
        "approve-gateway",
        &pk.to_string(),
        "--url",
        "http://127.0.0.1:8175",
    ])
    .expect("approve-gateway parses");
    assert!(matches!(
        approve,
        Opts::ApproveGateway {
            gateway_key,
            url: Some(_),
        } if gateway_key == pk
    ));

    let revoke = Opts::try_parse_from(["bolt12", "revoke-gateway", &pk.to_string()])
        .expect("revoke-gateway parses");
    assert!(matches!(
        revoke,
        Opts::RevokeGateway { gateway_key } if gateway_key == pk
    ));

    let rescan = Opts::try_parse_from(["bolt12", "rescan-offers", "--max-index", "250"])
        .expect("rescan-offers parses");
    assert!(matches!(rescan, Opts::RescanOffers { max_index: 250 }));
}
