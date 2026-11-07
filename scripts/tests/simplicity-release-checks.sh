#!/usr/bin/env bash
# Focused checks for the Simplicity patch set on the official release baseline.
set -euo pipefail
cd "$(dirname "$0")/../.."
export RUSTFLAGS="${RUSTFLAGS:---cfg tokio_unstable}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_DEBUG="${CARGO_PROFILE_RELEASE_DEBUG:-0}"
export FM_TEST_USE_REAL_DAEMONS=0
simplicity_toolchain="${FM_SIMPLICITY_TOOLCHAIN:-1.93.0}"
# Keep Cargo's feature graph identical for ordinary and network tests so the
# network step reuses the already-built test executables.
simplicity_test_packages=(
    -p fedimint-simplicity-common -p fedimint-simplicity-client
    -p fedimint-simplicity-server -p fedimint-core
    -p fedimint-client-module -p fedimint-client
    -p fedimint-mintv2-client -p fedimint-server -p fedimint-server-core
    -p fedimint-mintv2-common -p fedimint-mintv2-server
    -p fedimint-mint-common -p fedimint-mint-client -p fedimint-mint-server
    -p fedimint-meta-common -p fedimint-meta-client
    -p fedimint-wallet-common -p fedimint-ln-common
)
simplicity_doc_packages=(
    -p fedimint-simplicity-common -p fedimint-simplicity-client
    -p fedimint-simplicity-server -p fedimint-core
    -p fedimint-client-module -p fedimint-client
    -p fedimint-mintv2-common -p fedimint-mintv2-client -p fedimint-mintv2-server
    -p fedimint-server -p fedimint-server-core
)
simplicity_network_tests=(
    four_guardians_submit_settle_and_recover_assets_from_disk
    sessions::creation_sessions_and_expired_policy_replay_match_authenticated_history
    status::operator_status_observes_four_guardians_and_a_missing_peer
    wallet::direct_sender_receipts_restore_history_without_owning_recipient_contracts
    wallet::mnemonic_only_client_recovery_preserves_assets_history_and_spendability
    wallet::pruning::funding_sensitive_pruning_and_stale_plans_roll_back_real_ecash
    wallet::receipts::watched_shared_contract_submission_survives_mnemonic_only_recovery
)

case "${1:-tests}" in
    tests)
        # The separate network step runs the four-guardian process fixtures.
        rustup run "$simplicity_toolchain" cargo test --release --locked \
            "${simplicity_test_packages[@]}" --lib --tests -- \
            --skip tests::assets::network:: --test-threads=2
        printf '%s\n' 'Mintv2 integration: fake Bitcoin, real client/server operations and migration validation'
        rustup run "$simplicity_toolchain" cargo test --release --locked \
            -p fedimint-mintv2-tests --test fedimint_mintv2_tests -- \
            --skip db::snapshot_ --test-threads=2
        for regression in sends_ecash_out_of_band \
            transaction_with_invalid_signature_is_rejected \
            reissuing_the_same_notes_twice_reports_already_reissued; do
            bash scripts/tests/simplicity-test-selection.sh \
                --name "mint-${regression//_/-}" --require "$regression" -- \
                rustup run "$simplicity_toolchain" cargo test --release --locked \
                -p fedimint-mint-tests --test fedimint_mint_tests "$regression" -- \
                --exact --test-threads=1
        done
        # Compile every client example and execute their embedded CLI tests.
        rustup run "$simplicity_toolchain" cargo test --release --locked \
            -p fedimint-simplicity-client --examples
        ;;
    docs)
        rustup run "$simplicity_toolchain" cargo test --release --locked \
            "${simplicity_doc_packages[@]}" --doc -- --test-threads=2
        ;;
    network)
        required_network_tests=()
        for scenario in "${simplicity_network_tests[@]}"; do
            required_network_tests+=(--require "tests::assets::network::$scenario")
        done
        bash scripts/tests/simplicity-test-selection.sh \
            --name network "${required_network_tests[@]}" -- \
            rustup run "$simplicity_toolchain" cargo test --release --locked \
            "${simplicity_test_packages[@]}" --lib --tests tests::assets::network:: -- \
            --nocapture --test-threads=1
        ;;
    guardian)
        untracked_sources="$(git ls-files --others --exclude-standard)"
        if ! git diff --quiet HEAD || [[ -n "$untracked_sources" ]]; then
            echo 'Guardian release artifacts require a clean committed source tree' >&2
            exit 1
        fi
        guardian_revision="$(git rev-parse HEAD)"
        if [[ -n "${FEDIMINT_BUILD_FORCE_GIT_HASH:-}" && "$FEDIMINT_BUILD_FORCE_GIT_HASH" != "$guardian_revision" ]]; then
            echo 'FEDIMINT_BUILD_FORCE_GIT_HASH must identify the current source revision' >&2
            exit 1
        fi
        export FEDIMINT_BUILD_FORCE_GIT_HASH="$guardian_revision"
        guardian_directory="${CARGO_TARGET_DIR:-target}${CARGO_BUILD_TARGET:+/$CARGO_BUILD_TARGET}/release"
        rustup run "$simplicity_toolchain" cargo build --release --locked -p fedimintd
        bash scripts/tests/simplicity-artifacts.sh guardian default "$guardian_directory/fedimintd"
        rustup run "$simplicity_toolchain" cargo build --release --locked \
            -p fedimintd --features experimental-simplicity
        bash scripts/tests/simplicity-artifacts.sh guardian experimental-simplicity "$guardian_directory/fedimintd"
        ;;
    clippy)
        rustup run "$simplicity_toolchain" cargo clippy --release --locked \
            -p fedimint-simplicity-common -p fedimint-simplicity-client \
            -p fedimint-simplicity-server -p fedimint-client-module \
            -p fedimint-client -p fedimint-mintv2-client \
            --all-targets --no-deps -- -D warnings
        ;;
    *)
        echo "Usage: $0 [tests|docs|network|guardian|clippy]" >&2
        exit 2
        ;;
esac
