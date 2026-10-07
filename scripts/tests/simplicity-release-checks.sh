#!/usr/bin/env bash
# Focused checks for the Simplicity patch set on the official release baseline.
set -euo pipefail
cd "$(dirname "$0")/../.."
export RUSTFLAGS="${RUSTFLAGS:---cfg tokio_unstable}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_DEBUG="${CARGO_PROFILE_RELEASE_DEBUG:-0}"
simplicity_toolchain="${FM_SIMPLICITY_TOOLCHAIN:-1.93.0}"

case "${1:-tests}" in
    tests)
        # The separate network step runs the four-guardian process fixtures.
        rustup run "$simplicity_toolchain" cargo test --release --locked \
            -p fedimint-simplicity-common -p fedimint-simplicity-client \
            -p fedimint-simplicity-server -p fedimint-core \
            -p fedimint-client-module -p fedimint-client \
            -p fedimint-mintv2-client -p fedimint-server --lib --tests -- \
            --skip tests::assets::network:: --test-threads=2
        rustup run "$simplicity_toolchain" cargo check --release --locked \
            -p fedimint-simplicity-client --examples
        ;;
    network)
        rustup run "$simplicity_toolchain" cargo test --release --locked \
            -p fedimint-simplicity-server --lib tests::assets::network:: -- \
            --nocapture --test-threads=1
        ;;
    guardian)
        rustup run "$simplicity_toolchain" cargo build --release --locked -p fedimintd
        "${CARGO_TARGET_DIR:-target}/release/fedimintd" --version
        rustup run "$simplicity_toolchain" cargo build --release --locked \
            -p fedimintd --features experimental-simplicity
        "${CARGO_TARGET_DIR:-target}/release/fedimintd" --version
        ;;
    clippy)
        rustup run "$simplicity_toolchain" cargo clippy --release --locked \
            -p fedimint-simplicity-common -p fedimint-simplicity-client \
            -p fedimint-simplicity-server --all-targets --no-deps -- -D warnings
        ;;
    *)
        echo "Usage: $0 [tests|network|guardian|clippy]" >&2
        exit 2
        ;;
esac
