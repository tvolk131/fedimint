#!/usr/bin/env bash

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"
export FM_ENABLE_MODULE_LNV2=${FM_ENABLE_MODULE_LNV2:-1}

source scripts/_common.sh
build_workspace
add_target_dir_to_path

fedimint-lnv2-devimint-tests
