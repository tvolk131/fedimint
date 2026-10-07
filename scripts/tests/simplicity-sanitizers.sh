#!/usr/bin/env bash
# Focused native Linux campaign. No wallet, federation credentials or live funds.
set -euo pipefail
cd "$(dirname "$0")/../.."
test "$(uname -s)" = Linux
test "$(uname -m)" = x86_64

simplicity_toolchain=nightly-2026-02-10
simplicity_target=x86_64-unknown-linux-gnu
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/simplicity-linux-asan}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}" CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=1 CARGO_PROFILE_TEST_DEBUG=1
export CC_x86_64_unknown_linux_gnu=clang-21 CXX_x86_64_unknown_linux_gnu=clang++-21
export CFLAGS_x86_64_unknown_linux_gnu='-fsanitize=address -fno-omit-frame-pointer'
export CXXFLAGS_x86_64_unknown_linux_gnu="$CFLAGS_x86_64_unknown_linux_gnu"
export LIBCLANG_PATH=/usr/lib/llvm-21/lib
# One Clang runtime serves both languages, including standalone CMake probes.
export RUSTFLAGS='--cfg tokio_unstable -Zsanitizer=address -Zexternal-clangrt -Cforce-frame-pointers=yes -Clinker=clang-21 -Clink-arg=-fsanitize=address'
export ASAN_OPTIONS='detect_leaks=1:detect_stack_use_after_return=1:halt_on_error=1'
export ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-21
export FM_SIMPLICITY_REPORT_DIR="$PWD/evidence"
export FM_SIMPLICITY_MUTATION_ROUNDS="${FM_SIMPLICITY_MUTATION_ROUNDS:-100000}"
export FM_SIMPLICITY_MUTATION_SEED="${FM_SIMPLICITY_MUTATION_SEED:-5065796730156482561}"
mkdir -p evidence
{
    git rev-parse HEAD
    sha256sum Cargo.lock
    uname -a
    rustup run "$simplicity_toolchain" rustc -vV
    clang-21 --version
    printf 'RUSTFLAGS=%s\nCFLAGS=%s\nASAN_OPTIONS=%s\n' "$RUSTFLAGS" "$CFLAGS_x86_64_unknown_linux_gnu" "$ASAN_OPTIONS"
} > evidence/sanitizer-environment.txt

simplicity_probe="$(mktemp -d)"
trap 'rm -rf "$simplicity_probe"' EXIT
cat > "$simplicity_probe/probe.c" <<'C'
#include <stdlib.h>
__attribute__((noinline)) void c_probe(unsigned mode) {
    volatile char *p = malloc(8);
    p[mode == 0 ? 8 : 0] = 1;
    /* Deliberately leak when mode == 1. */
    if (mode == 0) free((void *)p);
}
C
cat > "$simplicity_probe/probe.rs" <<'RS'
unsafe extern "C" { fn c_probe(mode: u32); }
fn main() {
    let mode: u32 = std::env::args().nth(1).unwrap().parse().unwrap();
    unsafe {
        if mode < 2 {
            c_probe(mode);
        } else {
            let mut data = vec![0u8; 8];
            std::ptr::write_volatile(data.as_mut_ptr().add(8), 1);
        }
    }
}
RS
clang-21 -g -O1 -fsanitize=address -fno-omit-frame-pointer -c "$simplicity_probe/probe.c" -o "$simplicity_probe/probe.o"
rustup run "$simplicity_toolchain" rustc --edition=2024 --target "$simplicity_target" \
    -Zsanitizer=address -Zexternal-clangrt -Clinker=clang-21 -Clink-arg=-fsanitize=address \
    -Clink-arg="$simplicity_probe/probe.o" "$simplicity_probe/probe.rs" -o "$simplicity_probe/probe"
for mode in 0 1 2; do
    if "$simplicity_probe/probe" "$mode" > "evidence/positive-control-$mode.txt" 2>&1; then
        echo "Sanitizer positive control $mode unexpectedly passed" >&2
        exit 1
    fi
    if [[ "$mode" == 1 ]]; then
        grep -q 'LeakSanitizer: detected memory leaks' "evidence/positive-control-$mode.txt"
    else
        grep -q 'AddressSanitizer: heap-buffer-overflow' "evidence/positive-control-$mode.txt"
    fi
done

rustup run "$simplicity_toolchain" cargo test -Zbuild-std --target "$simplicity_target" \
    --locked -p fedimint-simplicity-common --features compiler --lib
rustup run "$simplicity_toolchain" cargo test -Zbuild-std --target "$simplicity_target" \
    --locked -p fedimint-simplicity-common --features compiler --lib -- \
    --ignored --nocapture --test-threads=1
