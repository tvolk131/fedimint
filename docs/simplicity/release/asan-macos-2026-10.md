# Simplicity: October 2026 macOS AddressSanitizer campaign notes

This record preserves toolchain workarounds from the October 2026 AArch64 macOS
run of the bounded mutation campaign described in the
[consensus vectors README](../../../modules/fedimint-simplicity-common/tests/vectors/README.md#bounded-mutation-and-sanitizer-campaigns).
It qualifies nothing on its own; see the [evidence index](evidence-index.md) for
revision-bound results, including the hosted Linux sanitizer job.

On that Mac, Apple's Clang 21 ASan used a private ABI incompatible with Rust's
runtime, so target C/C++ compilation used upstream LLVM Clang. Set `CMAKE` if it
is outside PATH.

The campaign used nightly-2026-02-10 and upstream Clang 21.1.8. Both Rust and C
must use the same sanitizer runtime, and CMake's standalone compiler probes also
need it: the tested C flags included
`-fsanitize=address -fno-sanitize-link-runtime -fno-omit-frame-pointer`, plus
`-L`, `-lrustc-nightly_rt.asan` and an rpath to that nightly's target library
directory. This avoided an upstream Clang runtime initialization hang on that
macOS release. Check a minimal C/Rust executable and a deliberate memory-error
positive control before interpreting a silent process as a running campaign.

On macOS 26.6.2 that runtime's LeakSanitizer shutdown scan also deadlocked in
`get_dyld_hdr` while dynamically loading an introspection library with allocator
locks held. The completed AddressSanitizer run used `detect_leaks=0` with
`detect_stack_use_after_return=1:halt_on_error=1`; it does not establish absence
of leaks. Preserve the failed-run stack sample separately from the successful
ASan log. A supported Linux LeakSanitizer run remains useful.
