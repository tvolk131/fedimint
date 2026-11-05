#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

python3 - "$@" <<'PY'
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path


def output(*command):
    return subprocess.check_output(command, text=True).strip()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def public_setting(name, default, pattern):
    value = os.environ.get(name, default)
    if re.fullmatch(pattern, value):
        return value
    return {
        "value": "redacted-nonstandard-setting",
        "sha256": hashlib.sha256(value.encode()).hexdigest(),
    }


def write_json(path, manifest):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


arguments = sys.argv[1:]
if arguments != ["environment"] and not (
    len(arguments) == 3
    and arguments[0] == "guardian"
    and arguments[1] in ("default", "experimental-simplicity")
):
    sys.exit("Usage: simplicity-artifacts.sh environment | guardian {default|experimental-simplicity} BINARY")

evidence = Path("evidence")
evidence.mkdir(exist_ok=True)
toolchain = os.environ.get("FM_SIMPLICITY_TOOLCHAIN", "1.93.0")
compiler_output = output("rustup", "run", toolchain, "rustc", "-vV")
compiler_fields = dict(
    line.split(": ", 1) for line in compiler_output.splitlines() if ": " in line
)
compiler = {
    key: value if re.fullmatch(r"[A-Za-z0-9_.+-]+", value) else "redacted"
    for key, value in compiler_fields.items()
    if key in ("release", "host", "commit-hash", "commit-date", "LLVM version")
}
cargo_output = output("rustup", "run", toolchain, "cargo", "--version")
cargo_version = re.search(r"^cargo ([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)", cargo_output)
if cargo_version is None or "host" not in compiler:
    sys.exit("Cannot identify the selected Rust compiler and Cargo")

source_revision = output("git", "rev-parse", "HEAD")
if not re.fullmatch(r"[0-9a-f]{40,64}", source_revision):
    sys.exit("Invalid source revision")
tracked_changes = subprocess.run(["git", "diff", "--quiet", "HEAD"], check=False).returncode
if tracked_changes not in (0, 1):
    sys.exit("Cannot determine tracked source changes")
tracked_diff = subprocess.check_output(["git", "diff", "--binary", "HEAD"])
untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "-z"])
untracked_count = len([path for path in untracked.split(b"\0") if path])

build_environment = {
    "CARGO_BUILD_JOBS": public_setting("CARGO_BUILD_JOBS", "2", r"[1-9][0-9]*"),
    "CARGO_BUILD_TARGET": public_setting("CARGO_BUILD_TARGET", compiler["host"], re.escape(compiler["host"])),
    "CARGO_INCREMENTAL": public_setting("CARGO_INCREMENTAL", "0", r"[01]"),
    "CARGO_PROFILE_RELEASE_DEBUG": public_setting("CARGO_PROFILE_RELEASE_DEBUG", "0", r"[012]|none|limited|full|line-tables-only|line-directives-only"),
    "RUSTFLAGS": public_setting("RUSTFLAGS", "--cfg tokio_unstable", r"(?:--cfg tokio_unstable)?"),
    "RUSTDOCFLAGS": public_setting("RUSTDOCFLAGS", "", r""),
    "CARGO_ENCODED_RUSTFLAGS": public_setting("CARGO_ENCODED_RUSTFLAGS", "", r""),
    "CC": public_setting("CC", "cc", r"cc|gcc(?:-[0-9]+)?|clang(?:-[0-9]+)?"),
    "CXX": public_setting("CXX", "c++", r"c\+\+|g\+\+(?:-[0-9]+)?|clang\+\+(?:-[0-9]+)?"),
    "CFLAGS": public_setting("CFLAGS", "", r""),
    "CXXFLAGS": public_setting("CXXFLAGS", "", r""),
    "FEDIMINT_BUILD_FORCE_GIT_HASH": public_setting("FEDIMINT_BUILD_FORCE_GIT_HASH", "", r"(?:[0-9a-f]{40,64})?"),
}
manifest = {
    "schema_version": 1,
    "source_revision": source_revision,
    "source_clean": not tracked_changes and not untracked_count,
    "tracked_source_dirty": bool(tracked_changes),
    "untracked_file_count": untracked_count,
    "tracked_diff_sha256": hashlib.sha256(tracked_diff).hexdigest(),
    "cargo_lock_sha256": sha256_file(Path("Cargo.lock")),
    "flake_lock_sha256": sha256_file(Path("flake.lock")),
    "rustc": compiler,
    "cargo_version": cargo_version.group(1),
    "toolchain": public_setting("FM_SIMPLICITY_TOOLCHAIN", "1.93.0", r"[0-9]+\.[0-9]+\.[0-9]+|nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}"),
    "build": {
        "profile": "release",
        "locked": True,
        "default_features": True,
        "environment": build_environment,
        "custom_target_directory": "CARGO_TARGET_DIR" in os.environ,
        "libclang_path_override": "LIBCLANG_PATH" in os.environ,
        "rustc_wrapper_override": bool(os.environ.get("RUSTC_WRAPPER")),
        "configuration_scope": "Selected invocation and allowlisted environment; external Cargo configuration is not captured",
    },
    "coverage": {
        "release_job": "Native Linux x86_64 only when this workflow succeeds",
        "native_consensus_jobs": "Linux x86_64 and aarch64; separate jobs, not full release qualification",
        "local_execution": "Not evidence of Linux CI success",
        "wasm": "Not qualified by this workflow",
        "raspberry_pi_5": "Not tested; aarch64 CI is not Pi5 qualification",
        "external_services": "Mint and mintv2 regression fixtures use fake Bitcoin; no live Bitcoin or Lightning qualification",
        "test_selection_evidence": "test-selections/*.json records required runnable names and aggregate execution totals for the legacy-mint and network selections only",
        "mintv2_snapshot_generation": "db::snapshot_ tests are filtered out; retained migration-snapshot validation still runs",
        "other_tests": "Broad tests, examples and doctests retain their logs and ignored/filtered counts; they do not have required-name selection guards",
    },
}

if arguments[0] == "environment":
    manifest["features"] = {
        "tests": "Selected packages' defaults with Cargo feature unification",
        "guardian_default": ["default"],
        "guardian_experimental_simplicity": ["default", "experimental-simplicity"],
    }
    write_json(evidence / "release-manifest.json", manifest)
else:
    variant = arguments[1]
    directory = evidence / "guardians" / variant
    directory.mkdir(parents=True, exist_ok=True)
    binary = directory / "fedimintd"
    shutil.copyfile(arguments[2], binary)
    shutil.copymode(arguments[2], binary)
    manifest["build"]["package"] = "fedimintd"
    manifest["build"]["features"] = ["default"] + (
        ["experimental-simplicity"] if variant == "experimental-simplicity" else []
    )
    manifest["guardian"] = {
        "variant": variant,
        "binary": binary.relative_to(evidence).as_posix(),
        "sha256": sha256_file(binary),
        "size_bytes": binary.stat().st_size,
        "host_os": platform.system() if platform.system() in ("Linux", "Darwin", "Windows") else "other",
        "qualification_status": "Built; version probe and other workflow checks have separate outcomes",
    }
    write_json(directory / "manifest.json", manifest)
    (directory / "SHA256SUMS").write_text(manifest["guardian"]["sha256"] + "  fedimintd\n")
    result = subprocess.run([str(binary), "--version"], capture_output=True, check=False)
    (directory / "version.log").write_bytes(result.stdout + result.stderr)
    manifest["guardian"]["version_probe_exit_code"] = result.returncode
    write_json(directory / "manifest.json", manifest)
    sys.stdout.buffer.write(result.stdout + result.stderr)
    sys.exit(result.returncode)
PY
