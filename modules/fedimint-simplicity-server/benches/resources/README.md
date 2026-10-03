# Simplicity resource measurements

This is a data-gathering harness, not a fee policy or a throughput guarantee.
It does not change consensus limits, fees, or guardian execution. It uses Divan,
as do existing Fedimint benchmarks. No benchmark is added to PR CI.

## Running

From the repository root, in the normal development environment:

```sh
# Check every fixture's decoding, execution and guardian-validation outcome.
cargo bench --locked -p fedimint-simplicity-server --bench resources -- --test

# Deterministic sizes, static bounds, fees, expected errors and transaction hashes.
FM_SIMPLICITY_BENCH_MANIFEST=1 cargo bench --locked \
  -p fedimint-simplicity-server --bench resources > manifest.json

# Timing: ordinary System allocator, no allocation instrumentation.
cargo bench --locked -p fedimint-simplicity-server --bench resources -- \
  --sample-count 100 --sample-size 1 --color never > timing.txt

# Allocations: separate executable; do not use its timings for comparisons.
cargo bench --locked -p fedimint-simplicity-server --bench resources \
  --features bench-alloc -- \
  --sample-count 100 --sample-size 1 --color never > allocations.txt
```

Use the default optimized bench profile for measurements. `--profile dev` is
useful only for fixture smoke checks. Divan accepts name filters, e.g.
`guardian_validation::recovery_32`. Run on an otherwise idle machine, repeat the
timing run, and keep the full output, manifest, compiler/OS/CPU/RAM, source
revision, compiler flags and allocator details. Do not run builds alongside the
measurements. The manifest pins fixture transactions, not only case labels.

Fixture construction, SimplicityHL compilation, signing, database seeding,
warm-up and manifest generation are outside measurement. Every invocation first
checks all fixtures against the real decoder, executor and guardian hook,
including exact rejection reasons. It also checks the fully signed transaction's
encoded size against `Transaction::MAX_TX_SIZE` (49,968 bytes at this revision).
The same fixed keys, nonce, votes and contract outpoints reproduce the same cases.

## What each stage measures

| Stage | Scope |
| --- | --- |
| `decode` | Production `decode_program`: length checks, structural preflight, type inference/limits, redemption decoding and static bounds, including dropping its result. This is also the work performed by guardian `verify_input`. |
| `vm_cached` | A predecoded program: allocate a fresh BitMachine, execute, and drop the machine/result. Excludes decoding, CMR and execution-version checks. |
| `runtime_execute` | Production `execute`, including decode, CMR/version checks, VM allocation/execution and fee calculation. |
| `intent_hash` | One production v0/v1 transaction intent hash. |
| `environment_clone` | Clone and drop one already constructed environment. Isolates the cost of copying its vectors, contracts, assets and recovery data. It is **not** a measurement of the entire context-building path. |
| `guardian_validation` | The actual `ServerModule::validate_transaction` hook: output validation/hashing, consumed-contract DB reads, conservation checks, block votes, intent hashes, environment construction, every input's runtime execution and final transaction hash. Includes current-thread executor entry and result destruction. |

Per-input stages use the first input. The guardian stage measures all inputs in
the transaction. Its database is a small, seeded MemDatabase with a warm,
read-only transaction. No database snapshot construction is timed. Asset records
are seeded directly; these fixtures measure transitions from ledger state, not
asset genesis.

The guardian stage is **module validation**, not end-to-end acceptance. It omits
core's initial parallel `verify_input` pass (which decodes each input again),
outer signature verification, native bitcoin funding checks, processing hooks,
database commits, RocksDB I/O, network admission and consensus. Transactions have
outer signatures but do not include fee/collateral sponsorship. In particular,
`market_issue` needs foreign funding to pass core conservation. Benchmark success
must not be interpreted as full transaction acceptance.

The helper environment is for isolated runtime/clone measurements. The guardian
measurement constructs its own context using production code; it does not use
that helper. Do not subtract stage medians to infer an exact unmeasured stage:
allocation lifetimes and caches differ.

Divan's `max alloc` measures peak additional live bytes requested through Rust's
global allocator on the measured thread, and `alloc` measures allocation count
and bytes. These are **not RSS**. They exclude pre-existing fixtures/database,
stack, allocator overhead and allocations made directly by C or other threads.
Timing and profiling use separate builds to avoid profiler overhead in reported
latency. Outputs and temporaries are dropped inside measurement; sample size one
keeps peak allocation associated with one operation.

## Cases

- `unit_v0` / `unit_v1`: minimal programs, exposing fixed overhead.
- `owner`: one valid transaction-bound BIP340 signature.
- `market_issue` / `market_resolve`: the actual binary-market template, including
  asset accounting or an external oracle's signature. `bad_oracle` signs the
  wrong outcome and is rejected by the program.
- `inputs_8` / `inputs_32`: increasing input counts with no successors;
  `context_32` adds 32 successors; `recovery_32` adds 1 KiB to every consumed
  contract and successor; `assets_32` holds all 32 assets in every one of 32
  consumed contracts and 32 successors. `foreign_outputs_128` hashes the maximum
  outer-output count with 32 module inputs.
- `cost_near_limit`: a tiny shared DAG describing 49,152 unit executions, near
  the 10,000,000 milliweight cap. `signature_cost_near_limit` instead repeats
  192 valid BIP340 checks against a fixed message, at a similar static bound.
  These synthetic policies are workload probes, not usable authorization
  contracts. `cost_32` and `signature_cost_32` put 32 copies of each workload in
  one transaction, respectively.
- `wide_value`: a shared DAG builds a 1,048,576-bit intermediate value before
  discarding it. `large_constant` embeds a 4 KiB word. `large_witness` hashes
  128 SHA256 blocks, consuming exactly 8 KiB of witness data.
- `asset_failure` fails conservation in a large asset context;
  `late_bad_signature` executes 31 valid owner programs before the last fails.
  These show work performed for rejected transactions, which pay no accepted
  transaction fee.
- Decoder rejection cases cover excessive static cost, exponential inferred
  types, a truncated huge word, an impossible declared node count, byte limits,
  and a trailing witness. The existing allocation regression tests remain the
  correctness checks for rejecting hostile declarations before allocation.

This is a representative matrix, not an adversarial maximum search. It does not
exercise every combination of frame/cell/type limits, worst-case canonical
sharing/type inference, asset-creation signatures, all market branches, large
historical databases, recovery scans or multiple module instances at once.
Those remain relevant before production calibration, alongside measurements on
guardian-class Linux hardware and concurrent invalid-submission load.

The [2026-10-02 report](REPORT-2026-10-02.md) contains the first measured baseline,
its raw data, and interpretation.
Fee coefficients or limit changes should be reviewed separately after examining
the measurements.
