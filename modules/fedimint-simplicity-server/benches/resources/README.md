# Simplicity resource measurements

This is a data-gathering harness, not a fee policy or a throughput guarantee.
It does not change consensus limits, fees, or guardian execution. It uses Divan,
as do existing Fedimint benchmarks. No benchmark is added to PR CI.

The minimum guardian performance target is **Raspberry Pi 5**. Calibration needs
measurements on that hardware, including the full admission/consensus path. Record
RAM, storage, cooling, clock settings and thermal throttling alongside each Pi
run. Results from faster machines establish comparisons, not Pi latency or safe
production limits.

## Running

From the repository root, in the normal development environment:

```sh
# Check decoding, execution, preflight, module and core-processing outcomes.
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

# Focus on the aggregate caps and complete in-memory submission checks.
cargo bench --locked -p fedimint-simplicity-server --bench resources -- \
  'transaction_preflight|core_submission' \
  --sample-count 100 --sample-size 1 --color never > caps-timing.txt
```

Use the default optimized bench profile for measurements. `--profile dev` is
useful only for fixture smoke checks. Divan accepts name filters, e.g.
`guardian_validation::recovery_32`. Run on an otherwise idle machine, repeat the
timing run, and keep the full output, manifest, compiler/OS/CPU/RAM, source
revision, compiler flags and allocator details. Do not run builds alongside the
measurements. The manifest pins fixture transactions, not only case labels.

Fixture construction, SimplicityHL compilation, signing, database seeding,
warm-up and manifest generation are outside measurement. Every invocation first
checks all fixtures against the real decoder, executor, preflight, guardian hook
and core submission processor, including exact rejection reasons. It also checks
the fully signed transaction's
encoded size against `Transaction::MAX_TX_SIZE` (49,968 bytes at this revision).
The same fixed keys, nonce, votes and contract outpoints reproduce the same cases.

## What each stage measures

| Stage | Scope |
| --- | --- |
| `decode` | Production `decode_program`: length checks, structural preflight, type inference/limits, redemption decoding and static bounds, including dropping its result. |
| `vm_cached` | A predecoded program: allocate a fresh BitMachine, execute, and drop the machine/result. Excludes decoding, CMR and execution-version checks. |
| `runtime_execute` | Production `execute`, including decode, CMR/version checks, VM allocation/execution and fee calculation. |
| `intent_hash` | One production v0/v1 transaction intent hash. |
| `environment_clone` | Clone and drop one already constructed environment. Shares immutable input/output/action data through `Arc` and copies the current contract snapshot. It is **not** a measurement of the entire context-building path. The first baseline predates sharing and copied the full context. |
| `guardian_validation` | The actual `ServerModule::validate_transaction` hook: output validation/hashing, consumed-contract DB reads, conservation checks, block votes, intent hashes, environment construction, every input's runtime execution and final transaction hash. Includes current-thread executor entry and result destruction. |
| `transaction_preflight` | Production `resources::check_transaction`: combined byte/count checks, creation-signature charges and sequential redemption decoding/static cost accumulation. Stops on the first error, before VM execution or database access. |
| `core_submission` | Production `process_transaction_with_dbtx` in submission mode: kind-wide preflight, input verification, module validation, outer signatures, native funding checks and processing hooks. Includes creation of a fresh warm MemDatabase transaction and dropping all writes after each iteration. |

Per-input stages use the first input. The guardian stage measures all inputs in
the transaction. Its database is a small, seeded MemDatabase with a warm,
read-only transaction. No database snapshot construction is timed. Asset records
are seeded directly; these fixtures measure transitions from ledger state, not
asset genesis.

The guardian stage is **module validation**, not end-to-end acceptance. It omits
core's stateless transaction preflight (which decodes each Simplicity input),
outer signature verification, native bitcoin funding checks, processing hooks,
database commits, RocksDB I/O, network admission and consensus. Transactions have
outer signatures but do not include fee/collateral sponsorship. In particular,
`market_issue` needs foreign funding to pass core conservation. Benchmark success
must not be interpreted as full transaction acceptance.

The core stage adds a dummy-module funding input and regenerates outer
signatures outside measurement. This does not alter the inner Simplicity intent.
It seeds state separately and runs all core submission checks, but does not
commit writes, exercise RocksDB, mint funding, network admission or consensus.
Accepted fixtures are rolled back between iterations. The schema-2 manifest
records both the original and funded transaction hashes/sizes and the expected
preflight error. The isolated guardian/runtime stages intentionally retain
over-budget workloads for historical comparisons; only the core stage models
the caps' effect on transaction processing.

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
  one transaction, respectively. All four exceed the new 2,000,000 milliweight
  transaction budget and are rejected by preflight.
- `signature_budget` executes 32 valid signature checks in one input;
  `signature_split_budget` spreads those checks over four inputs. Both fit the
  shared budget. `signature_budget_over` doubles the single-input workload and
  is rejected before execution.
- `constants_3` / `constants_4`: three or four copies of the 4 KiB constant
  program, respectively. The first is decoder-heavy but accepted; the second
  exceeds the combined 16 KiB redemption limit and is rejected before decoding.
- `creation_19` / `creation_20`: a minimal contract spend plus 19 or 20 asset
  creation signatures. The latter exceeds the shared budget, since each creation
  consumes 100,000 milliweight and the contract also has nonzero cost.
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
sharing/type inference, all market branches, large historical databases,
recovery scans or multiple module instances at once.
Those remain relevant before production calibration, alongside measurements on
guardian-class Linux hardware and concurrent invalid-submission load.

The [2026-10-02 report](REPORT-2026-10-02.md) contains the first measured baseline,
its raw data, and interpretation.
The [context-sharing comparison](REPORT-2026-10-02-context-sharing.md) records the
first optimization against that unchanged fixture matrix.
The [aggregate-cap measurements](REPORT-2026-10-02-transaction-caps.md) add
preflight and core submission measurements, including accepted and rejected
workloads near the new transaction budgets.
Keep the harness, fixtures and methodology as regression tools. Retain selected
comparison reports; routine raw runs need not all be committed.
Fee coefficients or limit changes should be reviewed separately after examining
the measurements.
