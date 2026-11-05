#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == --fixture ]]; then
    shift
    phase=execution
    for argument in "$@"; do
        case "$argument" in
            --list) phase=listing ;;
            --ignored) phase=ignored-listing ;;
        esac
    done
    printf '%s\0' "$@" > "$fixture_directory/$phase.args"
    if [[ -f "$fixture_directory/interrupt" ]]; then
        grep -Fxq 'status=running' "$fixture_directory/evidence/fixture/result.txt"
        : > "$fixture_directory/invalidated"
        kill -TERM "$PPID"
        exit 0
    fi
    cat "$fixture_directory/$phase.txt"
    exit "$(cat "$fixture_directory/$phase.exit")"
fi

script_directory="$(cd "$(dirname "$0")" && pwd)"
test_directory="$(mktemp -d)"
trap 'rm -rf "$test_directory"' EXIT
case_count=0

assert_equal() {
    if [[ "$1" != "$2" ]]; then
        echo "$case_name: expected '$2', got '$1'" >&2
        exit 1
    fi
}

assert_line() {
    if ! grep -Fxq -- "$2" "$1"; then
        echo "$case_name: missing '$2' in $1" >&2
        cat "$1" >&2
        exit 1
    fi
}

summary() {
    printf 'test result: %s. %s passed; %s failed; %s ignored; %s measured; %s filtered out; finished in 0.01s\n' \
        "${6:-ok}" "${1:-1}" "${2:-0}" "${3:-0}" "${4:-0}" "${5:-0}"
}

new_case() {
    local phase
    case_count=$((case_count + 1))
    case_name="$1"
    export fixture_directory="$test_directory/case $case_count"
    mkdir -p "$fixture_directory"
    printf 'required: test\n' > "$fixture_directory/listing.txt"
    : > "$fixture_directory/ignored-listing.txt"
    summary > "$fixture_directory/execution.txt"
    for phase in listing ignored-listing execution; do
        printf '0\n' > "$fixture_directory/$phase.exit"
    done
    required=(--require required)
    command=(bash "$script_directory/test-simplicity-test-selection.sh" --fixture cargo test --release --locked -p 'fixture package' -- --exact)
    evidence="$fixture_directory/evidence/fixture"
}

run_guard() {
    actual_exit=0
    bash "$script_directory/simplicity-test-selection.sh" --name fixture \
        --evidence-dir "$fixture_directory/evidence" "${required[@]}" -- "${command[@]}" \
        > "$fixture_directory/stdout.txt" 2> "$fixture_directory/stderr.txt" || actual_exit=$?
    if [[ "$actual_exit" -ne "$1" ]]; then
        cat "$fixture_directory/stderr.txt" >&2
    fi
    assert_equal "$actual_exit" "$1"
    if [[ "$1" -eq 0 ]]; then status=passed; else status=failed; fi
    assert_line "$evidence/result.txt" "status=$status"
    assert_line "$evidence/result.txt" "exit_code=$1"
}

reject_inventory() {
    run_guard 1
    assert_line "$evidence/error.txt" "$1"
    assert_equal "$(test -f "$fixture_directory/execution.args" && echo yes || echo no)" no
}

new_case 'success preserves arguments and records counts'
run_guard 0
assert_line "$evidence/inventory.txt" runnable=1
assert_line "$evidence/totals.txt" passed=1
for phase in listing ignored-listing execution; do
    arguments=("${command[@]:3}")
    case "$phase" in
        listing) arguments+=(--list --format=terse) ;;
        ignored-listing) arguments+=(--list --format=terse --ignored) ;;
        execution) arguments+=(--format=pretty --color=never) ;;
    esac
    printf '%s\0' "${arguments[@]}" > "$fixture_directory/expected.args"
    cmp "$fixture_directory/expected.args" "$fixture_directory/$phase.args"
done
assert_line "$evidence/required.txt" required
assert_line "$evidence/selected.txt" required

for listing in '' 'renamed: test'; do
    new_case 'missing or renamed test'
    printf '%s\n' "$listing" > "$fixture_directory/listing.txt"
    reject_inventory 'required test missing or ambiguous: required'
done

new_case 'one missing scenario within a nonempty group'
required+=(--require missing)
reject_inventory 'required test missing or ambiguous: missing'

new_case 'required ignored test within a nonempty group'
printf 'required: test\nother: test\n' > "$fixture_directory/listing.txt"
printf 'required: test\n' > "$fixture_directory/ignored-listing.txt"
reject_inventory 'required test is ignored: required'

new_case 'ignored-only group'
printf 'required: test\n' > "$fixture_directory/ignored-listing.txt"
reject_inventory 'required test is ignored: required'

new_case 'duplicate required name'
printf 'required: test\nrequired: test\n' > "$fixture_directory/listing.txt"
reject_inventory 'required test missing or ambiguous: required'

new_case 'unrelated empty harnesses'
{ summary 0; summary; summary 0; } > "$fixture_directory/execution.txt"
run_guard 0
assert_line "$evidence/totals.txt" summaries=3
assert_line "$evidence/totals.txt" passed=1

new_case 'additional runnable and intentionally ignored tests'
printf 'required: test\nextra: test\nmanual: test\n' > "$fixture_directory/listing.txt"
printf 'manual: test\n' > "$fixture_directory/ignored-listing.txt"
summary 2 0 1 0 3 > "$fixture_directory/execution.txt"
run_guard 0
assert_line "$evidence/ignored.txt" manual
assert_line "$evidence/totals.txt" filtered_out=3

for phase in listing ignored-listing; do
    new_case "$phase failure"
    printf '101\n' > "$fixture_directory/$phase.exit"
    run_guard 101
    assert_equal "$(test -f "$fixture_directory/execution.args" && echo yes || echo no)" no
done

new_case 'execution failure records totals and propagates exit'
summary 0 1 0 0 0 FAILED > "$fixture_directory/execution.txt"
printf '101\n' > "$fixture_directory/execution.exit"
run_guard 101
assert_line "$evidence/totals.txt" failed=1

for mismatch in absent zero extra ignored failed measured status; do
    new_case "invalid execution summary: $mismatch"
    case "$mismatch" in
        absent) : > "$fixture_directory/execution.txt" ;;
        zero) summary 0 > "$fixture_directory/execution.txt" ;;
        extra) summary 2 > "$fixture_directory/execution.txt" ;;
        ignored) summary 1 0 1 > "$fixture_directory/execution.txt" ;;
        failed) summary 0 1 0 0 0 FAILED > "$fixture_directory/execution.txt" ;;
        measured) summary 1 0 0 1 > "$fixture_directory/execution.txt" ;;
        status) summary 1 0 0 0 0 FAILED > "$fixture_directory/execution.txt" ;;
    esac
    run_guard 1
    assert_line "$evidence/error.txt" 'executed test totals disagree with the runnable selection'
done

new_case 'inconsistent ignored inventory'
printf 'unknown: test\n' > "$fixture_directory/ignored-listing.txt"
reject_inventory 'ignored-test listing disagrees with selected tests'

new_case 'duplicate ignored inventory exceeds selected count'
printf 'required: test\nmanual: test\n' > "$fixture_directory/listing.txt"
printf 'manual: test\nmanual: test\n' > "$fixture_directory/ignored-listing.txt"
reject_inventory 'ignored-test listing disagrees with selected tests'

new_case 'command launch failure'
command=("$test_directory/missing-cargo")
launch_exit=0
"${command[@]}" --list --format=terse > /dev/null 2>&1 || launch_exit=$?
run_guard "$launch_exit"
assert_line "$evidence/error.txt" 'test listing failed'

new_case 'old success invalidated before interrupted listing'
mkdir -p "$evidence"
printf 'status=passed\n' > "$evidence/result.txt"
printf 'passed=99\n' > "$evidence/totals.txt"
: > "$fixture_directory/interrupt"
run_guard 143
assert_equal "$(test -f "$fixture_directory/invalidated" && echo yes || echo no)" yes
assert_equal "$(cat "$evidence/totals.txt")" ''

new_case 'output streaming and nonstandard exit propagation'
{ printf 'test output\n'; summary; } > "$fixture_directory/execution.txt"
printf '7\n' > "$fixture_directory/execution.exit"
run_guard 7
assert_line "$fixture_directory/stdout.txt" 'test output'
assert_line "$evidence/execution.txt" 'test output'

for invalid in no-require unsafe-name no-command; do
    new_case "invalid invocation: $invalid"
    arguments=(--name fixture --require required)
    case "$invalid" in
        no-require) arguments=(--name fixture) ;;
        unsafe-name) arguments=(--name ../fixture --require required) ;;
        no-command) command=("") ;;
    esac
    actual_exit=0
    if [[ "$invalid" == no-command ]]; then
        bash "$script_directory/simplicity-test-selection.sh" "${arguments[@]}" -- > /dev/null 2>&1 || actual_exit=$?
    else
        bash "$script_directory/simplicity-test-selection.sh" "${arguments[@]}" -- "${command[@]}" > /dev/null 2>&1 || actual_exit=$?
    fi
    assert_equal "$actual_exit" 2
done

printf 'Passed %s test-selection regression cases\n' "$case_count"
