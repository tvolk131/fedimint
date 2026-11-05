#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
    echo "Usage: $0 --name NAME --require TEST [--require TEST ...] [--evidence-dir DIR] -- COMMAND [ARG ...]" >&2
    exit 2
}

name=
evidence_directory=evidence/test-selections
required_tests=()
required_count=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --name|--require|--evidence-dir)
            [[ $# -ge 2 && -n "$2" ]] || usage
            case "$1" in
                --name) name="$2" ;;
                --require) required_tests+=("$2"); required_count=$((required_count + 1)) ;;
                --evidence-dir) evidence_directory="$2" ;;
            esac
            shift 2
            ;;
        --) shift; break ;;
        *) usage ;;
    esac
done
[[ "$name" =~ ^[a-z0-9-]+$ && $required_count -gt 0 && $# -gt 0 ]] || usage
command=("$@")
evidence_directory="$evidence_directory/$name"
mkdir -p "$evidence_directory"
printf 'status=running\n' > "$evidence_directory/result.txt"

finish() {
    exit_code=$?
    trap - EXIT
    if [[ $exit_code -eq 0 ]]; then
        status=passed
    else
        status=failed
        echo "Test selection $name failed (exit $exit_code)" >&2
        cat "$evidence_directory/error.txt" >&2
    fi
    printf 'status=%s\nexit_code=%s\n' "$status" "$exit_code" > "$evidence_directory/result.tmp"
    mv "$evidence_directory/result.tmp" "$evidence_directory/result.txt"
    exit "$exit_code"
}

trap finish EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
for report in error command required selected ignored listing ignored-listing execution totals inventory; do
    : > "$evidence_directory/$report.txt"
done
printf '%q ' "${command[@]}" > "$evidence_directory/command.txt"
printf '\n' >> "$evidence_directory/command.txt"
printf '%s\n' "${required_tests[@]}" > "$evidence_directory/required.txt"

fail() {
    printf '%s\n' "$1" >> "$evidence_directory/error.txt"
    exit "${2:-1}"
}

"${command[@]}" --list --format=terse > "$evidence_directory/listing.txt" || fail 'test listing failed' "$?"
"${command[@]}" --list --format=terse --ignored > "$evidence_directory/ignored-listing.txt" || fail 'ignored-test listing failed' "$?"
for listing in listing ignored-listing; do
    if [[ "$listing" == listing ]]; then
        inventory=selected
    else
        inventory=ignored
    fi
    sed -n 's/: test$//p' "$evidence_directory/$listing.txt" | sort > "$evidence_directory/$inventory.txt"
done
unselected_ignored="$(comm -23 "$evidence_directory/ignored.txt" "$evidence_directory/selected.txt")"
if [[ -n "$unselected_ignored" ]]; then
    fail 'ignored-test listing disagrees with selected tests'
fi
for required in "${required_tests[@]}"; do
    count="$(grep -Fxc -- "$required" "$evidence_directory/selected.txt" || true)"
    [[ "$count" -eq 1 ]] || fail "required test missing or ambiguous: $required"
    if grep -Fxq -- "$required" "$evidence_directory/ignored.txt"; then
        fail "required test is ignored: $required"
    fi
done
selected_count="$(wc -l < "$evidence_directory/selected.txt")"
ignored_count="$(wc -l < "$evidence_directory/ignored.txt")"
runnable_count=$((selected_count - ignored_count))
[[ $runnable_count -gt 0 ]] || fail 'selection contains no runnable tests'
printf 'selected=%d\nignored=%d\nrunnable=%d\n' "$selected_count" "$ignored_count" "$runnable_count" > "$evidence_directory/inventory.txt"

set +e
"${command[@]}" --format=pretty --color=never | tee "$evidence_directory/execution.txt"
execution_status=("${PIPESTATUS[@]}")
set -e
summary_status=0
awk -v expected_passed="$runnable_count" -v expected_ignored="$ignored_count" '
    /^test result: (ok|FAILED)\. [0-9]+ passed; [0-9]+ failed; [0-9]+ ignored; [0-9]+ measured; [0-9]+ filtered out;/ {
        summaries++
        if ($3 != "ok.") unsuccessful++
        passed += $4
        failed += $6
        ignored += $8
        measured += $10
        filtered += $12
    }
    END {
        printf "summaries=%d\npassed=%d\nfailed=%d\nignored=%d\nmeasured=%d\nfiltered_out=%d\n", summaries, passed, failed, ignored, measured, filtered
        if (!summaries || unsuccessful || failed || measured || passed != expected_passed || ignored != expected_ignored) exit 1
    }
' "$evidence_directory/execution.txt" > "$evidence_directory/totals.txt" || summary_status=$?
[[ ${execution_status[0]} -eq 0 ]] || fail 'test execution failed' "${execution_status[0]}"
[[ ${execution_status[1]} -eq 0 ]] || fail 'recording test output failed' "${execution_status[1]}"
[[ $summary_status -eq 0 ]] || fail 'executed test totals disagree with the runnable selection'
