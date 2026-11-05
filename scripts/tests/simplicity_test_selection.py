import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys


TEST = re.compile(r"^(.+): test$", re.MULTILINE)
SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out;",
    re.MULTILINE,
)


class SelectionError(Exception):
    def __init__(self, message, exit_code=1):
        super().__init__(message)
        self.exit_code = exit_code if exit_code > 0 else 1


def run_command(command, stream=False):
    if not stream:
        return subprocess.run(command, stdout=subprocess.PIPE, text=True, check=False)
    summaries = []
    with subprocess.Popen(command, stdout=subprocess.PIPE, text=True) as process:
        for line in process.stdout:
            print(line, end="", flush=True)
            if SUMMARY.match(line):
                summaries.append(line)
    return subprocess.CompletedProcess(command, process.returncode, "".join(summaries))


def checked_command(command, phase, stream=False):
    result = run_command(command, stream=stream)
    if result.returncode:
        raise SelectionError(f"{phase} exited with {result.returncode}", result.returncode)
    return result.stdout


def write_report(directory, name, report):
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{name}.json"
    temporary = destination.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    temporary.replace(destination)


def run_selection(name, required, command, evidence_directory):
    report = {
        "schema_version": 1,
        "selection": name,
        "command": command,
        "required_tests": required,
        "status": "running",
    }
    write_report(evidence_directory, name, report)
    exit_code = 0
    try:
        selected = Counter(TEST.findall(checked_command(
            command + ["--list", "--format=terse"], "test listing"
        )))
        report["selected_tests"] = sorted(selected.elements())
        ignored = Counter(TEST.findall(checked_command(
            command + ["--list", "--format=terse", "--ignored"], "ignored-test listing"
        )))
        report["ignored_tests"] = sorted(ignored.elements())
        if ignored - selected:
            raise SelectionError("ignored-test listing disagrees with selected tests")
        runnable = selected - ignored
        for test in required:
            if selected[test] != 1:
                raise SelectionError(f"required test missing or ambiguous: {test}")
            if not runnable[test]:
                raise SelectionError(f"required test is ignored: {test}")
        if not runnable:
            raise SelectionError("selection contains no runnable tests")
        execution = run_command(
            command + ["--format=pretty", "--color=never"], stream=True
        )
        report["execution_exit_code"] = execution.returncode
        summaries = SUMMARY.findall(execution.stdout)
        counts = {
            field: sum(int(summary[index]) for summary in summaries)
            for index, field in enumerate(
                ("passed", "failed", "ignored", "measured", "filtered_out"), start=1
            )
        }
        report["results"] = counts
        if execution.returncode:
            raise SelectionError(
                f"test execution exited with {execution.returncode}", execution.returncode
            )
        if (
            not summaries
            or any(summary[0] != "ok" for summary in summaries)
            or counts["failed"]
            or counts["measured"]
            or counts["passed"] != sum(runnable.values())
            or counts["ignored"] != sum(ignored.values())
        ):
            raise SelectionError("executed test totals disagree with the runnable selection")
        report["status"] = "passed"
    except (SelectionError, OSError) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        exit_code = error.exit_code if isinstance(error, SelectionError) else 1
        print(f"Test selection {name} failed: {error}", file=sys.stderr)
    report["exit_code"] = exit_code
    write_report(evidence_directory, name, report)
    return exit_code


def main():
    parser = argparse.ArgumentParser(description="Require selected libtest tests to exist and run")
    parser.add_argument("--name", required=True)
    parser.add_argument("--require", action="append", required=True)
    parser.add_argument("--evidence-dir", type=Path, default=Path("evidence/test-selections"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    command = arguments.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command or not re.fullmatch(r"[a-z0-9-]+", arguments.name):
        parser.error("a command and a lowercase, hyphenated selection name are required")
    return run_selection(arguments.name, arguments.require, command, arguments.evidence_dir)


if __name__ == "__main__":
    sys.exit(main())
