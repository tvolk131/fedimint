import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import simplicity_test_selection as selection


def summary(passed=1, failed=0, ignored=0, measured=0, filtered=0):
    status = "FAILED" if failed else "ok"
    return (
        f"test result: {status}. {passed} passed; {failed} failed; {ignored} ignored; "
        f"{measured} measured; {filtered} filtered out; finished in 0.01s\n"
    )


class TestSelection(unittest.TestCase):
    def run_guard(
        self, listed="required: test\n", ignored="", output=None, required=None,
        listing_exit=0, ignored_exit=0, execution_exit=0,
    ):
        command = ["cargo", "test", "--release", "--locked", "--", "--exact"]
        responses = [
            subprocess.CompletedProcess(command, listing_exit, listed),
            subprocess.CompletedProcess(command, ignored_exit, ignored),
            subprocess.CompletedProcess(command, execution_exit, summary() if output is None else output),
        ]
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(selection, "run_command", side_effect=responses) as runner:
                with contextlib.redirect_stderr(io.StringIO()):
                    exit_code = selection.run_selection(
                        "fixture", ["required"] if required is None else required,
                        command, Path(directory),
                    )
                report = json.loads((Path(directory) / "fixture.json").read_text())
            calls = runner.call_args_list
        return exit_code, report, calls

    def test_success_preserves_command_and_records_counts(self):
        exit_code, report, calls = self.run_guard()
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["results"]["passed"], 1)
        self.assertEqual(calls[0].args[0], report["command"] + ["--list", "--format=terse"])
        self.assertEqual(calls[1].args[0], report["command"] + ["--list", "--format=terse", "--ignored"])
        self.assertEqual(calls[2].args[0], report["command"] + ["--format=pretty", "--color=never"])
        self.assertTrue(calls[2].kwargs["stream"])

    def test_missing_or_renamed_test_fails_before_execution(self):
        for listed in ("", "renamed: test\n"):
            with self.subTest(listed=listed):
                exit_code, report, calls = self.run_guard(listed=listed)
                self.assertEqual(exit_code, 1)
                self.assertIn("missing", report["error"])
                self.assertEqual(len(calls), 2)

    def test_one_missing_scenario_cannot_hide_in_nonempty_group(self):
        exit_code, report, _ = self.run_guard(required=["required", "missing"])
        self.assertEqual(exit_code, 1)
        self.assertIn("missing", report["error"])

    def test_ignored_required_test_cannot_hide_in_nonempty_group(self):
        exit_code, report, calls = self.run_guard(
            listed="required: test\nother: test\n", ignored="required: test\n"
        )
        self.assertEqual(exit_code, 1)
        self.assertIn("ignored", report["error"])
        self.assertEqual(len(calls), 2)

    def test_ignored_only_group_fails(self):
        exit_code, _, _ = self.run_guard(ignored="required: test\n")
        self.assertEqual(exit_code, 1)

    def test_empty_group_without_required_names_fails(self):
        exit_code, report, calls = self.run_guard(listed="", required=[])
        self.assertEqual(exit_code, 1)
        self.assertIn("no runnable tests", report["error"])
        self.assertEqual(len(calls), 2)

    def test_duplicate_required_name_fails(self):
        exit_code, report, _ = self.run_guard(listed="required: test\nrequired: test\n")
        self.assertEqual(exit_code, 1)
        self.assertIn("ambiguous", report["error"])

    def test_zero_test_harnesses_are_allowed_beside_required_tests(self):
        exit_code, report, _ = self.run_guard(output=summary(passed=0) + summary() + summary(passed=0))
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["results"]["passed"], 1)

    def test_additional_and_intentionally_ignored_tests_are_recorded(self):
        exit_code, report, _ = self.run_guard(
            listed="required: test\nextra: test\nmanual: test\n",
            ignored="manual: test\n", output=summary(passed=2, ignored=1, filtered=3),
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["ignored_tests"], ["manual"])
        self.assertEqual(report["results"]["filtered_out"], 3)

    def test_listing_failures_propagate_and_skip_execution(self):
        for field, expected_calls in (("listing_exit", 1), ("ignored_exit", 2)):
            with self.subTest(field=field):
                exit_code, report, calls = self.run_guard(**{field: 101})
                self.assertEqual(exit_code, 101)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(len(calls), expected_calls)

    def test_execution_failure_propagates(self):
        exit_code, report, _ = self.run_guard(execution_exit=101, output=summary(passed=0, failed=1))
        self.assertEqual(exit_code, 101)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["results"]["failed"], 1)

    def test_missing_or_inconsistent_execution_summaries_fail(self):
        for output in ("", summary(passed=0), summary(passed=2), summary(ignored=1),
                       summary(passed=0, failed=1), summary(measured=1)):
            with self.subTest(output=output):
                exit_code, report, _ = self.run_guard(output=output)
                self.assertEqual(exit_code, 1)
                self.assertIn("totals", report["error"])

    def test_inconsistent_ignored_inventory_fails(self):
        exit_code, report, _ = self.run_guard(ignored="unknown: test\n")
        self.assertEqual(exit_code, 1)
        self.assertIn("listing disagrees", report["error"])

    def test_launch_failure_is_recorded(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(selection, "run_command", side_effect=FileNotFoundError("missing cargo")):
                with contextlib.redirect_stderr(io.StringIO()):
                    exit_code = selection.run_selection("fixture", ["required"], ["cargo"], Path(directory))
            report = json.loads((Path(directory) / "fixture.json").read_text())
        self.assertEqual(exit_code, 1)
        self.assertIn("missing cargo", report["error"])

    def test_previous_success_is_invalidated_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "fixture.json"
            destination.write_text('{"status": "passed"}')

            def interrupted(command, stream=False):
                self.assertEqual(json.loads(destination.read_text())["status"], "running")
                raise KeyboardInterrupt()

            with patch.object(selection, "run_command", side_effect=interrupted):
                with self.assertRaises(KeyboardInterrupt):
                    selection.run_selection("fixture", ["required"], ["cargo"], Path(directory))
            self.assertEqual(json.loads(destination.read_text())["status"], "running")

    def test_streaming_command_retains_summaries_and_propagates_exit(self):
        code = f"import sys; print('test output'); print({summary()!r}, end=''); sys.exit(7)"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = selection.run_command([sys.executable, "-c", code], stream=True)
        self.assertEqual(result.returncode, 7)
        self.assertIn("test output", output.getvalue())
        self.assertEqual(result.stdout, summary())


if __name__ == "__main__":
    unittest.main()
