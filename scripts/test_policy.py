import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import case_runner
import policy_runner
import release


class DeclarativePolicyTests(unittest.TestCase):
    def document(self, cases):
        directory = tempfile.TemporaryDirectory()
        Path(directory.name, "cases.json").write_text(json.dumps({"schema": 1, "cases": cases}))
        self.addCleanup(directory.cleanup)
        return directory.name

    def test_honest_pass_and_fail(self):
        good = [{"id": "ok", "call": "inline_source", "args": [{"commit_id": "abc"}],
                 "expect": "abc"}]
        case_runner.evaluate(self.document(good))
        bad = [{**good[0], "expect": "wrong"}]
        with self.assertRaises(AssertionError):
            case_runner.evaluate(self.document(bad))

    def test_malformed_empty_unknown_and_unbounded_cases_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "bad.json").write_text("{")
            with self.assertRaises(case_runner.CaseError):
                case_runner.load_cases(directory)
        for case in ({"id": "bad", "call": "arbitrary", "args": [], "expect": None},
                     {"id": "bad", "call": "inline_source", "args": [], "raises": "OSError"}):
            with self.assertRaises(case_runner.CaseError):
                case_runner.load_cases(self.document([case]))

    def test_scheduler_rejects_early_exit_and_missing_completion(self):
        result = subprocess.CompletedProcess([], 0, stdout="")
        with patch.object(policy_runner.subprocess, "run", return_value=result), self.assertRaises(RuntimeError):
            policy_runner.checked(["ignored"], "required")
        failed = subprocess.CompletedProcess([], 1, stdout="required\n")
        with patch.object(policy_runner.subprocess, "run", return_value=failed), self.assertRaises(RuntimeError):
            policy_runner.checked(["ignored"], "required")

    def test_trusted_update_path_allowlist(self):
        release.allowed_trusted_paths({"scripts/release.py": "100644",
                                       ".github/workflows/release.yml": "100644",
                                       "scripts/test_release.py": "100644"})
        for path in ("AGENTS.md", "app/Dockerfile", ".repair/failure.txt",
                     "Ghidra/x", "scripts/evil.py"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                release.allowed_trusted_paths({path: "100644"})

    def test_data_only_attempt_routes_to_separate_trusted_pr(self):
        state = {"schema": 1, "config": "a" * 40, "seed": "b" * 40,
                 "upstream": "c" * 40, "upstream_release_id": 7, "cycle": "d" * 64,
                 "number": 10, "head": "b" * 40}
        calls = []
        def api(path, method="GET", data=None, **kwargs):
            calls.append((path, method, data, kwargs))
            return {"number": 11} if path.endswith("/pulls") and method == "POST" else {}
        with patch.object(release, "ensure_ref") as ref, patch.object(release, "api", side_effect=api):
            trusted = release.begin_trusted_update(release.REPOSITORY, state, "failure")
        ref.assert_called_once_with(release.REPOSITORY, "repair/trusted-aaaaaaaaaaaa-cccccccccccc",
                                    "a" * 40)
        self.assertEqual(trusted["kind"], "trusted")
        self.assertEqual(trusted["seed"], "a" * 40)
        self.assertEqual(trusted["number"], 11)
        self.assertTrue(any(path.endswith("/pulls/10") and method == "PATCH"
                            for path, method, _data, _kwargs in calls))


if __name__ == "__main__":
    unittest.main()
