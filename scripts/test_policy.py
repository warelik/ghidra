import base64
import hashlib
import json
from contextlib import redirect_stdout
from io import StringIO
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
        with redirect_stdout(StringIO()):
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

    def test_policy_orchestration_is_never_selected_from_the_candidate(self):
        import inspect
        source = inspect.getsource(release.check_policy)
        self.assertIn("source = ROOT", source)
        self.assertNotIn("TRUSTED_UPDATE", source)

    def test_data_only_attempt_routes_to_separate_trusted_pr(self):
        state = {"schema": 1, "config": "a" * 40, "seed": "b" * 40,
                 "upstream": "c" * 40, "upstream_release_id": 7, "cycle": "d" * 64,
                 "number": 10, "head": "b" * 40}
        calls = []
        def api(path, method="GET", data=None, **kwargs):
            calls.append((path, method, data, kwargs))
            return {"number": 11} if path.endswith("/pulls") and method == "POST" else {}
        with patch.object(release, "ensure_ref") as ref, \
                patch.object(release, "original_failure_evidence",
                             return_value="Original archive verification failure") as original, \
                patch.object(release, "api", side_effect=api):
            trusted = release.begin_trusted_update(
                release.REPOSITORY, state, "failure", "2026-01-01T00:00:00Z")
        original.assert_called_once_with(release.REPOSITORY, state)
        ref.assert_called_once_with(release.REPOSITORY, "repair/trusted-aaaaaaaaaaaa-cccccccccccc",
                                    "a" * 40)
        self.assertEqual(trusted["kind"], "trusted")
        self.assertEqual(trusted["seed"], "a" * 40)
        self.assertEqual(trusted["started_at"], "2026-01-01T00:00:00Z")
        self.assertEqual(trusted["number"], 11)
        self.assertTrue(any(path.endswith("/pulls/10") and method == "PATCH"
                            for path, method, _data, _kwargs in calls))
        prompt = next(data["body"] for path, method, data, _kwargs in calls
                      if path.endswith("/issues/11/comments") and method == "POST")
        self.assertIn("Original archive verification failure", prompt)
        self.assertIn("Original failure from PR #10", prompt)

    def test_original_failure_is_read_from_exact_seed(self):
        raw = b"Official archive checksum mismatch"
        record = {"type": "file", "encoding": "base64", "size": len(raw),
                  "content": base64.b64encode(raw).decode("ascii")}
        state = {"seed": "a" * 40}
        with patch.object(release, "api", return_value=record) as api:
            self.assertEqual(release.original_failure_evidence(release.REPOSITORY, state),
                             raw.decode("utf-8"))
        api.assert_called_once_with(
            f"repos/{release.REPOSITORY}/contents/.repair/failure.txt?ref={'a' * 40}")
        with patch.object(release, "api", return_value={**record, "size": len(raw) + 1}), \
                self.assertRaises(ValueError):
            release.original_failure_evidence(release.REPOSITORY, state)
        multibyte = "😀" * 24000
        encoded = multibyte.encode("utf-8")
        large = {**record, "size": len(encoded),
                 "content": base64.b64encode(encoded).decode("ascii")}
        with patch.object(release, "api", return_value=large):
            self.assertEqual(release.original_failure_evidence(release.REPOSITORY, state), multibyte)

    def test_task_start_does_not_escalate_before_completion(self):
        head = "a" * 40
        request = {"created_at": "2026-01-01T00:00:00Z",
                   "user": {"login": "warelik", "type": "User"},
                   "body": f"@codex fix\n<!-- ghidra-fix:{head}:1 -->"}
        bot = {"created_at": "2026-01-01T00:00:01Z",
               "user": {"login": release.BOT, "type": "Bot"},
               "performed_via_github_app": {"slug": release.APP},
               "body": "Task started"}
        self.assertFalse(release.completed_unchanged_task([request, bot], head))
        self.assertTrue(release.completed_unchanged_task(
            [request, {**bot, "body": "### Summary\nNo data-only fix"}], head))

    def test_pending_review_does_not_request_another_coding_task(self):
        self.assertFalse(release.needs_coding_after_review(
            False, release.WAITING, "success", "skipped", "skipped"))
        self.assertFalse(release.needs_coding_after_review(
            False, "No owner-authored exact-SHA request", "success", "skipped", "skipped"))
        self.assertTrue(release.needs_coding_after_review(
            False, "No owner-authored exact-SHA request", "failure", "skipped", "skipped"))
        self.assertFalse(release.needs_coding_after_review(
            True, "Reviewed", "success", "skipped", "skipped"))
        self.assertTrue(release.needs_coding_after_review(
            False, "Codex reported an unresolved P0/P1 finding on this commit",
            "success", "skipped", "skipped"))
        self.assertTrue(release.needs_coding_after_review(
            True, "Reviewed", "success", "failure", "skipped"))
        self.assertTrue(release.needs_coding_after_review(
            True, "Reviewed", "success", "success", "failure"))
        with self.assertRaisesRegex(ValueError, "identity changed"):
            release.needs_coding_after_review(
                False, "Review PR identity changed", "success", "skipped", "skipped")

    def test_pending_configuration_review_does_not_create_a_repair_pr(self):
        with patch.dict(release.os.environ, {"PREPARE_MODE": "waiting",
                                            "PREPARE_REASON": release.WAITING}), \
                patch.object(release, "configuration") as configuration, \
                redirect_stdout(StringIO()):
            release.request_repair(None)
        configuration.assert_not_called()

    def test_pending_review_does_not_post_a_coding_request(self):
        config, seed, head, upstream = (letter * 40 for letter in "abcd")
        state = {"config": config, "seed": seed, "head": head, "number": 6,
                 "upstream": upstream,
                 "cycle": hashlib.sha256(f"{upstream}:0".encode()).hexdigest()}
        request = {"user": {"login": "warelik", "type": "User"},
                   "created_at": "2026-01-01T00:00:00Z",
                   "body": f"<!-- ghidra-fix:{seed}:1 -->"}
        records = {f"repos/{release.REPOSITORY}/releases": [],
                   f"repos/{release.REPOSITORY}/pulls?state=all&base=downstream": [{}],
                   f"repos/{release.REPOSITORY}/issues/6/comments": [request]}
        with patch.dict(release.os.environ, {"SELECTED_JSON": "selected",
                                            "NONBLOCKING_FOLLOWUP": "", "GITHUB_RUN_ID": "7"}), \
                patch.object(release, "configuration", return_value=(release.REPOSITORY, config)), \
                patch.object(release, "selected_source", return_value={"upstream_sha": upstream}), \
                patch.object(release, "failed_job_evidence", return_value="Pending review job"), \
                patch.object(release, "pages", side_effect=lambda endpoint: records[endpoint]), \
                patch.object(release, "repair_state", return_value=state), \
                patch.object(release, "active_repair", return_value=state), \
                patch.object(release, "owner_identity"), \
                patch.object(release, "enforce_deadline"), \
                patch.object(release, "check_review", return_value=(False, release.WAITING)) as review, \
                patch.object(release, "api") as api, redirect_stdout(StringIO()):
            release.request_repair(None)
        review.assert_called_once_with(6, head, config)
        api.assert_not_called()

    def test_blocking_review_posts_the_next_coding_request(self):
        config, seed, head, upstream = (letter * 40 for letter in "abcd")
        state = {"config": config, "seed": seed, "head": head, "number": 6,
                 "upstream": upstream,
                 "cycle": hashlib.sha256(f"{upstream}:0".encode()).hexdigest()}
        request = {"user": {"login": "warelik", "type": "User"},
                   "created_at": "2026-01-01T00:00:00Z",
                   "body": f"<!-- ghidra-fix:{seed}:1 -->"}
        records = {f"repos/{release.REPOSITORY}/releases": [],
                   f"repos/{release.REPOSITORY}/pulls?state=all&base=downstream": [{}],
                   f"repos/{release.REPOSITORY}/issues/6/comments": [request]}
        for finding, prepare in (
                ("Codex reported an unresolved P0/P1 finding on this commit", "success"),
                ("No owner-authored exact-SHA request", "failure")):
            with self.subTest(finding=finding), \
                    patch.dict(release.os.environ, {"SELECTED_JSON": "selected",
                                                 "NONBLOCKING_FOLLOWUP": "", "GITHUB_RUN_ID": "7",
                                                 "PREPARE_RESULT": prepare}), \
                    patch.object(release, "configuration", return_value=(release.REPOSITORY, config)), \
                    patch.object(release, "selected_source", return_value={"upstream_sha": upstream}), \
                    patch.object(release, "failed_job_evidence", return_value="Blocking review finding"), \
                    patch.object(release, "pages", side_effect=lambda endpoint: records[endpoint]), \
                    patch.object(release, "repair_state", return_value=state), \
                    patch.object(release, "active_repair", return_value=state), \
                    patch.object(release, "owner_identity"), \
                    patch.object(release, "enforce_deadline"), \
                    patch.object(release, "check_review", return_value=(False, finding)), \
                    patch.object(release, "api") as api, redirect_stdout(StringIO()):
                release.request_repair(None)
            api.assert_called_once()
            self.assertIn(f"<!-- ghidra-fix:{head}:2 -->", api.call_args.kwargs["data"]["body"])

    def test_trusted_state_requires_original_repair_start(self):
        state = {"schema": 1, "kind": "trusted", "config": "a" * 40,
                 "seed": "a" * 40, "upstream": "b" * 40,
                 "upstream_release_id": 7, "cycle": "c" * 64}
        pull = {"number": 10, "user": {"login": "warelik"},
                "head": {"sha": "d" * 40, "ref": "repair/trusted-test",
                         "repo": {"full_name": release.REPOSITORY}},
                "body": "<!-- ghidra-repair:v1 " + json.dumps(state) + " -->"}
        with self.assertRaises(ValueError):
            release.repair_state(pull)
        state["started_at"] = "2026-01-01T00:00:00Z"
        pull["body"] = "<!-- ghidra-repair:v1 " + json.dumps(state) + " -->"
        self.assertEqual(release.repair_state(pull)["started_at"], state["started_at"])


if __name__ == "__main__":
    unittest.main()
