import os
from pathlib import Path
import unittest
from unittest.mock import patch

import release


class RepairModeTests(unittest.TestCase):
    def test_shared_escalation_does_not_create_a_coding_workspace(self):
        config = "1" * 40
        selected = {"upstream_sha": "2" * 40}
        with patch.dict(os.environ, {
                "FORK_REPAIR_MODE": "escalate", "GITHUB_RUN_ID": "42",
                "PREPARE_RESULT": "failure", "PREPARE_MODE": "build",
                "PREPARE_REASON": "patch failed", "PRIVATE_SOURCE_ACQUISITION_FAILED": "false",
                "LAND_DECISION": "", "SELECTED_JSON": ""}), \
                patch.object(release, "configuration", return_value=(release.REPOSITORY, config)), \
                patch.object(release, "select_release", return_value=selected), \
                patch.object(release, "failed_job_evidence", return_value="exact failure evidence"), \
                patch.object(release, "owner_identity") as owner, \
                patch.object(release, "api") as api, \
                patch.object(release, "run") as run, \
                patch.object(release, "escalation") as escalate:
            release.request_repair_shared(Path("unused"))
        self.assertEqual(escalate.call_args.args[:2], (config, selected))
        self.assertIn("exact failure evidence", escalate.call_args.args[2])
        self.assertIn("FORK_REPAIR_MODE=escalate", escalate.call_args.args[2])
        owner.assert_not_called()
        api.assert_not_called()
        run.assert_not_called()

    def test_legacy_explicit_escalation_preserves_the_working_release(self):
        config = "1" * 40
        selected = {"upstream_sha": "2" * 40}
        with patch.dict(os.environ, {
                "FORK_REPAIR_MODE": "escalate", "GITHUB_RUN_ID": "42",
                "PREPARE_MODE": "build", "SELECTED_JSON": "", "NONBLOCKING_FOLLOWUP": "false"}), \
                patch.object(release, "configuration", return_value=(release.REPOSITORY, config)), \
                patch.object(release, "select_release", return_value=selected), \
                patch.object(release, "failed_job_evidence", return_value="exact failure evidence"), \
                patch.object(release, "owner_identity") as owner, \
                patch.object(release, "api") as api, \
                patch.object(release, "escalation") as escalate:
            release.request_repair(Path("unused"))
        self.assertEqual(escalate.call_args.args[:2], (config, selected))
        self.assertIn("exact failure evidence", escalate.call_args.args[2])
        owner.assert_not_called()
        api.assert_not_called()

    def test_invalid_mode_refuses_before_any_native_write(self):
        with patch.dict(os.environ, {"FORK_REPAIR_MODE": "silent"}), \
                patch.object(release, "api") as api:
            with self.assertRaisesRegex(ValueError, "FORK_REPAIR_MODE"):
                release.request_repair_shared(Path("unused"))
        api.assert_not_called()

    def test_identical_escalation_is_not_posted_again(self):
        config = "1" * 40
        selected = {"upstream_sha": "2" * 40}
        with patch.object(release, "pages", return_value=[]), \
                patch.object(release, "api") as create:
            release.escalation(config, selected, "same bounded failure")
        body = create.call_args.kwargs["data"]["body"]
        issue = {"number": 7, "body": body, "user": {"login": "warelik"}}
        with patch.object(release, "pages", return_value=[issue]), \
                patch.object(release, "api") as duplicate:
            release.escalation(config, selected, "same bounded failure")
        duplicate.assert_not_called()

    def test_new_diagnostics_are_kept_but_identical_comment_is_not_repeated(self):
        config = "1" * 40
        selected = {"upstream_sha": "2" * 40}
        with patch.object(release, "pages", return_value=[]), \
                patch.object(release, "api") as create:
            release.escalation(config, selected, "new bounded failure")
        body = create.call_args.kwargs["data"]["body"]
        issue = {"number": 7, "body": "<!-- ghidra-escalation:" + "2" * 40 + " -->",
                 "user": {"login": "warelik"}}
        with patch.object(release, "pages", side_effect=[[issue], []]), \
                patch.object(release, "api") as comment:
            release.escalation(config, selected, "new bounded failure")
        self.assertEqual(comment.call_args.args[0], f"repos/{release.REPOSITORY}/issues/7/comments")
        with patch.object(release, "pages", side_effect=[
                [issue], [{"body": body, "user": {"login": "github-actions[bot]"}}]]), \
                patch.object(release, "api") as duplicate:
            release.escalation(config, selected, "new bounded failure")
        duplicate.assert_not_called()

    def test_repeated_cron_run_of_same_failure_is_not_repeated(self):
        config = "1" * 40
        selected = {"upstream_sha": "2" * 40}
        with patch.object(release, "pages", return_value=[]), \
                patch.object(release, "api") as create:
            release.escalation(
                config, selected,
                "Workflow 41; job 77: Select Official Release\n"
                "2026-10-31T17:00:00.1234567Z patch does not apply")
        body = create.call_args.kwargs["data"]["body"]
        issue = {"number": 8, "body": body, "user": {"login": "warelik"}}
        with patch.object(release, "pages", return_value=[issue]), \
                patch.object(release, "api") as duplicate:
            release.escalation(
                config, selected,
                "Workflow 42; job 88: Select Official Release\n"
                "2026-11-01T01:00:00.7654321Z patch does not apply")
        duplicate.assert_not_called()
        self.assertNotIn("pull_request", issue)

    def test_native_workflow_defaults_to_immediate_escalation(self):
        text = (release.ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("FORK_REPAIR_MODE: ${{ vars.FORK_REPAIR_MODE || 'escalate' }}", text)
