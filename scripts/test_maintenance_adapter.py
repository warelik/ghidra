"""Focused contracts for the native shared-maintenance adapter boundary."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import baseline_runner
import policy_runner
import release


SHA = "1" * 40
METADATA = "d" * 64


def candidate():
    return {
        "schema": 1,
        "repository": release.REPOSITORY,
        "upstream_sha": SHA,
        "application_sha": SHA,
        "configuration_sha": "2" * 40,
        "patchset_sha256": hashlib.sha256(b"").hexdigest(),
        "recipe_sha256": "3" * 64,
        "platform": "linux/amd64",
    }


class FakeLifecycle:
    @staticmethod
    def candidate_identity(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def evaluate_review(target, *_evidence):
        return target


class AcceptedBaselineTests(unittest.TestCase):
    def publication(self):
        release_record = {
            "id": 71,
            "target_commitish": candidate()["configuration_sha"],
            "published_at": "2026-10-19T10:00:00Z",
        }
        return {"release": release_record, "selected": {"upstream_sha": SHA},
                "metadata_sha256": METADATA}

    def native_variable(self, *, release_id=71, metadata_sha256=METADATA):
        value = {
            "schema": 1,
            "repository": release.REPOSITORY,
            "candidate": candidate(),
            "publication": {
                "kind": "github-release",
                "id": release_id,
                "published_at": "2026-10-19T10:00:00Z",
                "metadata_sha256": metadata_sha256,
            },
        }
        return {
            "name": "FORK_ACCEPTED_BASELINE",
            "value": json.dumps(value, sort_keys=True, separators=(",", ":")),
            "created_at": "2026-10-19T09:00:00Z",
            "updated_at": "2026-10-19T10:01:00Z",
        }

    def test_native_checkpoint_must_match_verified_release_and_metadata(self):
        with patch.object(release, "api", return_value=self.native_variable()), \
                patch.object(release, "maintenance_candidate", return_value=candidate()), \
                patch.object(release, "lifecycle", return_value=FakeLifecycle):
            accepted = release.read_accepted_baseline(self.publication())
        self.assertEqual(accepted["candidate"], candidate())
        self.assertEqual(accepted["publication"]["id"], 71)
        self.assertEqual(accepted["proof"]["endpoint"], release.ACCEPTED_BASELINE_ENDPOINT)

    def test_only_exact_native_owner_dispositions_are_consumed(self):
        source = candidate()
        record = [{"finding_id": "inline:91:601", "candidate_id": FakeLifecycle.candidate_identity(source),
                   "source_sha": source["configuration_sha"], "status": "fixed",
                   "evidence": ("code location `scripts/release.py` at `@@ -1 +1 @@`; "
                               "code diff SHA-256 `" + "d" * 64 + "`; "
                               "regression path `scripts/test_release.py`; regression diff SHA-256 `"
                               + "e" * 64 + "`;")}]
        marker = release.disposition_marker(source, record)
        native_user = {"login": "warelik", "type": "User", "id": 17,
                       "node_id": "MDQ6VXNlcjE3", "site_admin": False}
        comment = {"id": 701, "user": native_user,
                   "created_at": "2026-10-19T10:00:00Z", "updated_at": "2026-10-19T10:00:00Z",
                   "body": marker}
        with patch.object(release, "lifecycle", return_value=FakeLifecycle):
            result = release.review_dispositions_from_comments([comment], source)
        self.assertEqual(result[0]["finding_id"], "inline:91:601")
        self.assertEqual(result[0]["native_comment"], {
            "id": comment["id"], "created_at": comment["created_at"],
            "updated_at": comment["updated_at"], "user": native_user,
        })
        self.assertEqual(release._merge_disposition_records(result, [result]), result)
        for invalid in ({**comment, "user": {"login": "not-owner", "type": "User"}},
                        {**comment, "updated_at": "2026-10-19T10:01:00Z"}):
            with patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                    self.subTest(invalid=invalid), self.assertRaises(ValueError):
                release.review_dispositions_from_comments([invalid], source)

    def test_disposition_without_regression_evidence_is_rejected(self):
        source = candidate()
        record = [{"finding_id": "inline:91:601", "candidate_id": FakeLifecycle.candidate_identity(source),
                   "source_sha": source["configuration_sha"], "status": "fixed",
                   "evidence": "code location `scripts/release.py` at `@@ -1 +1 @@`; "
                               "code diff SHA-256 `" + "d" * 64 + "`"}]
        comment = {"id": 702, "user": {"login": "warelik", "type": "User"},
                   "created_at": "2026-10-19T10:00:00Z", "updated_at": "2026-10-19T10:00:00Z",
                   "body": release.disposition_marker(source, record)}
        with patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                self.assertRaisesRegex(ValueError, "code and regression evidence"):
            release.review_dispositions_from_comments([comment], source)

    def test_native_checkpoint_cannot_name_another_release_or_provenance(self):
        for variable in (self.native_variable(release_id=72),
                         self.native_variable(metadata_sha256="e" * 64)):
            with self.subTest(variable=variable), \
                    patch.object(release, "api", return_value=variable), \
                    patch.object(release, "maintenance_candidate", return_value=candidate()), \
                    patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                    self.assertRaises(ValueError):
                release.read_accepted_baseline(self.publication())

    def test_interrupted_publication_recovers_only_an_unchanged_prior_checkpoint(self):
        previous = self.publication()
        latest = {
            "release": {"id": 72, "target_commitish": "4" * 40,
                        "published_at": "2026-10-19T11:00:00Z"},
            "selected": {"upstream_sha": SHA},
            "published_at": release.parse_github_time("2026-10-19T11:00:00Z", "fixture"),
            "metadata_sha256": "e" * 64,
        }
        prior = {
            **previous,
            "published_at": release.parse_github_time(previous["release"]["published_at"], "fixture"),
        }
        old_variable = self.native_variable()
        new_record = {"schema": 1, "repository": release.REPOSITORY,
                      "candidate": {**candidate(), "configuration_sha": "4" * 40},
                      "publication": {"kind": "github-release", "id": 72,
                                      "published_at": latest["release"]["published_at"],
                                      "metadata_sha256": "e" * 64}}
        accepted = {"proof": {"endpoint": release.ACCEPTED_BASELINE_ENDPOINT,
                              "variable": {**old_variable, "value": json.dumps(new_record)}},
                    "candidate": new_record["candidate"],
                    "publication": new_record["publication"]}
        with patch.object(release, "api", return_value=old_variable), \
                patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                patch.object(release, "maintenance_candidate", side_effect=lambda config, _selected:
                             {**candidate(), "configuration_sha": config}), \
                patch.object(release, "record_accepted_baseline_after_publication",
                             return_value=accepted) as update:
            result = release.reconcile_accepted_baseline([prior, latest], latest)
        update.assert_called_once_with(latest["release"], latest["selected"], "4" * 40,
                                      expected_variable=old_variable)
        self.assertEqual(result, accepted)

    def test_interrupted_publication_recovery_refuses_checkpoint_updated_after_publish(self):
        previous = self.publication()
        latest = {
            "release": {"id": 72, "target_commitish": "4" * 40,
                        "published_at": "2026-10-19T11:00:00Z"},
            "selected": {"upstream_sha": SHA},
            "published_at": release.parse_github_time("2026-10-19T11:00:00Z", "fixture"),
            "metadata_sha256": "e" * 64,
        }
        prior = {
            **previous,
            "published_at": release.parse_github_time(previous["release"]["published_at"], "fixture"),
        }
        changed = self.native_variable()
        changed["updated_at"] = "2026-10-19T11:01:00Z"
        with patch.object(release, "api", return_value=changed), \
                patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                patch.object(release, "maintenance_candidate", side_effect=lambda config, _selected:
                             {**candidate(), "configuration_sha": config}), \
                patch.object(release, "record_accepted_baseline_after_publication") as update, \
                self.assertRaisesRegex(ValueError, "not caused by an interrupted newer publication"):
            release.reconcile_accepted_baseline([prior, latest], latest)
        update.assert_not_called()

    def test_recovery_requires_the_exact_recipe_of_the_verified_prior_publication(self):
        publication = self.publication()
        record = json.loads(self.native_variable()["value"])
        with patch.object(release, "maintenance_candidate", return_value=candidate()) as derive:
            self.assertTrue(release._baseline_record_matches_publication(record, publication))
            changed = {**record, "candidate": {**record["candidate"], "recipe_sha256":
                "0" * 64 if record["candidate"]["recipe_sha256"] != "0" * 64 else "f" * 64}}
            self.assertFalse(release._baseline_record_matches_publication(changed, publication))
        derive.assert_called_with(publication["release"]["target_commitish"], publication["selected"])

    def test_checkpoint_recovery_rechecks_native_variable_before_patch(self):
        publication = self.publication()
        expected_variable = self.native_variable()
        changed_variable = {**expected_variable, "updated_at": "2026-10-19T10:02:00Z"}
        with patch.object(release, "verify_remote_release", return_value=METADATA), \
                patch.object(release, "latest_verified_publication", return_value=publication), \
                patch.object(release, "api", return_value=changed_variable) as native, \
                patch.object(release, "maintenance_candidate", return_value=candidate()), \
                self.assertRaisesRegex(ValueError, "changed before the guarded recovery update"):
            release.record_accepted_baseline_after_publication(
                publication["release"], publication["selected"], candidate()["configuration_sha"],
                expected_variable=expected_variable)
        native.assert_called_once_with(release.ACCEPTED_BASELINE_ENDPOINT, owner=True)

    def test_checkpoint_advance_uses_owner_patch_and_verifies_native_readback(self):
        publication = self.publication()
        stale_variable = self.native_variable(release_id=70)
        record = {"schema": 1, "repository": release.REPOSITORY,
                  "candidate": candidate(),
                  "publication": {"kind": "github-release", "id": 71,
                                  "published_at": publication["release"]["published_at"],
                                  "metadata_sha256": METADATA}}
        value = json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with patch.object(release, "verify_remote_release", return_value=METADATA), \
                patch.object(release, "latest_verified_publication", return_value=publication), \
                patch.object(release, "maintenance_candidate", return_value=candidate()), \
                patch.object(release, "api", side_effect=[stale_variable, None]) as native, \
                patch.object(release, "read_accepted_baseline", return_value={"verified": True}) as readback:
            result = release.record_accepted_baseline_after_publication(
                publication["release"], publication["selected"], candidate()["configuration_sha"])

        self.assertEqual(result, {"verified": True})
        self.assertEqual(native.call_args_list[0].args,
                         (release.ACCEPTED_BASELINE_ENDPOINT,))
        self.assertEqual(native.call_args_list[0].kwargs, {"owner": True})
        self.assertEqual(native.call_args_list[1].args,
                         (release.ACCEPTED_BASELINE_ENDPOINT,))
        self.assertEqual(native.call_args_list[1].kwargs, {
            "method": "PATCH", "owner": True,
            "data": {"name": "FORK_ACCEPTED_BASELINE", "value": value},
        })
        readback.assert_called_once_with(publication)

    def test_duplicate_checkpoint_fields_fail_closed(self):
        variable = self.native_variable()
        variable["value"] = variable["value"].replace('"schema":1', '"schema":1,"schema":1', 1)
        with patch.object(release, "api", return_value=variable), \
                patch.object(release, "maintenance_candidate", return_value=candidate()), \
                patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                self.assertRaisesRegex(ValueError, "duplicate field"):
            release.read_accepted_baseline(self.publication())

    def test_final_history_uses_the_native_accepted_candidate(self):
        accepted = {
            "candidate": candidate(),
            "publication": {
                "kind": "github-release", "id": 71,
                "published_at": "2026-10-19T10:00:00Z", "metadata_sha256": METADATA,
            },
        }
        with patch.object(release, "pages", return_value=[]), \
                patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                patch.dict(os.environ, {"GITHUB_RUN_ID": ""}):
            history = release.final_attempt_history(accepted)
        self.assertEqual(history["baseline"]["candidate"], candidate())
        self.assertEqual(history["baseline"]["publication"], accepted["publication"])

    def test_final_history_requires_the_native_bare_workflow_path(self):
        accepted = {
            "candidate": candidate(),
            "publication": {
                "kind": "github-release", "id": 71,
                "published_at": "2026-10-19T10:00:00Z", "metadata_sha256": METADATA,
            },
        }
        run = {"id": 800, "path": release.WORKFLOW_PATH + "@refs/heads/downstream",
               "updated_at": "2026-10-19T10:10:00Z", "run_attempt": 1}

        def pages(path, *, list_field=None):
            if "/workflows/release.yml/runs" in path:
                return [run]
            return []

        with patch.object(release, "pages", side_effect=pages), \
                patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                patch.dict(os.environ, {"GITHUB_RUN_ID": "", "GITHUB_RUN_ATTEMPT": ""}):
            history = release.final_attempt_history(accepted)

        self.assertFalse(history["complete"])
        self.assertEqual(history["attempts"], [])

    def test_policy_receipt_rejects_a_suffixed_native_workflow_path(self):
        source = candidate()
        contexts = [
            {"scope": "full", "pr": 91, "request_id": 501},
            {"scope": "delta", "pr": 92, "request_id": 502},
        ]
        marker = {
            "schema": 1,
            "candidate_id": FakeLifecycle.candidate_identity(source),
            "candidate": source,
            "run_id": 800,
            "workflow_sha": "6" * 40,
            "review_contexts": release.paired_context_ids(contexts),
        }
        comment = {"user": {"login": "warelik", "type": "User"},
                   "body": "<!-- fork-policy-attempt:v1 "
                           + json.dumps(marker, sort_keys=True, separators=(",", ":")) + " -->"}
        native_run = {"path": release.WORKFLOW_PATH + "@refs/heads/downstream",
                      "head_sha": marker["workflow_sha"], "status": "completed"}
        with patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                patch.object(release, "pages", return_value=[comment]), \
                patch.object(release, "api", return_value=native_run), \
                self.assertRaisesRegex(ValueError, "exact native workflow source"):
            release.policy_migration_receipt(source, contexts)

    def test_native_workflow_identity_never_strips_a_path_suffix(self):
        source = Path(release.__file__).read_text(encoding="utf-8")
        self.assertNotIn('split("@", 1)[0]', source)
        self.assertIn('workflow_run.get("path") != WORKFLOW_PATH', source)
        self.assertIn('run_record.get("path") != WORKFLOW_PATH', source)

    def test_delta_review_target_carries_the_native_variable_object(self):
        source = candidate()
        base = "4" * 40
        proof = {"endpoint": release.ACCEPTED_BASELINE_ENDPOINT,
                 "variable": self.native_variable()}
        context = {
            "scope": "delta", "pr": 91, "request_id": 501,
            "review_sha": source["configuration_sha"], "base_sha": base,
            "head_ref": f"review/changes-{source['configuration_sha']}",
            "base_ref": f"review-base/{base}", "state": "open",
            "accepted_baseline": proof,
        }
        request = {
            "id": 501,
            "user": {"login": "warelik", "type": "User"},
            "created_at": "2026-10-19T10:02:00Z",
            "updated_at": "2026-10-19T10:02:00Z",
            "body": release.review_marker(source, "delta", source["configuration_sha"], base),
        }
        older_request = {**request, "id": 500,
                         "created_at": "2026-10-19T10:01:00Z",
                         "updated_at": "2026-10-19T10:01:00Z"}
        pull = {
            "number": 91, "state": "open",
            "head": {"sha": source["configuration_sha"], "ref": context["head_ref"],
                     "repo": {"full_name": release.REPOSITORY}},
            "base": {"sha": base, "ref": context["base_ref"],
                     "repo": {"full_name": release.REPOSITORY}},
        }

        def pages(path, **_kwargs):
            return [older_request, request] if path.endswith("/issues/91/comments") else []

        with patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                patch.object(release, "api", side_effect=[
                    pull, {"sha": base, "tree": {"sha": "5" * 40}},
                    {"sha": source["application_sha"]},
                    {"sha": source["configuration_sha"]},
                ]), \
                patch.object(release, "pages", side_effect=pages), \
                patch.object(release, "resolve_native_review_sources", return_value={}):
            target = release.review_context_result(source, context)
        self.assertEqual(target["accepted_baseline"], proof)
        self.assertEqual(target["request"]["id"], 501)
        self.assertEqual(context["request_id"], 501)
        self.assertEqual(target["source_git_data"], {
            "application": {"sha": source["application_sha"]},
            "configuration": {"sha": source["configuration_sha"]},
            "review": {"sha": source["configuration_sha"]},
        })

    def test_latest_owner_review_request_wins_and_must_be_immutable(self):
        source = candidate()
        with patch.object(release, "lifecycle", return_value=FakeLifecycle):
            marker = release.review_marker(source, "delta", source["configuration_sha"], SHA)
        earlier = {"id": 900, "user": {"login": "warelik", "type": "User"},
                   "body": marker, "created_at": "2026-10-19T10:00:00Z",
                   "updated_at": "2026-10-19T10:00:00Z"}
        later = {**earlier, "id": 701, "created_at": "2026-10-19T10:01:00Z",
                  "updated_at": "2026-10-19T10:01:00Z"}
        latest = {**later, "id": 702}
        bot = {**latest, "id": 703, "user": {"login": release.BOT, "type": "Bot"},
               "created_at": "2026-10-19T10:02:00Z",
               "updated_at": "2026-10-19T10:02:00Z"}
        self.assertIs(release.latest_owner_review_request(
            [earlier, later, latest, bot], marker), latest)
        edited = {**latest, "updated_at": "2026-10-19T10:03:00Z"}
        with self.assertRaisesRegex(ValueError, "Latest native owner review request was edited"):
            release.latest_owner_review_request([earlier, edited], marker)

    def test_review_context_result_rejects_newest_request_without_mutating_frozen_id(self):
        source = candidate()
        base = "4" * 40
        context = {
            "scope": "delta", "pr": 91, "request_id": 500,
            "review_sha": source["configuration_sha"], "base_sha": base,
            "head_ref": f"review/changes-{source['configuration_sha']}",
            "base_ref": f"review-base/{base}",
        }
        with patch.object(release, "lifecycle", return_value=FakeLifecycle):
            marker = release.review_marker(
                source, "delta", source["configuration_sha"], base)
        latest = {
            "id": 501, "user": {"login": "warelik", "type": "User"},
            "created_at": "2026-10-19T10:02:00Z",
            "updated_at": "2026-10-19T10:02:00Z", "body": marker,
        }
        pull = {"number": 91, "state": "open"}
        with patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                patch.object(release, "api", return_value=pull), \
                patch.object(release, "pages", return_value=[latest]):
            with self.assertRaisesRegex(ValueError, "differs from the latest exact owner request"):
                release.review_context_result(source, context)
        self.assertEqual(context["request_id"], 500)

    def test_full_and_delta_review_refs_have_distinct_names(self):
        source = candidate()
        with patch.object(release, "lifecycle", return_value=FakeLifecycle):
            self.assertEqual(release.review_scope_branch(
                source, "full", source["configuration_sha"]),
                f"review/{source['configuration_sha']}")
            self.assertEqual(release.review_scope_branch(
                source, "delta", source["configuration_sha"]),
                f"review/changes-{source['configuration_sha']}")

    def test_final_history_binds_jobs_to_each_native_run_attempt(self):
        value = candidate()
        candidate_id = FakeLifecycle.candidate_identity(value)
        reservation = {
            "id": 702, "user": {"login": "warelik", "type": "User"},
            "created_at": "2026-10-19T10:05:00Z", "updated_at": "2026-10-19T10:05:00Z",
            "body": (
                "<!-- fork-candidate:v1 "
                + json.dumps(value, sort_keys=True, separators=(",", ":"))
                + " -->\n<!-- fork-final:v1 "
                + json.dumps({"schema": 1, "candidate_id": candidate_id,
                              "run_id": 800, "run_attempt": 1,
                              "workflow_sha": "6" * 40}, sort_keys=True, separators=(",", ":"))
                + " -->"
            ),
        }
        workflow_run = {
            "id": 800, "path": ".github/workflows/release.yml",
            "updated_at": "2026-10-19T10:10:00Z", "run_attempt": 1,
        }
        native_attempt = {
            "id": 800, "run_attempt": 1, "path": ".github/workflows/release.yml",
            "node_id": "WFR_native_attempt_800",
            "created_at": "2026-10-19T10:04:00Z", "updated_at": "2026-10-19T10:10:00Z",
            "status": "completed", "conclusion": "failure", "head_sha": "5" * 40,
            "event": "pull_request_target", "head_branch": "repair/verified",
        }
        source_proof = {"run_file": {"sha": "7" * 40},
                        "reserved_file": {"sha": "7" * 40},
                        "workflow_run": {"data": {"node": {
                            "id": "WFR_native_attempt_800"}}}}
        job = {
            "id": 801, "name": release.FINAL_HEAVY_JOB, "status": "completed",
            "conclusion": "failure", "started_at": "2026-10-19T10:06:00Z",
            "completed_at": "2026-10-19T10:10:00Z", "steps": [],
        }
        accepted = {
            "candidate": value,
            "publication": {"kind": "github-release", "id": 71,
                            "published_at": "2026-10-19T10:00:00Z",
                            "metadata_sha256": METADATA},
        }

        def pages(path, *, list_field=None):
            if "/issues/comments?" in path:
                return [reservation]
            if path.endswith("/workflows/release.yml/runs"):
                return [workflow_run]
            if path.endswith("/attempts/1/jobs"):
                return [job]
            return []

        with patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                patch.object(release, "pages", side_effect=pages), \
                patch.object(release, "api", return_value=native_attempt), \
                patch.object(release, "native_workflow_source_proof",
                             return_value=source_proof) as source_proof_reader, \
                patch.dict(os.environ, {"GITHUB_RUN_ID": "", "GITHUB_RUN_ATTEMPT": ""}):
            history = release.final_attempt_history(accepted)
        attempt = history["attempts"][0]
        self.assertEqual(attempt["run"]["run_attempt"], 1)
        self.assertEqual(attempt["run"], native_attempt)
        self.assertEqual(attempt["workflow_source"], source_proof)
        self.assertEqual(source_proof_reader.call_args.args,
                         (release.REPOSITORY, native_attempt, "6" * 40, release.WORKFLOW_PATH))
        self.assertEqual(attempt["jobs_context"], {
            "endpoint": "repos/warelik/ghidra/actions/runs/800/attempts/1/jobs",
            "run_id": 800, "run_attempt": 1,
        })

        malformed = {**job, "steps": [{"name": "Build", "conclusion": "failure"}]}
        malformed.pop("started_at")
        for reserved in (False, True):
            def broken_pages(path, *, list_field=None):
                if "/issues/comments?" in path:
                    return [reservation] if reserved else []
                if path.endswith("/workflows/release.yml/runs"):
                    return [workflow_run]
                if path.endswith("/attempts/1/jobs"):
                    return [malformed]
                return []

            with self.subTest(reserved=reserved), \
                    patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                    patch.object(release, "pages", side_effect=broken_pages), \
                    patch.object(release, "api", return_value=native_attempt), \
                    patch.object(release, "native_workflow_source_proof",
                                 return_value=source_proof), \
                    patch.dict(os.environ, {"GITHUB_RUN_ID": "", "GITHUB_RUN_ATTEMPT": ""}), \
                    self.assertRaisesRegex(ValueError, "executed steps without a start timestamp"):
                release.final_attempt_history(accepted)

    def test_current_native_workflow_source_uses_exact_graphql_file_proof_on_mismatch(self):
        run_record = {
            "id": 801, "run_attempt": 2, "path": release.WORKFLOW_PATH,
            "head_sha": "a" * 40, "node_id": "WFR_kgDOExample",
            "event": "pull_request_target", "head_branch": "repair/verified",
        }
        run_file = {"type": "file", "sha": "c" * 40}
        reserved_file = {"type": "file", "sha": "c" * 40}
        graphql = {"data": {"node": {"id": run_record["node_id"]}}}
        routes = {
            f"repos/{release.REPOSITORY}/actions/runs/801/attempts/2": run_record,
            f"repos/{release.REPOSITORY}/contents/{release.WORKFLOW_PATH}?ref={'a' * 40}": run_file,
            f"repos/{release.REPOSITORY}/contents/{release.WORKFLOW_PATH}?ref={'b' * 40}": reserved_file,
            "graphql": graphql,
        }
        core = Mock()
        core.validate_workflow_source.return_value = True
        calls = []

        def api(route, **kwargs):
            calls.append((route, kwargs))
            return routes[route]

        with patch.dict(os.environ, {"GITHUB_RUN_ID": "801", "GITHUB_RUN_ATTEMPT": "2",
                                     "GITHUB_SHA": "b" * 40}), \
                patch.object(release, "api", side_effect=api), \
                patch.object(release, "lifecycle", return_value=core):
            checked = release.validate_current_workflow_source()

        self.assertEqual(checked, run_record)
        proof = core.validate_workflow_source.call_args.args[-1]
        self.assertEqual(proof, {"run_file": run_file, "reserved_file": reserved_file,
                                 "workflow_run": graphql})
        self.assertEqual(calls[-1], ("graphql", {
            "method": "POST", "data": {
                "query": release._WORKFLOW_RUN_FILE_QUERY,
                "variables": {"id": run_record["node_id"]},
            }}))

    def test_dismissed_native_review_passes_the_raw_issue_events_to_shared_core(self):
        value = candidate()
        review_sha, base_sha = value["configuration_sha"], "5" * 40
        request = {"id": 91, "user": {"login": "warelik", "type": "User"},
                   "body": "exact request", "created_at": "2026-10-19T10:00:00Z",
                   "updated_at": "2026-10-19T10:00:00Z"}
        review = {"id": 501, "state": "DISMISSED", "commit_id": review_sha,
                  "submitted_at": "2026-10-19T10:01:00Z"}
        dismissal = {"id": 601, "event": "review_dismissed",
                     "created_at": "2026-10-19T10:03:00Z",
                     "dismissed_review": {"review_id": "501"},
                     "url": f"https://api.github.com/repos/{release.REPOSITORY}/issues/events/601"}
        context = {"scope": "delta", "review_sha": review_sha, "base_sha": base_sha,
                   "head_ref": f"review/changes-{review_sha}",
                   "base_ref": "review-base/base", "pr": 92, "request_id": request["id"]}
        base_commit = {"sha": base_sha}
        core = Mock()
        core.candidate_identity.return_value = "c" * 64
        core.evaluate_review.return_value = {"state": "complete"}
        pages_by_route = {
            f"repos/{release.REPOSITORY}/issues/92/comments": [request],
            f"repos/{release.REPOSITORY}/pulls/92/reviews": [review],
            f"repos/{release.REPOSITORY}/pulls/92/comments": [],
            f"repos/{release.REPOSITORY}/issues/92/events": [dismissal],
        }

        with patch.object(release, "lifecycle", return_value=core), \
                patch.object(release, "api", side_effect=lambda route: (
                    {"number": 92} if route.endswith("/pulls/92") else base_commit)), \
                patch.object(release, "pages", side_effect=lambda route: pages_by_route[route]) as page, \
                patch.object(release, "latest_owner_review_request", return_value=request), \
                patch.object(release, "native_source_git_data", return_value={"application": {}}), \
                patch.object(release, "resolve_native_review_sources", return_value={}):
            result = release.review_context_result(value, context)

        self.assertEqual(result, {"state": "complete"})
        target = core.evaluate_review.call_args.args[0]
        self.assertEqual(target["review_dismissals"], [dismissal])
        self.assertIn(f"repos/{release.REPOSITORY}/issues/92/events", [
            call.args[0] for call in page.call_args_list])

    def test_untrusted_partial_final_markers_cannot_invalidate_native_history(self):
        owner_reservation = {
            "id": 701, "user": {"login": "warelik", "type": "User"},
            "body": (
                "<!-- fork-candidate:v1 {} -->\n"
                "<!-- fork-final:v1 "
                + json.dumps({"candidate_id": "a" * 64, "run_id": 81,
                              "run_attempt": 2, "workflow_sha": "b" * 40})
                + " -->"
            ),
        }
        hostile_comments = [
            {"id": 702, "user": {"login": "public-user", "type": "User"},
             "body": "<!-- fork-final:v1 {} -->"},
            {"id": 703, "user": {"login": "warelik", "type": "Bot"},
             "body": "<!-- fork-final:v1 {} -->"},
            owner_reservation,
        ]
        reservations, grants, consumed, complete = release.reservation_records(hostile_comments)
        self.assertTrue(complete)
        self.assertEqual(set(reservations), {(81, 2)})
        self.assertEqual(grants, [])
        self.assertEqual(consumed, [])

        malformed_owner = {"id": 704, "user": {"login": "warelik", "type": "User"},
                           "body": "<!-- fork-final:v1 {} -->"}
        self.assertFalse(release.reservation_records([malformed_owner])[3])


class OfficialPackagingProofTests(unittest.TestCase):
    def selection(self):
        return {
            "version": "12.1.4",
            "upstream_tag": "Ghidra_12.1.4_build",
            "upstream_sha": SHA,
            "upstream_release_id": 393162725,
            "asset": {
                "name": "ghidra_12.1.4_PUBLIC_20260921.zip",
                "sha256": "a" * 64,
                "size": 569649598,
                "url": "https://github.com/NationalSecurityAgency/ghidra/releases/download/"
                       "Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip",
            },
        }

    def native_source(self, selection):
        return (
            {"full_name": release.REPOSITORY, "fork": True,
             "parent": {"full_name": release.UPSTREAM},
             "source": {"full_name": release.UPSTREAM}},
            {"id": selection["upstream_release_id"], "tag_name": selection["upstream_tag"],
             "draft": False, "prerelease": False,
             "assets": [{"name": selection["asset"]["name"],
                         "digest": "sha256:" + selection["asset"]["sha256"],
                         "size": selection["asset"]["size"],
                         "browser_download_url": selection["asset"]["url"]}]},
            {"ref": "refs/tags/" + selection["upstream_tag"],
             "object": {"sha": SHA, "type": "commit"}},
        )

    def test_full_review_target_includes_exact_native_official_source(self):
        source = candidate()
        base = release.BASELINE
        selection = self.selection()
        proof = {"fork": {}, "release": {}, "tag_ref": {}, "tag_objects": []}
        context = {
            "scope": "full", "pr": 91, "request_id": 501,
            "review_sha": source["configuration_sha"], "base_sha": base,
            "head_ref": f"review/{source['configuration_sha']}",
            "base_ref": f"review-base/{base}", "state": "open",
        }
        request = {
            "id": 501,
            "user": {"login": "warelik", "type": "User"},
            "created_at": "2026-10-19T10:02:00Z",
            "updated_at": "2026-10-19T10:02:00Z",
            "body": release.review_marker(source, "full", source["configuration_sha"], base),
        }
        pull = {
            "number": 91, "state": "open",
            "head": {"sha": source["configuration_sha"], "ref": context["head_ref"],
                     "repo": {"full_name": release.REPOSITORY}},
            "base": {"sha": base, "ref": context["base_ref"],
                     "repo": {"full_name": release.REPOSITORY}},
        }

        def pages(path, **_kwargs):
            return [request] if path.endswith("/issues/91/comments") else []

        with patch.object(release, "lifecycle", return_value=FakeLifecycle), \
                patch.object(release, "api", side_effect=[
                    pull, {"sha": base, "tree": {"sha": release.EMPTY_TREE}},
                    {"sha": source["application_sha"]},
                    {"sha": source["configuration_sha"]},
                ]), \
                patch.object(release, "pages", side_effect=pages), \
                patch.object(release, "selected_source", return_value=selection), \
                patch.object(release, "official_source_proof", return_value=proof), \
                patch.object(release, "resolve_native_review_sources", return_value={}):
            target = release.review_context_result(source, context)

        self.assertEqual(target["official_release_id"], selection["upstream_release_id"])
        self.assertEqual(context["official_release_id"], selection["upstream_release_id"])
        self.assertIs(target["official_source"], proof)
        self.assertEqual(target["source_git_data"]["application"]["sha"], source["application_sha"])
        self.assertEqual(target["source_git_data"]["configuration"]["sha"],
                         source["configuration_sha"])
        self.assertIs(target["source_git_data"]["review"],
                      target["source_git_data"]["configuration"])

    def test_native_source_proof_binds_release_ref_and_fork(self):
        selection = self.selection()
        native = self.native_source(selection)
        with patch.object(release, "api", side_effect=native):
            proof = release.official_source_proof(selection)
        self.assertEqual(proof, {"fork": native[0], "release": native[1],
                                 "tag_ref": native[2], "tag_objects": []})

        annotated_ref = {"ref": native[2]["ref"],
                         "object": {"sha": "4" * 40, "type": "tag"}}
        annotated_tag = {"sha": "4" * 40, "tag": selection["upstream_tag"],
                         "object": {"sha": SHA, "type": "commit"}}
        with patch.object(release, "api", side_effect=(native[0], native[1],
                                                         annotated_ref, annotated_tag)):
            annotated = release.official_source_proof(selection)
        self.assertEqual(annotated["tag_objects"], [annotated_tag])

        mismatched_ref = {**native[2], "object": {"sha": "4" * 40, "type": "commit"}}
        with patch.object(release, "api", side_effect=(native[0], native[1], mismatched_ref)), \
                self.assertRaisesRegex(ValueError, "frozen upstream commit"):
            release.official_source_proof(selection)


class PolicyCurrentRecoveryTests(unittest.TestCase):
    def pair_environment(self):
        source = candidate()
        baseline = {"proof": {"endpoint": release.ACCEPTED_BASELINE_ENDPOINT,
                              "variable": {}},
                    "publication": {"published_at": "2026-10-19T10:00:00Z"}}
        contexts = [
            {"scope": "full", "pr": 91, "request_id": 501,
             "review_sha": source["configuration_sha"], "base_sha": release.BASELINE,
             "head_ref": f"review/{source['configuration_sha']}",
             "base_ref": f"review-base/{release.BASELINE}",
             "accepted_baseline": baseline["proof"]},
            {"scope": "delta", "pr": 92, "request_id": 502,
             "review_sha": source["configuration_sha"], "base_sha": SHA,
             "head_ref": f"review/changes-{source['configuration_sha']}",
             "base_ref": f"review-base/{SHA}",
             "accepted_baseline": baseline["proof"]},
        ]
        pair = {"candidate": source, "candidate_id": FakeLifecycle.candidate_identity(source),
                "contexts": contexts}
        env = {"PREPARE_MODE": "policy-current",
               "CONFIGURATION_SHA": source["configuration_sha"],
               "FINAL_CANDIDATE": json.dumps(source, sort_keys=True, separators=(",", ":")),
               "REVIEW_PAIR": json.dumps(pair, sort_keys=True, separators=(",", ":")),
               "SELECTED_JSON": "selected"}
        return source, contexts, baseline, env

    def run_finalizer(self, *, bundle, receipt):
        source, contexts, baseline, env = self.pair_environment()
        core = Mock()
        core.candidate_identity.side_effect = FakeLifecycle.candidate_identity
        core.authorize_final.return_value = {"decision": "policy-only", "reason": "same product"}
        with patch.dict(os.environ, env, clear=True), \
                patch.object(release, "configuration", return_value=(release.REPOSITORY,
                                                                       source["configuration_sha"])), \
                patch.object(release, "selected_source", return_value={"upstream_sha": SHA}), \
                patch.object(release, "maintenance_candidate", return_value=source), \
                patch.object(release, "lifecycle", return_value=core), \
                patch.object(release, "pages", return_value=[]), \
                patch.object(release, "review_pair_for",
                             return_value={"result": {"state": "ready"}}) as pair_check, \
                patch.object(release, "validate_adopted_candidate") as adopted, \
                patch.object(release, "latest_verified_publication", return_value={}), \
                patch.object(release, "accepted_baseline_from_contexts", return_value=baseline), \
                patch.object(release, "final_attempt_history", return_value={}), \
                patch.object(release, "verified_shared_bundle", return_value=bundle), \
                patch.object(release, "policy_migration_receipt", return_value=receipt) as local_receipt, \
                patch.object(release, "close_review_contexts") as close:
            release.finish_policy_current(None)
        pair_check.assert_called_once()
        adopted.assert_called_once_with(source, source["configuration_sha"])
        core.authorize_final.assert_called_once_with(source, {})
        return close, local_receipt, contexts

    def test_policy_current_rechecks_proof_before_idempotent_pair_closure(self):
        close, local_receipt, contexts = self.run_finalizer(
            bundle={"verified": True}, receipt={"state": "none"})
        close.assert_called_once_with(contexts)
        local_receipt.assert_not_called()

    def test_policy_current_without_bundle_or_passing_receipt_fails_closed(self):
        source, _contexts, _baseline, env = self.pair_environment()
        core = Mock()
        core.candidate_identity.side_effect = FakeLifecycle.candidate_identity
        core.authorize_final.return_value = {"decision": "policy-only", "reason": "same product"}
        with patch.dict(os.environ, env, clear=True), \
                patch.object(release, "configuration", return_value=(release.REPOSITORY,
                                                                       source["configuration_sha"])), \
                patch.object(release, "selected_source", return_value={"upstream_sha": SHA}), \
                patch.object(release, "maintenance_candidate", return_value=source), \
                patch.object(release, "lifecycle", return_value=core), \
                patch.object(release, "pages", return_value=[]), \
                patch.object(release, "review_pair_for",
                             return_value={"result": {"state": "ready"}}), \
                patch.object(release, "validate_adopted_candidate"), \
                patch.object(release, "latest_verified_publication", return_value={}), \
                patch.object(release, "accepted_baseline_from_contexts", return_value=_baseline), \
                patch.object(release, "final_attempt_history", return_value={}), \
                patch.object(release, "verified_shared_bundle", return_value=None), \
                patch.object(release, "policy_migration_receipt", return_value={"state": "failed"}), \
                patch.object(release, "close_review_contexts") as close, \
                self.assertRaisesRegex(ValueError, "no passing exact native bundle"):
            release.finish_policy_current(None)
        close.assert_not_called()


class FrozenExecutionTests(unittest.TestCase):
    def test_trusted_a_runner_imports_the_candidate_b_controller(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted = root / "trusted"
            candidate_root = root / "candidate"
            trusted_scripts = trusted / "scripts"
            candidate_scripts = candidate_root / "scripts"
            trusted_scripts.mkdir(parents=True)
            candidate_scripts.mkdir(parents=True)
            candidate_release = candidate_scripts / "release.py"
            candidate_release.write_text("CONTROLLER_ID = 'B'\n")
            names = ("release", "baseline_runner", "case_runner", "policy_runner")
            previous_modules = {name: sys.modules.get(name) for name in names}
            previous_path = list(sys.path)
            try:
                baseline_runner._load_suite([], trusted, candidate_root)
                loaded_release = sys.modules["release"]
            finally:
                sys.path[:] = previous_path
                for name in names:
                    sys.modules.pop(name, None)
                    if previous_modules[name] is not None:
                        sys.modules[name] = previous_modules[name]

            self.assertEqual(Path(loaded_release.__file__).resolve(), candidate_release.resolve())

    def test_policy_orchestrator_uses_trusted_runner_for_both_a_and_b_suites(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted = root / "trusted"
            candidate_root = root / "candidate"
            trusted_scripts = trusted / "scripts"
            candidate_scripts = candidate_root / "scripts"
            cases = candidate_scripts / "cases"
            trusted_scripts.mkdir(parents=True)
            cases.mkdir(parents=True)
            candidate_scripts.joinpath("baseline_runner.py").write_text("# B controller under test\n")
            trusted_runner = trusted_scripts / "baseline_runner.py"
            trusted_runner.write_text("# A trusted test orchestrator\n")
            commands = []

            def checked(command, accepts):
                commands.append(command)
                self.assertTrue(accepts("GHIDRA_BASELINE_COMPLETE:1" if command[-1] == "baseline"
                                        else "GHIDRA_CANDIDATE_TESTS_COMPLETE:0"))

            with patch.object(policy_runner, "load") as load_shared, \
                    patch.object(policy_runner, "_checked", side_effect=checked), \
                    patch.object(policy_runner, "_load_candidate_case_runner", return_value=object()), \
                    patch.object(policy_runner, "_run_cases"), \
                    patch.object(policy_runner, "_write_policy_completion"):
                policy_runner.main(cases, trusted, candidate_root)

        self.assertEqual(len(commands), 2)
        load_shared.assert_called_once_with(candidate_root / "scripts" / "maintenance.lock.json")
        self.assertTrue(all(command[2] == str(trusted_runner.resolve()) for command in commands))
        self.assertEqual([command[-1] for command in commands], ["baseline", "candidate"])

    def test_private_import_test_output_cannot_enter_public_logs(self):
        import subprocess
        result = subprocess.CompletedProcess(["fixture"], 1, stdout="PRIVATE MODULE SOURCE")
        with patch.object(release.subprocess, "run", return_value=result) as execute, \
                self.assertRaisesRegex(ValueError, "policy check failed: fixed suite") as error:
            release.isolated_policy_check(["fixture"], timeout=30, label="fixed suite")
        self.assertNotIn("PRIVATE MODULE SOURCE", str(error.exception))
        self.assertEqual(execute.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(execute.call_args.kwargs["stderr"], subprocess.STDOUT)

    def test_exit_zero_without_exact_outer_completion_is_rejected(self):
        import subprocess
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "policy-completion"
            with patch.object(release.subprocess, "run",
                              return_value=subprocess.CompletedProcess(["fixture"], 0)), \
                    self.assertRaisesRegex(ValueError, "completion receipt"):
                release.isolated_policy_check(
                    ["fixture"], timeout=30, label="fixed suite", completion_file=receipt,
                    completion_marker="GHIDRA_POLICY_CHECK_COMPLETE:1")

    def test_policy_completion_receipt_is_exact_and_bounded(self):
        import policy_runner
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "completion"
            receipt.write_text("GHIDRA_BASELINE_COMPLETE:55\n", encoding="ascii")
            self.assertEqual(policy_runner._read_completion(receipt), "GHIDRA_BASELINE_COMPLETE:55")
            for value in ("GHIDRA_BASELINE_COMPLETE:55\nextra\n", "x" * 129):
                receipt.write_text(value, encoding="ascii")
                with self.subTest(value=value), self.assertRaises(RuntimeError):
                    policy_runner._read_completion(receipt)

    def test_actionlint_mount_uses_the_candidate_workflow(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trusted_workflow = root / "trusted/.github/workflows/release.yml"
            candidate_workflow = root / "candidate/.github/workflows/release.yml"
            trusted_workflow.parent.mkdir(parents=True)
            candidate_workflow.parent.mkdir(parents=True)
            trusted_workflow.write_text("name: trusted\n")
            candidate_workflow.write_text("name: candidate\n")

            selected = release.candidate_workflow_for_actionlint(candidate_workflow.parents[2])
            expected_workflow = str(selected)
            command = release.actionlint_command(root / "actionlint", selected)

        workflow_mount = next(value for value in command
                              if value.startswith("type=bind,") and "target=/workflow.yml" in value)
        self.assertEqual(workflow_mount,
                         f"type=bind,source={expected_workflow},target=/workflow.yml,readonly")
        self.assertIn("--read-only", command)
        self.assertIn("--network=none", command)

    def test_candidate_cannot_replace_or_drop_immutable_trusted_test_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            trusted = Path(temporary) / "trusted"
            candidate_root = Path(temporary) / "candidate"
            trusted_scripts = trusted / "scripts"
            candidate_scripts = candidate_root / "scripts"
            trusted_scripts.mkdir(parents=True)
            candidate_scripts.mkdir(parents=True)
            (trusted_scripts / "test_release.py").write_bytes(b"immutable A release tests")
            (trusted_scripts / "test_policy.py").write_bytes(b"immutable A policy tests")
            (trusted_scripts / "test_same.py").write_bytes(b"identical test bytes")
            (candidate_scripts / "test_release.py").write_bytes(b"weakened B release tests")
            (candidate_scripts / "test_same.py").write_bytes(b"identical test bytes")
            (candidate_scripts / "test_added.py").write_bytes(b"new B tests")

            immutable, proposed = baseline_runner.test_plan(trusted, candidate_root)

        self.assertEqual({path.name for path in immutable},
                         {"test_release.py", "test_policy.py", "test_same.py"})
        self.assertEqual({path.name for path in proposed}, {"test_release.py", "test_added.py"})
        self.assertTrue(all(path.is_relative_to(trusted) for path in immutable))
        self.assertTrue(all(path.is_relative_to(candidate_root) for path in proposed))

    def test_verified_private_bundle_keeps_closed_exact_review_contexts_closed(self):
        source = candidate()
        proof = {"endpoint": release.ACCEPTED_BASELINE_ENDPOINT, "variable": {}}
        contexts = [{"scope": scope, "pr": number, "state": "closed"}
                    for scope, number in (("full", 91), ("delta", 92))]
        core = Mock()
        core.candidate_identity.side_effect = FakeLifecycle.candidate_identity
        core.evaluate_pair.return_value = {"state": "ready", "complete": True,
                                           "findings": []}
        finding = {"finding_id": "review:91:601",
                   "candidate_id": FakeLifecycle.candidate_identity(source),
                   "scope": "full", "source": "review",
                   "source_sha": source["configuration_sha"], "native_id": 601,
                   "body": "An earlier native finding"}
        disposition = {"finding_id": finding["finding_id"], "candidate_id": finding["candidate_id"],
                       "source_sha": source["configuration_sha"], "status": "fixed",
                       "evidence": "Exact code and regression evidence"}
        accepted = {"proof": proof, "publication": {"published_at": "2026-10-19T10:00:00Z"}}
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(release, "lifecycle", return_value=core), \
                patch.object(release, "request_review_context", side_effect=contexts), \
                patch.object(release, "native_review_history",
                             return_value={"findings": [finding],
                                           "dispositions": [disposition]}) as history, \
                patch.object(release, "verified_shared_bundle", return_value={"verified": True}), \
                patch.object(release, "policy_migration_receipt") as local_receipt, \
                patch.object(release, "close_review_contexts"), \
                patch.object(release, "reopen_review_contexts") as reopen, \
                patch.object(release, "native_review_results", return_value=({}, {})) as native:
            result = release.review_pair_for(
                source, source["configuration_sha"], "4" * 40,
                delta_review_sha=source["configuration_sha"],
                accepted_baseline=accepted)
        self.assertEqual(result["result"]["state"], "ready")
        self.assertTrue(native.call_args.kwargs["allow_closed"])
        self.assertTrue(all(item["state"] == "closed" for item in result["contexts"]))
        history.assert_called_once_with(source, accepted["publication"])
        self.assertEqual(core.evaluate_pair.call_args.kwargs["known_findings"], [finding])
        self.assertEqual(core.evaluate_pair.call_args.kwargs["dispositions"], [disposition])
        local_receipt.assert_not_called()
        reopen.assert_not_called()

    def test_reopened_closed_pair_uses_refreshed_open_state_before_native_evaluation(self):
        source = candidate()
        accepted = {"proof": {"endpoint": release.ACCEPTED_BASELINE_ENDPOINT,
                              "variable": {}},
                    "publication": {"published_at": "2026-10-19T10:00:00Z"}}
        contexts = [
            {"scope": "full", "pr": 91, "state": "closed"},
            {"scope": "delta", "pr": 92, "state": "closed"},
        ]
        core = Mock()
        core.candidate_identity.side_effect = FakeLifecycle.candidate_identity
        core.evaluate_pair.return_value = {"state": "ready", "complete": True,
                                           "findings": []}
        reopened = [dict(context, state="open") for context in contexts]
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(release, "lifecycle", return_value=core), \
                patch.object(release, "request_review_context", side_effect=contexts), \
                patch.object(release, "native_review_history",
                             return_value={"findings": [], "dispositions": []}), \
                patch.object(release, "verified_shared_bundle", return_value=None), \
                patch.object(release, "policy_migration_receipt",
                             return_value={"state": "none"}), \
                patch.object(release, "reopen_review_contexts", return_value=reopened), \
                patch.object(release, "native_review_results", return_value=({}, {})) as native:
            result = release.review_pair_for(
                source, source["configuration_sha"], "4" * 40,
                delta_review_sha=source["configuration_sha"], accepted_baseline=accepted)
        self.assertEqual(result["result"]["state"], "ready")
        self.assertTrue(all(context["state"] == "open" for context in result["contexts"]))
        self.assertFalse(native.call_args.kwargs["allow_closed"])

    def test_carried_finding_stays_blocking_without_native_owner_disposition(self):
        source = candidate()
        accepted = {"proof": {"endpoint": release.ACCEPTED_BASELINE_ENDPOINT,
                              "variable": {}},
                    "publication": {"published_at": "2026-10-19T10:00:00Z"}}
        contexts = [
            {"scope": "full", "pr": 91, "state": "open"},
            {"scope": "delta", "pr": 92, "state": "open"},
        ]
        finding = {"finding_id": "inline:91:601",
                   "candidate_id": FakeLifecycle.candidate_identity(source),
                   "scope": "full", "source": "inline", "source_sha": source["configuration_sha"],
                   "native_id": 601, "body": "The carried defect is still unresolved"}
        core = Mock()
        core.candidate_identity.side_effect = FakeLifecycle.candidate_identity
        core.evaluate_pair.return_value = {"state": "findings", "complete": True,
                                           "findings": [finding]}
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(release, "lifecycle", return_value=core), \
                patch.object(release, "request_review_context", side_effect=contexts), \
                patch.object(release, "native_review_history",
                             return_value={"findings": [finding], "dispositions": []}), \
                patch.object(release, "native_review_results", return_value=({}, {})), \
                patch.object(release, "api") as native:
            result = release.review_pair_for(
                source, source["configuration_sha"], "4" * 40,
                delta_review_sha=source["configuration_sha"], accepted_baseline=accepted)

        self.assertEqual(result["result"]["state"], "findings")
        self.assertEqual(result["reason"], release.PAIR_FINDINGS)
        core.evaluate_pair.assert_called_once_with(
            source, {}, {}, known_findings=[finding], dispositions=[])
        native.assert_not_called()

    def test_native_review_history_reads_complete_same_repository_pr_records(self):
        current = {"number": 91, "updated_at": "2026-10-19T10:05:00Z", "state": "open",
                   "head": {"sha": SHA, "repo": {"full_name": release.REPOSITORY}}}
        older = {"number": 90, "updated_at": "2026-10-19T09:59:00Z", "state": "closed",
                 "head": {"sha": "2" * 40, "repo": {"full_name": release.REPOSITORY}}}
        fork = {"number": 89, "updated_at": "2026-10-19T10:06:00Z", "state": "open",
                "head": {"sha": "3" * 40, "repo": {"full_name": "someone/ghidra"}}}
        comments = [{"id": 1, "body": "owner review history"}]
        reviews = [{"id": 2, "body": "native review"}]
        inline = [{"id": 3, "body": "native inline finding", "commit_id": SHA}]
        inventory = [fork, current, older]

        def pages(path, **_kwargs):
            if path.endswith("/issues/91/comments"):
                return comments
            if path.endswith("/pulls/91/reviews"):
                return reviews
            if path.endswith("/pulls/91/comments"):
                return inline
            return []

        def api(path, **_kwargs):
            if path.startswith(f"repos/{release.REPOSITORY}/pulls?state=all&sort=updated"):
                return inventory
            if path == f"repos/{release.REPOSITORY}/pulls/91":
                return current
            raise AssertionError(f"unexpected native API request: {path}")

        with patch.object(release, "pages", side_effect=pages), \
                patch.object(release, "api", side_effect=api) as native, \
                patch.object(release, "resolve_native_review_sources", return_value={SHA: SHA}):
            records = release.native_review_history_records("2026-10-19T10:00:00Z")

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0], {"pull": current, "comments": comments,
                                      "reviews": reviews, "inline": inline,
                                      "resolved_commits": {SHA: SHA}})
        self.assertEqual(native.call_count, 4)

    def test_native_review_history_rejects_pr_and_inventory_changes_during_read(self):
        current = {"number": 91, "updated_at": "2026-10-19T10:05:00Z", "state": "open",
                   "head": {"sha": SHA, "repo": {"full_name": release.REPOSITORY}}}
        changed = {**current, "updated_at": "2026-10-19T10:06:00Z"}
        comments, reviews, inline = [], [], []

        def pages(path, **_kwargs):
            if path.endswith("/issues/91/comments"):
                return comments
            if path.endswith("/pulls/91/reviews"):
                return reviews
            if path.endswith("/pulls/91/comments"):
                return inline
            return []

        for mode in ("pr", "inventory"):
            inventory_reads = 0
            pull_reads = 0

            def api(path, **_kwargs):
                nonlocal inventory_reads, pull_reads
                if path.startswith(f"repos/{release.REPOSITORY}/pulls?state=all&sort=updated"):
                    inventory_reads += 1
                    if mode == "inventory" and inventory_reads == 2:
                        return [current, {**current, "number": 92, "head": {
                            "sha": "4" * 40, "repo": {"full_name": release.REPOSITORY}}}]
                    return [current]
                if path == f"repos/{release.REPOSITORY}/pulls/91":
                    pull_reads += 1
                    return changed if mode == "pr" and pull_reads == 2 else current
                raise AssertionError(f"unexpected native API request: {path}")

            with self.subTest(mode=mode), \
                    patch.object(release, "pages", side_effect=pages), \
                    patch.object(release, "api", side_effect=api), \
                    patch.object(release, "resolve_native_review_sources", return_value={}), \
                    self.assertRaisesRegex(ValueError, "changed"):
                release.native_review_history_records("2026-10-19T10:00:00Z")

    def test_failed_resolution_of_authenticated_codex_completion_prefix_blocks(self):
        prefix = "abcdef1"
        native_actor = {"login": release.BOT, "type": "Bot"}
        native_comment = {
            "user": native_actor,
            "performed_via_github_app": {"slug": release.APP},
            "body": f"Reviewed commit: `{prefix}`",
        }
        state_comment = {
            **native_comment,
            "body": "<!-- codex-review-state:v1 " + json.dumps({
                "code_review": {"commit_sha": prefix, "status": "completed"}}) + " -->",
        }
        for comment in (native_comment, state_comment):
            with self.subTest(body=comment["body"]), \
                    patch.object(release, "api", side_effect=ValueError("native commit not found")) as native, \
                    self.assertRaisesRegex(ValueError, "Codex completion source prefix"):
                release.resolve_native_review_sources([], [], [comment])
            self.assertFalse(native.call_args.kwargs["missing"])

        exact = prefix + "2" * 33
        with patch.object(release, "api", return_value={"sha": exact}) as native:
            self.assertEqual(release.resolve_native_review_sources([], [], [native_comment]),
                             {prefix: exact})
        native.assert_called_once_with(f"repos/{release.REPOSITORY}/commits/{prefix}", missing=False)
        with patch.object(release, "api", return_value={"sha": "b" * 40}), \
                self.assertRaisesRegex(ValueError, "Codex completion source prefix"):
            release.resolve_native_review_sources([], [], [native_comment])

    def test_unrelated_reviewed_commit_prose_does_not_become_a_resolution_gate(self):
        comment = {"user": {"login": "maintainer", "type": "User"},
                   "body": "Example only: Reviewed commit: `abcdef1`"}
        with patch.object(release, "api", return_value=None) as native:
            resolved = release.resolve_native_review_sources([], [], [comment])
        self.assertEqual(resolved, {})
        self.assertTrue(native.call_args.kwargs["missing"])

    def test_full_native_history_is_evaluated_at_verified_publication_cutoff(self):
        source = candidate()
        publication = {"published_at": "2026-10-19T10:00:00Z"}
        records = [{"pull": {"number": 91}, "comments": [], "reviews": [],
                    "inline": [], "resolved_commits": {}}]
        expected = {"findings": [{"finding_id": "review:91:601"}], "dispositions": []}
        core = Mock()
        core.review_history.return_value = expected
        native_commit = {"sha": SHA, "tree": {"sha": "5" * 40}}
        with patch.object(release, "lifecycle", return_value=core), \
                patch.object(release, "native_review_history_records", return_value=records) as fetch, \
                patch.object(release, "api", return_value=native_commit) as native_get:
            result = release.native_review_history(source, publication)
        fetch.assert_called_once_with(publication["published_at"])
        args, kwargs = core.review_history.call_args
        self.assertEqual(args, (source, records, publication["published_at"]))
        self.assertEqual(kwargs.keys(), {"read_native"})
        self.assertIs(kwargs["read_native"](f"repos/{release.REPOSITORY}/git/commits/{SHA}"),
                      native_commit)
        native_get.assert_called_once_with(f"repos/{release.REPOSITORY}/git/commits/{SHA}")
        self.assertEqual(result, expected)

    def environment(self):
        value = candidate()
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return {"GITHUB_SHA": value["configuration_sha"], "GITHUB_RUN_ID": "10",
                "GITHUB_RUN_ATTEMPT": "1", "FROZEN_RUN_ID": "10", "FROZEN_RUN_ATTEMPT": "1",
                "FROZEN_CANDIDATE": encoded,
                "FROZEN_CANDIDATE_ID": hashlib.sha256(encoded.encode()).hexdigest()}

    def test_checked_attempt_and_source_can_continue_without_private_credentials(self):
        with patch.dict(os.environ, self.environment(), clear=True), \
                patch.object(release, "selected_source", return_value={"upstream_sha": SHA}):
            self.assertEqual(release.check_shared_execution(), candidate())

    def test_mechanical_adoption_preserves_the_reviewed_candidate_identity(self):
        environment = {**self.environment(), "CONFIGURATION_SHA": "9" * 40,
                       "FROZEN_CONFIGURATION_SHA": "9" * 40}
        with patch.dict(os.environ, environment, clear=True), \
                patch.object(release, "selected_source", return_value={"upstream_sha": SHA}):
            self.assertEqual(release.check_shared_execution(), candidate())

    def test_native_rerun_or_changed_source_cannot_reuse_the_old_freeze(self):
        for changes in ({"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_RUN_ID": "11"},
                        {"GITHUB_SHA": "9" * 40}, {"FROZEN_CANDIDATE_ID": "0" * 64},
                        {"FROZEN_RUN_ATTEMPT": ""}):
            with self.subTest(changes=changes), \
                    patch.dict(os.environ, {**self.environment(), **changes}, clear=True), \
                    patch.object(release, "selected_source", return_value={"upstream_sha": SHA}), \
                    self.assertRaises(ValueError):
                release.check_shared_execution()

    def test_timestamped_native_skipped_placeholder_does_not_count_as_image_work(self):
        self.assertFalse(release.native_heavy_started({"started_at": "2026-10-19T10:00:00Z",
                                                      "conclusion": "skipped", "steps": []}))
        self.assertTrue(release.native_heavy_started({"started_at": "2026-10-19T10:00:00Z",
                                                     "conclusion": "failure", "steps": []}))
        with self.assertRaisesRegex(ValueError, "executed steps without a start timestamp"):
            release.native_heavy_started({"conclusion": "failure", "steps": [{"name": "Build"}]})
        with self.assertRaisesRegex(ValueError, "start timestamp"):
            release.native_heavy_started({"status": "completed", "conclusion": "success", "steps": []})

    def test_permanent_reviewed_instructions_are_part_of_adoption(self):
        product, regressions = release.adoption_contract_paths({
            "AGENTS.md": {}, "Dockerfile": {}, "scripts/test_release.py": {},
            ".repair/context.json": {}})
        self.assertIn("AGENTS.md", product)
        self.assertIn("scripts/test_release.py", regressions)
        self.assertNotIn(".repair/context.json", product + regressions)

    def test_complete_adopted_scope_reaches_the_real_shared_validator(self):
        blob = {"mode": "100644", "blob_sha": "a" * 40}
        before = {"AGENTS.md": blob, "Dockerfile": blob, "scripts/test_release.py": blob,
                  ".repair/context.json": blob}
        correct = {key: value for key, value in before.items() if not key.startswith(".repair/")}
        for extra in (False, True):
            adopted = {**correct, **({"unreviewed.py": blob} if extra else {})}
            with self.subTest(extra=extra), \
                    patch.object(release, "native_tree_map", side_effect=[before, adopted]):
                if extra:
                    with self.assertRaisesRegex(ValueError, "exactly"):
                        release.validate_adopted_candidate(candidate(), "9" * 40)
                else:
                    release.validate_adopted_candidate(candidate(), "9" * 40)


if __name__ == "__main__":
    unittest.main()
