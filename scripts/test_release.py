import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import release


SHA = "1" * 40
BASE = "2" * 40
OLD = "3" * 40
WHEN = "2026-01-01T00:00:00Z"
BOT = {"login": release.BOT, "type": "Bot"}
APP = {"slug": release.APP}


def selected(version="12.1.4"):
    name = f"ghidra_{version}_PUBLIC_20260921.zip"
    tag = f"Ghidra_{version}_build"
    return {"version": version, "upstream_tag": tag, "upstream_sha": SHA,
            "upstream_release_id": 7, "asset": {"name": name, "sha256": "a" * 64, "size": 1234,
            "url": f"https://github.com/{release.UPSTREAM}/releases/download/{tag}/{name}"}}


def provenance():
    source = selected()
    return {"schema": 1, "repository": release.REPOSITORY,
            "upstream_repository": release.UPSTREAM, "version": source["version"],
            "upstream_tag": source["upstream_tag"], "upstream_sha": source["upstream_sha"],
            "config_sha": BASE, "patchset_sha256": hashlib.sha256(b"").hexdigest(),
            "platform": "linux/amd64", "image_id": "sha256:" + "b" * 64,
            "asset": {"name": source["asset"]["name"], "sha256": source["asset"]["sha256"]},
            "archive": {"name": "ghidra-image.tar.gz", "sha256": "c" * 64}}


class SourceTests(unittest.TestCase):
    def test_official_two_and_three_component_versions(self):
        for version in ("12.1.4", "12.2"):
            with self.subTest(version=version):
                value = selected(version)
                self.assertEqual(release.validate_selection(value), value)
                self.assertEqual(release.release_tag(value, BASE),
                                 f"build-{version}-{SHA[:12]}-{BASE[:12]}")

    def test_selection_cannot_redirect_or_change_archive_identity(self):
        mutations = [
            lambda s: s.update(upstream_tag="master"),
            lambda s: s.update(upstream_sha="master"),
            lambda s: s.update(version="12.1.4-preview"),
            lambda s: s["asset"].update(url="https://example.invalid/ghidra.zip"),
            lambda s: s["asset"].update(sha256=""),
            lambda s: s["asset"].update(size=2**31),
            lambda s: s["asset"].update(name="../archive.zip"),
            lambda s: s["asset"].update(extra="untrusted"),
            lambda s: s.update(patches=["application.patch"]),
        ]
        for mutate in mutations:
            value = selected()
            mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                release.validate_selection(value)

    def test_latest_release_must_be_official_stable_and_checksummed(self):
        source = selected()
        record = {"id": 7, "tag_name": source["upstream_tag"], "draft": False, "prerelease": False,
                  "assets": [{"name": source["asset"]["name"], "size": 1234,
                              "digest": "sha256:" + "a" * 64,
                              "browser_download_url": source["asset"]["url"]}]}
        with patch.object(release, "commit_ref", return_value=SHA):
            self.assertEqual(release.select_release(record), source)
            for changes in ({"draft": True}, {"prerelease": True}, {"tag_name": "master"}, {"assets": []}):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    release.select_release({**record, **changes})
            for changes in ({"digest": None}, {"size": 0}, {"browser_download_url": "https://example.invalid"}):
                broken = copy.deepcopy(record)
                broken["assets"][0].update(changes)
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    release.select_release(broken)

    def test_invalid_explicit_release_never_falls_back_to_latest(self):
        with patch.object(release, "api") as api:
            with self.assertRaises(ValueError):
                release.select_release({})
            api.assert_not_called()

    def test_empty_patchset_is_explicit_and_provenance_fails_closed(self):
        self.assertEqual(release.EMPTY_PATCHSET, hashlib.sha256(b"").hexdigest())
        release.validate_provenance(provenance(), selected(), BASE)
        for key in ("schema", "repository", "upstream_repository", "version", "upstream_tag",
                    "upstream_sha", "config_sha", "patchset_sha256", "platform", "image_id", "asset", "archive"):
            bad = provenance()
            bad[key] = None
            with self.subTest(key=key), self.assertRaises((ValueError, TypeError)):
                release.validate_provenance(bad, selected(), BASE)
        bad = provenance()
        bad["patchset_sha256"] = "d" * 64
        with self.assertRaises(ValueError):
            release.validate_provenance(bad, selected(), BASE)

    def test_unsafe_distribution_members_never_escape_destination(self):
        for member in ("../escape", "/absolute", "ghidra/../../escape", "ghidra\\escape"):
            with self.subTest(member=member), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "distribution.zip"
                with zipfile.ZipFile(archive, "w") as stream:
                    stream.writestr(member, b"untrusted")
                with self.assertRaises(ValueError):
                    release.extract_distribution(archive, root / "expanded")
                self.assertFalse((root / "escape").exists())

    def test_official_file_permissions_preserved_without_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "distribution.zip"
            executable = zipfile.ZipInfo("ghidra/support/analyzeHeadless")
            executable.external_attr = 0o100755 << 16
            with zipfile.ZipFile(archive, "w") as stream:
                stream.writestr(executable, b"executable fixture")
            result = release.extract_distribution(archive, root / "expanded")
            self.assertEqual((result / "support/analyzeHeadless").stat().st_mode & 0o777, 0o755)
            with zipfile.ZipFile(root / "symlink.zip", "w") as stream:
                link = zipfile.ZipInfo("ghidra/link")
                link.external_attr = 0o120777 << 16
                stream.writestr(link, "outside")
            with self.assertRaises(ValueError):
                release.extract_distribution(root / "symlink.zip", root / "linked")

    def test_annotated_tag_is_resolved_to_commit_and_missing_identity_rejected(self):
        replies = [{"object": {"type": "tag", "sha": BASE}},
                   {"object": {"type": "commit", "sha": SHA}}]
        with patch.object(release, "api", side_effect=replies):
            self.assertEqual(release.commit_ref(release.UPSTREAM, "tags/example"), SHA)
        with patch.object(release, "api", return_value={"object": {"type": "tree", "sha": SHA}}):
            with self.assertRaises(ValueError):
                release.commit_ref(release.UPSTREAM, "tags/example")

    def test_uploaded_asset_set_is_exact_and_every_file_is_checksummed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in release.ASSETS:
                (root / name).write_text(name)
            records = [{"name": name, "size": (root / name).stat().st_size,
                        "digest": "sha256:" + release.digest(root / name)} for name in release.ASSETS]
            release.verify_uploaded_assets(records, root)
            for bad in (records[:-1], records + [records[0]], records + [{"name": "extra"}]):
                with self.subTest(bad=bad), self.assertRaises(ValueError):
                    release.verify_uploaded_assets(bad, root)
            for key, value in (("size", 0), ("digest", "sha256:" + "0" * 64)):
                bad = copy.deepcopy(records)
                bad[0][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    release.verify_uploaded_assets(bad, root)

    def test_product_contract_hashes_controller_helpers_fixtures_and_complete_build_job(self):
        workflow = (
            "jobs:\n  build:\n    runs-on: ubuntu-24.04\n    steps:\n"
            "      - name: Build Upstream Container Without Application Patches\n"
            "        run: python3 scripts/release.py build release\n"
            "  publish:\n    runs-on: ubuntu-24.04\n")
        files = {
            "scripts/release.py": b"import os\ndef main(): return 1\n",
            "scripts/helper.py": b"def archive_digest(path): return path\n",
            "scripts/smoke.py": b"def smoke(): return True\n",
            "scripts/cases/example.json": b'{"project":"fixture"}\n',
            ".github/workflows/release.yml": workflow.encode(),
        }
        tree = "\n".join(
            f"100644 blob {index:040x}\t{path}"
            for index, path in enumerate(("scripts/release.py", "scripts/helper.py",
                                          "scripts/test_policy.py", "scripts/policy_runner.py",
                                          "scripts/smoke.py"), 1))
        def git_output(args, **_kwargs):
            if "--name-only" in args:
                return "scripts/cases/example.json\n"
            return tree + "\n"

        def contract_digest():
            with patch.object(release, "git_commit_file",
                              side_effect=lambda _commit, path: files[path]), \
                    patch.object(release.subprocess, "check_output", side_effect=git_output):
                return release.product_contract_digest(BASE, selected())

        baseline = contract_digest()
        files["scripts/release.py"] += b"\n# changed main or import-time behavior\n"
        self.assertNotEqual(baseline, contract_digest())
        files["scripts/release.py"] = b"import os\ndef main(): return 1\n"
        files["scripts/helper.py"] += b"\n# changed helper\n"
        self.assertNotEqual(baseline, contract_digest())
        files["scripts/helper.py"] = b"def archive_digest(path): return path\n"
        files["scripts/cases/example.json"] = b'{"project":"changed"}\n'
        self.assertNotEqual(baseline, contract_digest())
        files["scripts/cases/example.json"] = b'{"project":"fixture"}\n'
        files[".github/workflows/release.yml"] = workflow.replace(
            "runs-on: ubuntu-24.04", "runs-on: ubuntu-22.04", 1).encode()
        self.assertNotEqual(baseline, contract_digest())

    def test_configuration_preserves_native_default_branch_contract(self):
        with patch.dict(release.os.environ, {
                "GITHUB_REPOSITORY": release.REPOSITORY,
                "GITHUB_SHA": BASE,
                "CONFIGURATION_SHA": SHA,
        }), patch.object(release, "api", side_effect=[
                {"default_branch": "downstream"}, {"sha": SHA}]) as api:
            self.assertEqual(release.configuration(), (release.REPOSITORY, SHA))
        self.assertEqual(api.call_args_list[0].args, (f"repos/{release.REPOSITORY}",))
        self.assertEqual(api.call_args_list[1].args,
                         (f"repos/{release.REPOSITORY}/commits/downstream",))

    def test_build_configuration_uses_the_checked_out_commit(self):
        with patch.dict(release.os.environ, {
                "GITHUB_REPOSITORY": release.REPOSITORY,
                "GITHUB_SHA": BASE,
                "CONFIGURATION_SHA": BASE,
        }), patch.object(release, "run", return_value=BASE) as run, \
                patch.object(release, "api") as api:
            self.assertEqual(release.build_configuration(), (release.REPOSITORY, BASE))
        run.assert_called_once_with("git", "rev-parse", "HEAD", cwd=release.ROOT)
        api.assert_not_called()
        with patch.dict(release.os.environ, {
                "GITHUB_REPOSITORY": release.REPOSITORY,
                "GITHUB_SHA": BASE,
                "CONFIGURATION_SHA": SHA,
        }), patch.object(release, "run", return_value=BASE):
            with self.assertRaisesRegex(ValueError, "checked-out configuration identity"):
                release.build_configuration()

    def test_build_cli_retains_native_configuration_preflight(self):
        events = []
        with patch.object(release.sys, "argv", ["release.py", "build", "/tmp/release"]), \
                patch.object(release, "configuration", side_effect=lambda: events.append("preflight")), \
                patch.object(release, "build", side_effect=lambda path: events.append(path)):
            release.main()
        self.assertEqual(events, ["preflight", Path("/tmp/release")])

    def test_prepare_cli_recovers_only_the_exact_latest_published_review_pair(self):
        class Lifecycle:
            @staticmethod
            def candidate_identity(value):
                return hashlib.sha256(json.dumps(
                    value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

        source = selected()
        current_config = BASE

        def candidate_for(config, _selected):
            return {"schema": 1, "repository": release.REPOSITORY,
                    "upstream_sha": SHA, "application_sha": SHA,
                    "configuration_sha": config,
                    "patchset_sha256": release.EMPTY_PATCHSET,
                    "recipe_sha256": "c" * 64, "platform": "linux/amd64"}

        previous_release = {"id": 71, "target_commitish": OLD,
                            "published_at": "2026-10-18T10:00:00Z"}
        current_release = {
            "id": 72, "tag_name": release.release_tag(source, current_config),
            "target_commitish": current_config, "published_at": "2026-10-19T10:00:00Z",
            "draft": False, "prerelease": False,
            "body": (f"Exact full review: https://github.com/{release.REPOSITORY}/pull/25; "
                     f"delta review: https://github.com/{release.REPOSITORY}/pull/26."),
        }
        previous_publication = {
            "release": previous_release, "selected": source,
            "published_at": release.parse_github_time(previous_release["published_at"], "test time"),
        }
        current_publication = {
            "release": current_release, "selected": source,
            "published_at": release.parse_github_time(current_release["published_at"], "test time"),
        }
        candidate = candidate_for(current_config, source)
        accepted = {"candidate": candidate, "publication": {"id": current_release["id"]}}

        def marker(scope, review_sha, base_sha):
            payload = {"schema": 1, "candidate_id": Lifecycle.candidate_identity(candidate),
                       "scope": scope, "review_sha": review_sha, "base_sha": base_sha}
            return "<!-- fork-review:v1 " + json.dumps(
                payload, sort_keys=True, separators=(",", ":")) + " -->"

        def pull(number, scope, review_sha, base_sha):
            return {
                "number": number, "state": "open",
                "head": {"sha": review_sha,
                         "ref": (f"review/{review_sha}" if scope == "full"
                                 else f"review/changes-{review_sha}"),
                         "repo": {"full_name": release.REPOSITORY}},
                "base": {"sha": base_sha, "ref": f"review-base/{base_sha}",
                         "repo": {"full_name": release.REPOSITORY}},
            }

        pulls = {
            f"repos/{release.REPOSITORY}/pulls/25":
                pull(25, "full", current_config, release.BASELINE),
            f"repos/{release.REPOSITORY}/pulls/26":
                pull(26, "delta", current_config, OLD),
        }
        owner = {"login": release.REPOSITORY.split("/", 1)[0], "type": "User"}
        comments = {
            25: [{"id": 251, "user": owner, "created_at": WHEN, "updated_at": WHEN,
                  "body": marker("full", current_config, release.BASELINE)}],
            26: [{"id": 261, "user": owner, "created_at": WHEN, "updated_at": WHEN,
                  "body": marker("delta", current_config, OLD)}],
        }

        def api(route, **_kwargs):
            if route == f"repos/{release.UPSTREAM}/commits/master":
                return {"sha": SHA}
            return pulls[route]

        def pages(route, **_kwargs):
            if route == f"repos/{release.REPOSITORY}/releases":
                return [current_release, previous_release]
            number = int(route.split("/issues/", 1)[1].split("/", 1)[0])
            return comments[number]

        with tempfile.TemporaryDirectory() as temporary:
            selection_path = Path(temporary) / "selection.json"
            output_path = Path(temporary) / "github-output"
            with patch.dict(release.os.environ, {
                    "GITHUB_OUTPUT": str(output_path), "GITHUB_RUN_ID": "900",
                    "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": release.REPOSITORY,
                    "GITHUB_SHA": current_config,
            }), patch.object(release.sys, "argv", ["release.py", "prepare-shared",
                                                    str(selection_path)]), \
                    patch.object(release, "enforce_runner_budget"), \
                    patch.object(release, "configuration", return_value=(release.REPOSITORY,
                                                                          current_config)), \
                    patch.object(release, "active_repair", return_value=None), \
                    patch.object(release, "select_release", return_value=source), \
                    patch.object(release, "validate_selection"), \
                    patch.object(release, "pages", side_effect=pages), \
                    patch.object(release, "verified_publications",
                                 return_value=[previous_publication, current_publication]), \
                    patch.object(release, "reconcile_accepted_baseline", return_value=accepted), \
                    patch.object(release, "api", side_effect=api), \
                    patch.object(release, "commit_ref", return_value=SHA), \
                    patch.object(release, "packaging_base"), \
                    patch.object(release, "verify_remote_release"), \
                    patch.object(release, "maintenance_candidate", side_effect=candidate_for), \
                    patch.object(release, "lifecycle", return_value=Lifecycle), \
                    patch.object(release, "close_review_contexts") as close:
                release.main()

            close.assert_called_once()
            recovered = close.call_args.args[0]
            self.assertEqual([item["scope"] for item in recovered], ["full", "delta"])
            self.assertEqual([item["pr"] for item in recovered], [25, 26])
            self.assertEqual([item["request_id"] for item in recovered], [251, 261])
            self.assertIn("mode=current", output_path.read_text())
            workflow = (release.ROOT / ".github/workflows/release.yml").read_text()
            self.assertIn("  schedule:", workflow)
            self.assertIn("  workflow_dispatch:", workflow)
            self.assertIn("scripts/release.py prepare-shared", workflow)
            build_job = workflow.split("\n  build:", 1)[1].split("\n  publish:", 1)[0]
            self.assertIn("needs.prepare.outputs.mode == 'build'", build_job)


class ReviewTests(unittest.TestCase):
    def gate(self, *, reviews=(), inline=(), comments=(), resolve=lambda _: SHA):
        return release.review_gate(SHA, WHEN, list(reviews), list(inline), list(comments), resolve)

    def approved(self, **changes):
        return {"user": BOT, "commit_id": SHA, "state": "APPROVED",
                "submitted_at": WHEN, "id": 1, **changes}

    def native(self, state=None, **changes):
        state = state or {"commit_sha": SHA, "status": "completed",
                          "has_any_findings": False, "has_unresolved_findings": False}
        return {"user": BOT, "performed_via_github_app": APP, "updated_at": WHEN,
                "body": "<!-- codex-review-state:v1 " + json.dumps({"code_review": state}) + " -->", **changes}

    def test_exact_authenticated_approval_or_native_completion_passes(self):
        self.assertTrue(self.gate(reviews=[self.approved()])[0])
        self.assertTrue(self.gate(comments=[self.native()])[0])

    def test_exact_review_body_with_only_p2_is_nonblocking(self):
        review = {"user": BOT, "performed_via_github_app": APP,
                  "commit_id": SHA, "state": "COMMENTED", "submitted_at": WHEN,
                  "id": 17, "body": "<!-- codex-code-review-finding:v1 -->\n[P2] Follow-up"}
        self.assertTrue(self.gate(reviews=[review])[0])
        self.assertFalse(self.gate(reviews=[{**review, "body": "[P2] No authenticated finding marker"}])[0])
        self.assertFalse(self.gate(reviews=[{**review, "body": review["body"].replace("P2", "P1")}])[0])

    def test_reactions_reports_stale_reviews_and_spoofed_actors_fail(self):
        self.assertFalse(self.gate()[0])
        cases = [self.approved(commit_id=BASE),
                 self.approved(user={"login": release.BOT, "type": "User"}),
                 self.approved(submitted_at="2025-01-01T00:00:00Z"),
                 self.approved(state="CHANGES_REQUESTED"),
                 self.approved(performed_via_github_app={"slug": "other-app"})]
        for record in cases:
            with self.subTest(record=record):
                self.assertFalse(self.gate(reviews=[record])[0])
        self.assertFalse(self.gate(comments=[self.native(performed_via_github_app=None)])[0])
        self.assertFalse(self.gate(comments=[self.native(body="Task acknowledged; looks good")])[0])

    def test_unresolved_major_finding_blocks_even_positive_review(self):
        finding = {"user": BOT, "commit_id": SHA, "body": "[P1] Integrity bypass"}
        self.assertFalse(self.gate(reviews=[self.approved()], inline=[finding])[0])
        finding["body"] = "[P2] Nonblocking follow-up"
        self.assertTrue(self.gate(reviews=[self.approved()], inline=[finding])[0])

    def test_migrated_old_major_finding_does_not_block_fresh_native_review(self):
        finding = {"user": BOT, "commit_id": SHA, "original_commit_id": OLD,
                   "body": "[P1] Finding on the old reviewed source"}
        self.assertTrue(self.gate(inline=[finding], comments=[self.native()])[0])

    def test_current_source_major_finding_still_blocks(self):
        finding = {"user": BOT, "commit_id": SHA, "original_commit_id": SHA,
                   "body": "[P1] Finding on the current reviewed source"}
        self.assertFalse(self.gate(inline=[finding], comments=[self.native()])[0])

    def test_invalid_original_identity_falls_back_to_mapped_commit(self):
        for original in (None, "not-a-full-sha", SHA[:12]):
            finding = {"user": BOT, "commit_id": SHA,
                       "body": "[P1] Conservatively associated finding"}
            if original is not None:
                finding["original_commit_id"] = original
            else:
                finding["original_commit_id"] = None
            with self.subTest(original=original):
                self.assertFalse(self.gate(inline=[finding], comments=[self.native()])[0])

        missing = {"user": BOT, "commit_id": SHA, "body": "[P1] Missing original identity"}
        self.assertFalse(self.gate(inline=[missing], comments=[self.native()])[0])

    def test_stale_finding_cannot_replace_completed_current_review(self):
        finding = {"user": BOT, "commit_id": SHA, "original_commit_id": OLD,
                   "body": "[P1] Finding on the old reviewed source"}
        self.assertFalse(self.gate(inline=[finding])[0])

    def test_minor_findings_use_original_review_source(self):
        stale = {"user": BOT, "commit_id": SHA, "original_commit_id": OLD,
                 "body": "[P2] Old follow-up"}
        current = {"user": BOT, "commit_id": SHA, "original_commit_id": SHA,
                   "body": "[P3] Current follow-up"}
        fallback = {"user": BOT, "commit_id": SHA, "original_commit_id": "malformed",
                    "body": "[P2] Conservative follow-up"}
        general = {"user": BOT, "performed_via_github_app": APP,
                   "commit_id": SHA, "state": "COMMENTED", "body": "[P2] General finding"}
        def records(endpoint):
            return [stale, current, fallback] if endpoint.endswith("/comments") else [general]
        with patch.object(release, "pages", side_effect=records):
            self.assertEqual(release.minor_findings(9, SHA), [current, fallback, general])

    def test_incomplete_ambiguous_or_stale_completion_does_not_pass(self):
        for state in ({"commit_sha": BASE, "status": "completed", "has_any_findings": False,
                       "has_unresolved_findings": False},
                      {"commit_sha": SHA, "status": "in_progress", "has_any_findings": False,
                       "has_unresolved_findings": False},
                      {"commit_sha": SHA, "status": "completed", "has_any_findings": True,
                       "has_unresolved_findings": True}):
            with self.subTest(state=state):
                self.assertFalse(self.gate(comments=[self.native(state)])[0])
        self.assertFalse(self.gate(comments=[self.native(updated_at="2025-01-01T00:00:00Z")])[0])

    def test_pull_head_base_and_repository_identity_are_checked(self):
        pull = {"state": "open", "head": {"sha": SHA, "repo": {"full_name": release.REPOSITORY}},
                "base": {"sha": BASE, "repo": {"full_name": release.REPOSITORY}}}
        mutations = [lambda p: p["head"].update(sha=BASE),
                     lambda p: p["base"].update(sha=SHA),
                     lambda p: p["head"]["repo"].update(full_name="someone/ghidra"),
                     lambda p: p["base"]["repo"].update(full_name="someone/ghidra")]
        for mutate in mutations:
            value = copy.deepcopy(pull)
            mutate(value)
            with patch.object(release, "api", return_value=value):
                self.assertFalse(release.check_review(1, SHA, BASE)[0])

    def test_deadline_is_finite(self):
        with self.assertRaises(ValueError):
            release.enforce_deadline("2000-01-01T00:00:00Z")

    def test_every_normal_review_covers_complete_packaging_not_unreviewed_parent(self):
        self.assertEqual(release.BASELINE, "41d2bb84cf1e63841abeb5721034b3977032c8a5")
        with patch.object(release, "api", return_value={
                "status": "ahead", "merge_base_commit": {"sha": release.BASELINE}}) as api:
            self.assertEqual(release.packaging_base(SHA), release.BASELINE)
            api.assert_called_once_with(
                f"repos/{release.REPOSITORY}/compare/{release.BASELINE}...{SHA}")
        for response in ({"status": "behind", "merge_base_commit": {"sha": release.BASELINE}},
                         {"status": "ahead", "merge_base_commit": {"sha": BASE}}):
            with patch.object(release, "api", return_value=response), self.assertRaises(ValueError):
                release.packaging_base(SHA)


class RepairAndRuntimeTests(unittest.TestCase):
    def test_only_verified_publication_resets_runner_cycle(self):
        official = selected()
        valid = {"tag_name": release.release_tag(official, BASE),
                 "target_commitish": BASE, "published_at": "2026-01-01T00:00:00Z",
                 "draft": False, "prerelease": False}
        corrupt = {**valid, "tag_name": release.release_tag(official, OLD),
                   "target_commitish": OLD, "published_at": "2026-01-02T00:00:00Z"}
        unrelated = {**valid, "tag_name": "unrelated",
                     "published_at": "2026-01-03T00:00:00Z"}
        def verify(record, _selected, _config):
            if record is corrupt:
                raise ValueError("Published checksums mismatch")
        with patch.object(release, "api", return_value={}), \
                patch.object(release, "select_release", return_value=official), \
                patch.object(release, "verify_remote_release", side_effect=verify) as checked:
            boundary = release.verified_publication_time([corrupt, unrelated, valid])
        self.assertEqual(boundary, release.datetime.fromisoformat("2026-01-01T00:00:00+00:00"))
        self.assertEqual(checked.call_count, 2)
        with patch.object(release, "api", side_effect=ValueError("GitHub request failed: HTTP 403")), \
                self.assertRaisesRegex(ValueError, "HTTP 403"):
            release.verified_publication_time([valid])

    @patch.object(release, "verified_publication_time",
                  return_value=release.datetime.fromisoformat("2026-01-01T00:00:00+00:00"))
    def test_runner_budget_counts_all_attempts_jobs_and_clipped_running_time(self, _publication):
        publication = "2026-01-01T00:00:00Z"
        request = "2026-01-01T01:00:00Z"
        owner = {"login": "warelik", "type": "User"}
        endpoints = []

        def records(endpoint, **_kwargs):
            endpoint = endpoint.split("&per_page=")[0].split("?per_page=")[0]
            endpoints.append(endpoint)
            if endpoint == f"repos/{release.REPOSITORY}/releases":
                return [{"draft": False, "prerelease": False, "published_at": publication},
                        {"draft": True, "prerelease": False, "published_at": None}]
            if endpoint.startswith(f"repos/{release.REPOSITORY}/issues/comments?"):
                return [
                    {"user": owner, "created_at": "2025-12-31T23:00:00Z",
                     "body": f"<!-- ghidra-fix:{SHA}:8 -->"},
                    {"user": owner, "created_at": request,
                     "body": f"<!-- ghidra-fix:{SHA}:9 -->"},
                    {"user": {"login": "someone", "type": "User"}, "created_at": request,
                     "body": f"<!-- ghidra-fix:{SHA}:1 -->"}]
            if endpoint == f"repos/{release.REPOSITORY}/actions/workflows/release.yml/runs":
                return {"workflow_runs": [{"id": 10, "run_attempt": 2},
                                          {"id": 11, "run_attempt": 1}]}
            jobs = {
                f"repos/{release.REPOSITORY}/actions/runs/10/attempts/1/jobs": [
                    {"id": 1, "status": "completed", "conclusion": "failure",
                     "started_at": "2026-01-01T00:50:00Z", "completed_at": "2026-01-01T01:10:00Z"},
                    {"id": 2, "status": "completed", "conclusion": "skipped",
                     "started_at": None, "completed_at": None}],
                f"repos/{release.REPOSITORY}/actions/runs/10/attempts/2/jobs": [
                    {"id": 3, "status": "completed", "conclusion": "success",
                     "started_at": "2026-01-01T01:20:00Z", "completed_at": "2026-01-01T01:25:00Z"}],
                f"repos/{release.REPOSITORY}/actions/runs/11/attempts/1/jobs": [
                    {"id": 1, "status": "completed", "conclusion": "failure",
                     "started_at": "2026-01-01T00:50:00Z", "completed_at": "2026-01-01T01:10:00Z"},
                    {"id": 4, "status": "in_progress", "conclusion": None,
                     "started_at": "2026-01-01T01:50:00Z", "completed_at": None},
                    {"id": 5, "status": "queued", "conclusion": None,
                     "started_at": None, "completed_at": None}]}
            return {"jobs": jobs[endpoint]}

        now = release.datetime.fromisoformat("2026-01-01T02:00:00+00:00")
        with patch.object(release, "api", side_effect=records):
            self.assertEqual(release.enforce_runner_budget(now), 1500)
        self.assertIn(f"repos/{release.REPOSITORY}/actions/runs/10/attempts/1/jobs", endpoints)
        self.assertIn(f"repos/{release.REPOSITORY}/actions/runs/10/attempts/2/jobs", endpoints)

    @patch.object(release, "verified_publication_time",
                  return_value=release.datetime.fromisoformat("2026-01-01T00:00:00+00:00"))
    def test_runner_budget_fails_closed_for_denial_and_malformed_metrics(self, _publication):
        publication = {"draft": False, "prerelease": False,
                       "published_at": "2026-01-01T00:00:00Z"}
        request = {"user": {"login": "warelik", "type": "User"},
                   "created_at": "2026-01-01T01:00:00Z",
                   "body": f"<!-- ghidra-fix:{SHA}:1 -->"}
        run = {"id": 10, "run_attempt": 1}
        denied = ValueError("GitHub request failed: HTTP 403")
        with patch.object(release, "pages", side_effect=[[publication], [request], denied]), \
                self.assertRaisesRegex(ValueError, "HTTP 403"):
            release.enforce_runner_budget()
        malformed = {"id": 1, "status": "completed", "conclusion": "success",
                     "started_at": "not-a-time", "completed_at": "2026-01-01T01:01:00Z"}
        with patch.object(release, "pages", side_effect=[[publication], [request], [run], [malformed]]), \
                self.assertRaisesRegex(ValueError, "malformed"):
            release.enforce_runner_budget()
        exhausted = {"id": 1, "status": "completed", "conclusion": "success",
                     "started_at": "2026-01-01T01:00:00Z",
                     "completed_at": "2026-01-01T03:13:20Z"}
        now = release.datetime.fromisoformat("2026-01-01T04:00:00+00:00")
        with patch.object(release, "pages", side_effect=[
                [publication], [request], [run], [exhausted]]), \
                self.assertRaisesRegex(ValueError, "runner budget exhausted"):
            release.enforce_runner_budget(now)

    @patch.object(release, "verified_publication_time",
                  return_value=release.datetime.fromisoformat("2026-01-01T00:00:00+00:00"))
    def test_cancelled_one_second_timestamp_inversion_is_charged(self, _publication):
        publication = {"draft": False, "prerelease": False,
                       "published_at": "2026-01-01T00:00:00Z"}
        request = {"user": {"login": "warelik", "type": "User"},
                   "created_at": "2026-01-01T01:00:00Z",
                   "body": f"<!-- ghidra-fix:{SHA}:1 -->"}
        run = {"id": 10, "run_attempt": 1}
        cancelled = {"id": 1, "status": "completed", "conclusion": "cancelled",
                     "started_at": "2026-01-01T01:00:01Z",
                     "completed_at": "2026-01-01T01:00:00Z"}
        now = release.datetime.fromisoformat("2026-01-01T02:00:00+00:00")
        with patch.object(release, "pages", side_effect=[
                [publication], [request], [run], [cancelled]]):
            self.assertEqual(release.enforce_runner_budget(now), 1)
        for job in ({**cancelled, "conclusion": "success"},
                    {**cancelled, "completed_at": "2026-01-01T00:59:59Z"},
                    {**cancelled, "started_at": "2026-01-01T01:00:01.500Z",
                     "completed_at": "2026-01-01T01:00:01Z"}):
            with self.subTest(job=job), patch.object(release, "pages", side_effect=[
                    [publication], [request], [run], [job]]), \
                    self.assertRaisesRegex(ValueError, "Malformed GitHub Actions job timestamps"):
                release.enforce_runner_budget(now)
        scan_boundary = release.datetime.fromisoformat("2026-01-01T01:00:01.200+00:00")
        with patch.object(release, "pages", side_effect=[
                [publication], [request], [run], [cancelled]]):
            self.assertEqual(release.enforce_runner_budget(scan_boundary), 1)

    @patch.object(release, "verified_publication_time",
                  return_value=release.datetime.fromisoformat("2026-01-01T00:00:00+00:00"))
    def test_runner_budget_accounts_for_jobs_started_during_api_walk(self, _publication):
        publication = {"draft": False, "prerelease": False,
                       "published_at": "2026-01-01T00:00:00Z"}
        request = {"user": {"login": "warelik", "type": "User"},
                   "created_at": "2026-01-01T01:00:00Z",
                   "body": f"<!-- ghidra-fix:{SHA}:1 -->"}
        run = {"id": 10, "run_attempt": 1}
        job = {"id": 1, "status": "completed", "conclusion": "success",
               "started_at": "2026-01-01T02:00:30Z",
               "completed_at": "2026-01-01T02:00:45Z"}
        class SequenceClock(release.datetime):
            instants = [release.datetime.fromisoformat("2026-01-01T02:00:00+00:00"),
                        release.datetime.fromisoformat("2026-01-01T02:01:00+00:00")]
            @classmethod
            def now(cls, _timezone):
                return cls.instants.pop(0)
        with patch.object(release, "datetime", SequenceClock), \
                patch.object(release, "pages", side_effect=[
                    [publication], [request], [run], [job]]):
            self.assertEqual(release.enforce_runner_budget(), 15)

    def test_provider_lists_are_paginated_until_a_short_page(self):
        full = [{"id": item} for item in range(100)]
        with patch.object(release, "api", side_effect=[full, [{"id": 100}]]) as api:
            self.assertEqual(len(release.pages("provider/list?filter=all")), 101)
        self.assertEqual(api.call_args_list[0].args[0], "provider/list?filter=all&per_page=100&page=1")
        self.assertEqual(api.call_args_list[1].args[0], "provider/list?filter=all&per_page=100&page=2")

        with patch.object(release, "api", side_effect=[
                {"jobs": full}, {"jobs": [{"id": 100}]}]):
            self.assertEqual(len(release.pages("provider/jobs", list_field="jobs")), 101)
        for response in ({}, {"jobs": {}}, []):
            with self.subTest(response=response), patch.object(release, "api", return_value=response), \
                    self.assertRaises(ValueError):
                release.pages("provider/jobs", list_field="jobs")

    def test_cli_budget_boundary_blocks_exhaustion_but_not_high_attempt_count(self):
        target = "/tmp/unused"
        with patch.object(release.sys, "argv", ["release.py", "prepare", target]), \
                patch.object(release, "enforce_runner_budget",
                             side_effect=ValueError("Cumulative runner budget exhausted")), \
                patch.object(release, "prepare") as handler, \
                self.assertRaisesRegex(ValueError, "runner budget exhausted"):
            release.main()
        handler.assert_not_called()

        source = selected()
        issue = {"number": 9, "body": f"<!-- ghidra-escalation:{source['upstream_sha']} -->",
                 "user": {"login": "warelik"}}
        for message in ("Cumulative runner budget exhausted", "GitHub request failed: HTTP 403"):
            with self.subTest(message=message), \
                    patch.object(release.sys, "argv", ["release.py", "repair", target]), \
                    patch.dict(release.os.environ, {"SELECTED_JSON": "selected"}), \
                    patch.object(release, "enforce_runner_budget", side_effect=ValueError(message)), \
                    patch.object(release, "configuration", return_value=(release.REPOSITORY, BASE)) as config, \
                    patch.object(release, "selected_source", return_value=source) as selection, \
                    patch.object(release, "pages", return_value=[issue]), \
                    patch.object(release, "api") as api, \
                    patch.object(release, "request_repair") as handler, \
                    self.assertRaisesRegex(ValueError, message):
                release.main()
            config.assert_called_once_with()
            selection.assert_called_once_with()
            handler.assert_not_called()
            api.assert_called_once_with(f"repos/{release.REPOSITORY}/issues/9/comments",
                                        method="POST", data=unittest.mock.ANY)
        with patch.object(release.sys, "argv", ["release.py", "repair", target]), \
                patch.object(release, "enforce_runner_budget", return_value=3599) as budget, \
                patch.object(release, "request_repair") as handler:
            release.main()
        budget.assert_called_once_with()
        handler.assert_called_once()

    def test_attempt_count_never_replaces_elapsed_budget(self):
        source = selected()
        cycle = release.hashlib.sha256(f"{source['upstream_sha']}:0".encode()).hexdigest()
        state = {"config": BASE, "number": 6, "head": SHA, "seed": SHA,
                 "upstream": source["upstream_sha"],
                 "cycle": cycle}
        comments = [{"user": {"login": "warelik", "type": "User"}, "created_at": WHEN,
                     "body": f"<!-- ghidra-fix:{i:040x}:{i} -->"} for i in range(1, 5)]
        records = {f"repos/{release.REPOSITORY}/releases": [],
                   f"repos/{release.REPOSITORY}/pulls?state=all&base=downstream": [{}],
                   f"repos/{release.REPOSITORY}/issues/6/comments": comments}
        for expired in (False, True):
            error = ValueError("Elapsed repair budget exhausted") if expired else None
            with self.subTest(expired=expired), \
                    patch.dict(release.os.environ, {"SELECTED_JSON": "selected",
                                                   "NONBLOCKING_FOLLOWUP": "", "GITHUB_RUN_ID": "7"}), \
                    patch.object(release, "configuration", return_value=(release.REPOSITORY, BASE)), \
                    patch.object(release, "selected_source", return_value=source), \
                    patch.object(release, "failed_job_evidence", return_value="Concrete failure"), \
                    patch.object(release, "pages", side_effect=lambda endpoint: records[endpoint]), \
                    patch.object(release, "repair_state", return_value=state), \
                    patch.object(release, "active_repair", return_value=state), \
                    patch.object(release, "owner_identity"), \
                    patch.object(release, "enforce_deadline", side_effect=error) as deadline, \
                    patch.object(release, "api") as api, \
                    patch.object(release, "escalation") as escalation:
                if expired:
                    with self.assertRaisesRegex(ValueError, "Elapsed repair budget"):
                        release.request_repair(None)
                    api.assert_not_called()
                    escalation.assert_called_once_with(BASE, source,
                                                       str(error) + "\n\nConcrete failure")
                else:
                    release.request_repair(None)
                    api.assert_called_once()
                    self.assertIn(f"<!-- ghidra-fix:{SHA}:5 -->", api.call_args.kwargs["data"]["body"])
                    escalation.assert_not_called()
                deadline.assert_called_once_with(WHEN)

    def test_repair_evidence_boundary_is_escalated(self):
        source = selected()
        for error in (ValueError("Job log API HTTP 403"),
                      release.subprocess.TimeoutExpired(["gh", "api"], 60)):
            with self.subTest(error=type(error).__name__), \
                    patch.dict(release.os.environ, {"SELECTED_JSON": "selected",
                                                   "NONBLOCKING_FOLLOWUP": "", "GITHUB_RUN_ID": "7"}), \
                    patch.object(release, "configuration", return_value=(release.REPOSITORY, BASE)), \
                    patch.object(release, "selected_source", return_value=source), \
                    patch.object(release, "failed_job_evidence", side_effect=error), \
                    patch.object(release, "escalation") as escalation:
                with self.assertRaises(type(error)):
                    release.request_repair(None)
                escalation.assert_called_once_with(BASE, source, str(error))

    def test_job_evidence_reads_completed_failed_jobs_not_running_workflow_logs(self):
        response = {"jobs": [
            {"id": 1, "name": "still running repair", "status": "in_progress", "conclusion": None},
            {"id": 2, "name": "build", "status": "completed", "conclusion": "failure",
             "steps": [{"name": "real smoke", "conclusion": "failure"}]}]}
        result = type("Result", (), {"returncode": 0, "stdout": "TypeError: concrete failure", "stderr": ""})()
        with patch.object(release, "api", return_value=response) as api, \
                patch.object(release.subprocess, "run", return_value=result) as run:
            evidence = release.failed_job_evidence(release.REPOSITORY, "39034727367")
            self.assertIn("TypeError: concrete failure", evidence)
            self.assertIn("real smoke", evidence)
            api.assert_called_once_with(
                f"repos/{release.REPOSITORY}/actions/runs/39034727367/jobs?filter=latest&per_page=100&page=1")
            self.assertEqual(run.call_args.args[0],
                             ["gh", "api", f"repos/{release.REPOSITORY}/actions/jobs/2/logs"])

    def test_job_evidence_retries_only_terminal_escape_refusal(self):
        response = {"jobs": [{"id": 2, "name": "build", "status": "completed",
                              "conclusion": "failure"}]}
        refused = type("Result", (), {"returncode": 1, "stdout": "",
                                      "stderr": release.TERMINAL_ESCAPE_REFUSAL})()
        retrieved = type("Result", (), {"returncode": 0, "stdout": "failure log", "stderr": ""})()
        with patch.object(release, "api", return_value=response), \
                patch.object(release.subprocess, "run", side_effect=[refused, retrieved]) as run:
            self.assertIn("failure log", release.failed_job_evidence(release.REPOSITORY, "7"))
            self.assertEqual(run.call_args_list[0].args[0],
                             ["gh", "api", f"repos/{release.REPOSITORY}/actions/jobs/2/logs"])
            self.assertEqual(run.call_args_list[1].args[0],
                             ["gh", "api", "--allow-escape-sequences",
                              f"repos/{release.REPOSITORY}/actions/jobs/2/logs"])

    def test_job_evidence_terminal_escape_retry_failure_is_fatal(self):
        response = {"jobs": [{"id": 2, "status": "completed", "conclusion": "failure"}]}
        refused = type("Result", (), {"returncode": 1, "stdout": "",
                                      "stderr": release.TERMINAL_ESCAPE_REFUSAL})()
        failed = type("Result", (), {"returncode": 1, "stdout": "", "stderr": "HTTP 403"})()
        with patch.object(release, "api", return_value=response), \
                patch.object(release.subprocess, "run", side_effect=[refused, failed]) as run, \
                self.assertRaisesRegex(ValueError, "HTTP 403"):
            release.failed_job_evidence(release.REPOSITORY, "7")
        self.assertEqual(run.call_count, 2)

    def test_job_evidence_neutralizes_terminal_controls(self):
        response = {"jobs": [{"id": 2, "status": "completed", "conclusion": "failure"}]}
        result = type("Result", (), {"returncode": 0,
                                     "stdout": "plain\ttext\n\x1b[31mred\x1b[0m\rnext\x07",
                                     "stderr": ""})()
        with patch.object(release, "api", return_value=response), \
                patch.object(release.subprocess, "run", return_value=result):
            evidence = release.failed_job_evidence(release.REPOSITORY, "7")
        self.assertIn("plain\ttext\n\\x1b[31mred\\x1b[0m\\x0dnext\\x07", evidence)
        self.assertNotIn("\x1b", evidence)
        self.assertNotIn("\r", evidence)

    def test_missing_failed_job_or_log_is_not_replaced_by_generic_repair_evidence(self):
        with patch.object(release, "api", return_value={"jobs": []}), self.assertRaises(ValueError):
            release.failed_job_evidence(release.REPOSITORY, "7")
        response = {"jobs": [{"id": 2, "status": "completed", "conclusion": "failure"}]}
        failed = type("Result", (), {"returncode": 1, "stdout": "", "stderr": "HTTP 403"})()
        with patch.object(release, "api", return_value=response), \
                patch.object(release.subprocess, "run", return_value=failed), self.assertRaises(ValueError):
            release.failed_job_evidence(release.REPOSITORY, "7")

    def test_coding_environment_boundary_requires_authenticated_bot_evidence(self):
        body = "To use Codex here, [create an environment for this repo](https://example.invalid)."
        self.assertIsNotNone(release.coding_boundary([{"user": BOT, "body": body}]))
        self.assertIsNone(release.coding_boundary([{"user": {"login": "someone", "type": "User"}, "body": body}]))
        self.assertIsNone(release.coding_boundary([{"user": BOT, "body": "Task started"}]))
        older_error = {"user": BOT, "body": body, "created_at": WHEN}
        new_request = {"user": {"login": "warelik", "type": "User"},
                       "body": f"<!-- ghidra-fix:{SHA}:2 -->", "created_at": "2026-01-01T00:00:01Z"}
        self.assertIsNone(release.coding_boundary([older_error, new_request]))
        self.assertIsNotNone(release.coding_boundary([
            new_request, {**older_error, "created_at": "2026-01-01T00:00:02Z"}]))

    def test_repair_never_changes_application_or_trusted_tests(self):
        release.allowed_repair_paths({"scripts/cases/regression-1.json": "100644"})
        with self.assertRaises(ValueError):
            release.allowed_repair_paths({"scripts/cases/helpers.json": "100644"},
                                         {"scripts/cases/helpers.json"})
        for changes in ({}, {"Ghidra/application.properties": "100644"},
                        {"docker/Dockerfile": "100644"}, {"AGENTS.md": "100644"},
                        {"scripts/test_new.py": "100644"}, {"scripts/test_release.py": None},
                        {"scripts/cases/bad.py": "100644"}, {"scripts/release.py": "120000"},
                        {"scripts/release.py": "100644"}, {"scripts/smoke.py": "100644"},
                        {".github/workflows/release.yml": "100644"},
                        {".repair/failure.txt": "100644"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                release.allowed_repair_paths(changes)

    def test_public_untrusted_pull_cannot_inject_repair_state(self):
        pull = {"body": "<!-- ghidra-repair:v1 malicious -->",
                "user": {"login": "untrusted"}, "head": {"ref": "repair/fake",
                "repo": {"full_name": "untrusted/fork"}}}
        self.assertIsNone(release.repair_state(pull))

    def test_land_selectively_adopts_allowed_blobs_without_repair_evidence_or_history(self):
        state = {"number": 6, "head": SHA, "seed": OLD, "config": BASE}
        changed = ["scripts/cases/regression.json"]
        blobs = {name: f"blob-{index}" for index, name in enumerate(changed)}

        def git_boundary(*args, **_kwargs):
            self.assertEqual(args[:2], ("git", "ls-tree"))
            path = args[-1]
            # The candidate also contains .repair/failure.txt, but land must never inspect or adopt it.
            self.assertIn(path, changed)
            return f"100644 blob {blobs[path]}\t{path}"

        def github_boundary(endpoint, method="GET", data=None, **_kwargs):
            if endpoint == f"repos/{release.REPOSITORY}/git/commits/{BASE}":
                return {"tree": {"sha": "trusted-tree"}}
            if endpoint == f"repos/{release.REPOSITORY}/git/trees":
                self.assertEqual(method, "POST")
                self.assertEqual(data, {"base_tree": "trusted-tree", "tree": [
                    {"path": name, "mode": "100644", "type": "blob", "sha": blobs[name]}
                    for name in changed]})
                return {"sha": "adopted-tree"}
            if endpoint == f"repos/{release.REPOSITORY}/git/commits":
                self.assertEqual(method, "POST")
                self.assertEqual(data["tree"], "adopted-tree")
                self.assertEqual(data["parents"], [BASE])
                self.assertNotIn(OLD, data["parents"])
                self.assertNotIn(SHA, data["parents"])
                return {"sha": "adopted-commit"}
            return {}

        with patch.dict(release.os.environ, {"REPAIR_PR": "6", "REPAIR_HEAD": SHA}), \
                patch.object(release, "configuration", return_value=(release.REPOSITORY, BASE)), \
                patch.object(release, "active_repair", return_value=state), \
                patch.object(release, "repair_diff", return_value=changed), \
                patch.object(release, "check_review", return_value=(True, "ready")) as review, \
                patch.object(release, "run", side_effect=git_boundary) as git, \
                patch.object(release, "api", side_effect=github_boundary):
            release.land(None)
        self.assertEqual(review.call_count, 2)
        self.assertEqual(git.call_count, len(changed))

    def test_smoke_runs_without_network_or_privileges_and_with_bounded_memory(self):
        command = release.runtime_command("sha256:" + "d" * 64, Path("/isolated/fixture"))
        for flag in ("--read-only", "--network=none", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", "--memory=4g", "--cpus=2", "--pids-limit=512"):
            self.assertIn(flag, command)
        self.assertIn("JAVA_TOOL_OPTIONS=-Xmx2g", command)
        self.assertNotIn("--privileged", command)
        self.assertFalse(any("docker.sock" in part or "podman.sock" in part for part in command))
        self.assertTrue(command[-2].endswith("/smoke.py"))
        self.assertEqual(command[-1], "create")
        verify = release.runtime_command("sha256:" + "d" * 64,
                                         Path("/isolated/fixture"), mode="verify")
        self.assertEqual(verify[-2:], ["/scripts/smoke.py", "verify"])
        with self.assertRaises(ValueError):
            release.runtime_command("sha256:" + "d" * 64,
                                    Path("/isolated/fixture"), mode="rewrite")

    def test_workflow_keeps_untrusted_code_in_read_only_job(self):
        workflow = (release.ROOT / ".github/workflows/release.yml").read_text()
        policy = workflow.split("\n  policy-check:", 1)[1].split("\n  build:", 1)[0]
        self.assertNotIn("CODEX_REQUEST_TOKEN", policy)
        self.assertNotIn("contents: write", policy)
        self.assertEqual(workflow.count("GH_TOKEN: ${{ secrets.CODEX_REQUEST_TOKEN }}"), 5)
        self.assertIn("persist-credentials: false", policy)
        self.assertIn("trusted/scripts/release.py check-policy", policy)
        self.assertIn("needs: [prepare, policy-check]", workflow)
        self.assertIn("needs: [prepare, pending, policy-check, build, publish, land]", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("format('ignored-{0}', github.run_id)", workflow)
        self.assertNotIn("mode == 'policy-current'", policy)
        policy_finish = workflow.split("\n  policy-finish:", 1)[1].split("\n  repair:", 1)[0]
        self.assertIn("needs.prepare.outputs.mode == 'policy-current'", policy_finish)
        self.assertIn("finish-policy-current", policy_finish)
        repair = workflow.split("\n  repair:", 1)[1]
        self.assertIn("needs.prepare.outputs.mode != 'policy-current'", repair)
        build = workflow.split("\n  build:", 1)[1].split("\n  publish:", 1)[0]
        publish = workflow.split("\n  publish:", 1)[1].split("\n  land:", 1)[0]
        self.assertNotIn("mode == 'policy-current'", build)
        self.assertNotIn("mode == 'policy-current'", publish)
        download = publish.split("actions/download-artifact@", 1)[1].split("\n      -", 1)[0]
        self.assertTrue(download.startswith("d3f86a106a0bac45b974a628896c90dbdf5c8093"))
        self.assertIn("actions: read", publish)
        self.assertIn("contents: read", publish)
        self.assertNotIn("contents: write", publish)
        self.assertNotIn("pull-requests: write", publish)
        self.assertIn("github-token: ${{ github.token }}", download)
        self.assertNotIn("CODEX_REQUEST_TOKEN", download)

    def test_public_release_recovery_advances_checkpoint_then_closes_review_pair(self):
        pair = {"contexts": [{"scope": "full", "pr": 25},
                             {"scope": "delta", "pr": 26}]}
        events = []
        with patch.object(release, "record_accepted_baseline_after_publication",
                          side_effect=lambda *_args: events.append("checkpoint")), \
                patch.object(release, "close_review_contexts",
                             side_effect=lambda contexts: events.append(("close", contexts))):
            release.recover_published_release(
                release.REPOSITORY, {"draft": False}, selected(), BASE, pair, 25)
        self.assertEqual(events, ["checkpoint", ("close", pair["contexts"])])

    def test_smoke_contract_contains_real_engine_and_persistence_operations(self):
        smoke = (release.ROOT / "scripts/smoke.py").read_text()
        for operation in ("pyghidra.start()", "pyghidra.analyze(program)", "decompileFunction(",
                          "getReferencesTo(", "setName(", "setComment(", "program.save("):
            self.assertIn(operation, smoke)
        self.assertGreaterEqual(smoke.count("pyghidra.open_project("), 2)
        self.assertIn("assert persisted is not None", smoke)
        self.assertIn('.source(str(work / "fixture"))', smoke)


if __name__ == "__main__":
    unittest.main()
