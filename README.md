# Ghidra / PyGhidra packaging

A public packaging fork of [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
for headless native Python workflows. **There are no Ghidra application patches.**

Like [zed-titlebarless](https://github.com/warelik/zed-titlebarless) and
[9router](https://github.com/warelik/9router), it follows one upstream snapshot,
reviews exact downstream configuration, verifies an artifact and publishes one
immutable release. It does not deploy to a server.

## Branches

- `master`: an unmodified, fast-forward-only upstream mirror.
- `downstream`: default branch containing packaging, smoke tests and release automation.
- Temporary review and repair PRs: exact-source review and native Codex work, not installation sources.

## Automatic maintenance cycle

Every six hours, on packaging changes and on authenticated Codex callbacks:

1. Select one stable official Ghidra release, resolve its exact tag commit, and verify the official distribution ZIP's SHA-256 and length.
2. Obtain two independent native Codex reviews bound to the exact candidate: the complete packaging integration from the empty packaging baseline and the exact delta since the last shipped source/configuration (packaging changes against the previous configuration, or upstream source changes when packaging is unchanged). The native `FORK_ACCEPTED_BASELINE` variable binds that delta to the candidate and provenance digest of the latest verified release; publication advances it only after the exact release verifies.
   An open full-review PR for the current configuration retains the exact official release selection, complete candidate and accepted-baseline proof in its immutable owner request. A callback reuses that selection only while the current configuration and baseline match and the native release tag and archive still verify.
3. Wait for both complete finding lists. Every actionable finding blocks release, including P2/P3 and unlabelled findings; machines repair the complete batch before fresh paired reviews.
4. Run the final credential-free policy and regression checks only after both reviews are clean.
5. For a changed product, build `linux/amd64` using the official distribution's own Dockerfile, then start that image without network access and prove import, instruction and cross-reference access, decompilation, annotation, save/reopen and persistence from a second process.
6. Check image identity, platform, actual Ghidra version and source labels; publish one verified release without replacing an existing asset.

The upstream mirror's duplicate `Build Ghidra` and `Dependency Submission`
Actions workflows are disabled. Maintenance uses the selected official release
artifact and the single final fork image job; the required fork policy and
regression checks remain part of that release sequence.

Historical findings are collected from a stable, updated-time-ordered native PR
inventory since the latest verified publication. For each same-repository PR,
the workflow checks the PR identity before and after fetching its complete
comments, reviews and inline reviews. Authenticated Codex completion commit
prefixes must resolve to an exact commit; unrelated prose does not become a new
history gate.

For a policy-only migration, the exact official source, image builder, runtime and regression contract must match the verified published image. The workflow runs the policy validation once, records its native result, and keeps the existing artifact and provenance without rebuilding or publishing a replacement. Pending external review or repair is reported as unverified, not a successful release.
The unpublished repair cycle is limited to 8,000 aggregate GitHub Actions runner
seconds, measured from actual job timestamps across all attempts; exhaustion
fails closed and reports the evidence in the existing issue.
Only a published release that passes the exact official-source, provenance,
asset and checksum verification resets that accounting window; unrelated or
unverified GitHub releases do not.
GitHub can report a cancelled job's completion one second before its start;
that exact anomaly is charged as a full second. Other inverted timestamps fail
closed. The real-time accounting clock is taken after the API walk so jobs
started during that walk are included.
Ordinary failures request bounded native Codex repair, but an ordinary candidate may
**add only** regular safe-named `scripts/cases/*.json` data; existing regression
files and cases cannot be replaced or removed. Trusted code parses
those files as bounded JSON literals and invokes a fixed function allowlist; no
candidate Python, workflow, test runner, documentation, Dockerfile or `.repair`
content is executed or adopted. The credential-free policy container retains no
network, capabilities or privilege escalation and has CPU, memory and process bounds.
The shared lifecycle code is fetched from its exact private pin through the public
loader; its source is not vendored here or included in release artifacts.

If a data-only attempt cannot repair the failure, the existing workflow uses the
owner-authorized Codex request mechanism to create a separate trusted-configuration
PR from the current `downstream` commit. Codex pushes the implementation there. The
workflow requires both paired exact-SHA review scopes, then runs the reviewed
candidate's normal unittest suite and declarative evaluator without write
credentials. Source review is the authority for that trusted program—tests cannot
prove actively malicious source honest. Only allowlisted configuration blobs are
adopted, never `.repair` evidence or candidate history. The shared adoption check
proves that all reviewed product and regression blobs are unchanged, then the same
workflow run continues to final validation, build and publication. Mechanical
adoption does not dispatch a second validation cycle. The original repair start
travels with the trusted PR and its deadline is checked again before adoption;
a task-start acknowledgement cannot advance an ordinary attempt.
Pending exact-SHA review also waits without issuing another coding task;
confirmed blocking findings and failed policy/land checks return to native repair.
Failure before a review request, including a forbidden candidate file, likewise
returns to coding rather than waiting for a review that was never requested.
Promotion carries the original immutable failure text from the ordinary seed and
links the old PR, so a later generic waiting message cannot erase the repair target.

If a final image job has started and failed, automation retains its diagnostics and
stops heavy retries. Another heavy attempt requires an owner-authored native grant
for the exact candidate and latest stopped `(run_id, run_attempt)` on its existing
full-review PR. Automation may present the exact marker, but never creates or
consumes the owner's authorization. The 8,000 runner-second repair
budget remains in force and is never reset by changing source or policy identity.
A policy-only migration does not start an application-heavy job.

Releases have the tag `build-VERSION-UPSTREAM_SHA12-CONFIG_SHA12` and exactly:

- `ghidra-image.tar.gz`: the verified image, usable with `podman load`.
- `provenance.json`: official release/archive identity, full upstream and packaging
  commits, empty patch-set SHA-256, platform, image ID and archive digest.
- `SHA256SUMS`: checksums of the image archive and provenance.

The image contains Ghidra, the JDK and a Python virtual environment with PyGhidra.
Python is `/ghidra/venv/bin/python3`; set `GHIDRA_INSTALL_DIR=/ghidra` when overriding
the standard entrypoint for direct Python scripts.

## GitHub setup

Use `downstream` as the default branch with Actions enabled. Enable the native
Codex GitHub integration for this repository and provide `CODEX_REQUEST_TOKEN`
from the existing repository owner's authorization. Trusted default-branch jobs
use it for paginated GitHub API reads and owner-authored requests because the
installation token's API quota can be exhausted by the bounded runner-history
audit. The credential-free repair policy job never receives it.
Set the `FORK_ACCEPTED_BASELINE` repository variable from the latest independently
verified release before enabling maintenance. The workflow checks its full
candidate identity and `provenance.json` digest before using it and advances the
variable only after a newly published release passes that verification. Provide
the read-only `MAINTENANCE_READ_KEY` repository secret for acquiring the exact
private lifecycle module; candidate tests and builds do not receive the key.
No VPS access or deployment credentials belong in this repository.

Run **Upstream Plus Packaging**. Build, publication, installation and validation
on the destination are separate stages; a workflow or schedule alone does not
prove a closed maintenance cycle. Server delivery belongs to its managed recipe.
