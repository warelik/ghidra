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

## Automatic releases

Every six hours, on packaging changes and on authenticated Codex callbacks:

1. Select the latest stable official Ghidra release and resolve its exact tag commit.
2. Obtain completed native Codex review of the exact packaging commit.
3. Download the official public distribution ZIP and verify its official SHA-256 and length.
4. Build `linux/amd64` using the distribution's own Dockerfile, without application patches.
5. Start the image without network access, import a synthetic ELF, read instructions
   and cross-references, decompile, rename and comment a function, save, close and reopen.
   Repeat from a second process to check durable persistence.
6. Check image identity, platform, actual Ghidra version and source labels.
7. Recheck review and configuration, then publish a verified release.

Pending external review or repair is reported as unverified, not a successful
release. P0/P1 findings block; P2/P3 findings receive automatic follow-up.
Ordinary failures request bounded native Codex repair, but an ordinary candidate may
change **only** regular safe-named `scripts/cases/*.json` data. Trusted code parses
those files as bounded JSON literals and invokes a fixed function allowlist; no
candidate Python, workflow, test runner, documentation, Dockerfile or `.repair`
content is executed or adopted. The credential-free policy container retains no
network, capabilities or privilege escalation and has CPU, memory and process bounds.

If a data-only attempt cannot repair the failure, the existing workflow uses the
owner-authorized Codex request mechanism to create a separate trusted-configuration
PR from the current `downstream` commit. Codex pushes the implementation there. The
workflow requires owner-authored native review of its exact SHA, then runs the
reviewed candidate's normal unittest suite and declarative evaluator without write
credentials. Source review is the authority for that trusted program—tests cannot
prove actively malicious source honest. Only allowlisted configuration blobs are
adopted, never `.repair` evidence or candidate history; adoption triggers a fresh
default-branch review and full build before publication.

Draft PR #14 is the one-time bootstrap because the old default cannot recognize this
trusted-update mode. Verify its exact head, run the full unit suite and rootless
read-only policy container, obtain a clean owner-authored native exact-SHA review,
then fast-forward `downstream` to that exact commit. Do not use the old generic
`land` command for this bootstrap. Dispatch the release workflow afterward; it must
perform a fresh default review and complete build before any publication. Future
trusted updates follow the automated separate-PR cycle above and need no manual owner
maintenance. The official application remains unmodified.

The reviewed bootstrap operation is a non-forced ref update, after replacing
`REVIEWED_SHA` with the full PR head verified by both `git ls-remote` and the native
review: `gh api --method PATCH repos/warelik/ghidra/git/refs/heads/downstream
-f sha=REVIEWED_SHA -F force=false`. Immediately read the ref
back and dispatch `release.yml` on `downstream`. Do not run this operation before the
review and rootless container check, and do not merge or mark draft PR #14 ready.

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
from the existing repository owner's authorization for owner-authored requests.
No VPS access or deployment credentials belong in this repository.

Run **Upstream Plus Packaging**. Build, publication, installation and validation
on the destination are separate stages; a workflow or schedule alone does not
prove a closed maintenance cycle. Server delivery belongs to its managed recipe.
