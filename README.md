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
Ordinary failures request bounded native Codex repair. Proposed repair code runs
without write credentials and against trusted tests before selective adoption.
The official application remains unmodified.

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
Native review and native coding are separate capabilities. For the native GitHub coding workflow, create a [Codex Cloud (Legacy) environment for this repository](https://chatgpt.com/codex/settings/environments) and verify that a coding task can push an actual repair to its PR branch. OpenAI's [current environment guide](https://learn.chatgpt.com/docs/environments/cloud-environments) states that GitHub integrations and reviews still use Legacy during the transition. A newly published Cloud environment is a separate setup, not a substitute for this workflow's Legacy environment. A completed review alone does not prove coding capability.
No VPS access or deployment credentials belong in this repository.

Run **Upstream Plus Packaging**. Build, publication, installation and validation
on the destination are separate stages; a workflow or schedule alone does not
prove a closed maintenance cycle. Server delivery belongs to its managed recipe.
