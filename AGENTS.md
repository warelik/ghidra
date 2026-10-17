# Ghidra packaging maintenance

This is a public fork of NationalSecurityAgency/ghidra, not a new analysis engine.
The application patch set is empty. Keep official Ghidra application sources and
the Dockerfile shipped in its distribution unmodified.

Keep `master` as an unchanged, fast-forward-only upstream mirror. The default
`downstream` branch holds packaging, verification and release automation, not a
second application tree. Temporary `review-base/`, `review/` and `repair/` branches
are native GitHub review/task evidence. Do not force-push or rewrite history.

Follow one complete stable official release. Pin its full upstream commit and
verify the official distribution asset's SHA-256 and size before extraction.
Build with the official container recipe in GitHub Actions. Do not assemble a
release from an operator's mutable working copy or compile on a production VPS.

Review the exact packaging configuration with the authenticated native Codex
integration. Owner-authored requests, exact commit identity, completed review and
the absence of P0/P1 findings are mandatory. Reactions, task acknowledgements,
stale approvals and unauthenticated comments do not count. P2/P3 findings retain
their nonblocking status and receive machine follow-up.

Prove actual import, instruction and cross-reference access, decompilation,
annotation and save/reopen persistence in the image. Match platform, version,
image ID, labels, official distribution identity, packaging revision and the
empty patch-set digest. Publish one checked image archive, provenance and
checksums without replacing a published asset. Publication is not installation.

Ordinary packaging failures belong to native Codex repair. Repair only
`scripts/release.py`, `scripts/smoke.py`, `.github/workflows/release.yml`, and
declarative `scripts/cases/*.json` regression cases. Proposed cases contain
literal arguments and expected values or named exceptions; only the reviewed
trusted configuration interprets them. Never import or execute candidate test
modules or let candidate code decide whether an assertion passed. The trusted
Python test suite and its interpreter are changed only by a separate, reviewed
configuration update, then protected from ordinary repair candidates. Do not
add application patches, features, controllers or queues. Do not weaken tests,
review prompts, criteria, integrity, isolation or publication controls to make
a build pass.

Test proposed repairs without write credentials, against both the trusted Python
suite and proposed declarative cases. Recheck exact-SHA review and selectively adopt only the verified
packaging/test files; never merge `.repair/` evidence into the default branch.
The adopted configuration requires a fresh review and build. Bound repair by
elapsed time and resource budgets; reaching a check or attempt count alone is
not a reason to stop or escalate. Preserve the last verified release and escalate
a real access boundary or exhausted repair through an existing GitHub issue with
evidence, attempted actions and remaining tradeoffs.

GitHub never deploys to a VPS and has no VPS credentials. Preserve user projects,
analysis databases, secrets and active work. Keep committed material portable
and public-safe: no private paths, hostnames, operator transcripts or secrets.
Use the simplest existing workflow that meets the whole contract; do not grow
this packaging fork into a separate product.
