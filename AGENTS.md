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

Review every candidate in two independent native Codex contexts: the complete
packaging integration from the empty packaging baseline and the exact delta since
the last verified source/configuration. Review packaging changes against the last
shipped configuration; when packaging is unchanged, review the official upstream
source delta. Bind each owner request and completion to
the exact candidate, review SHA, base SHA and scope. Wait for both complete finding
lists before requesting one batch repair. Every actionable finding blocks, including
P2/P3 and unlabelled findings. Reactions, task acknowledgements, stale approvals
and unauthenticated comments do not count.
Historical findings must be read from a stable updated-time-ordered PR inventory
after the latest verified publication. Recheck each same-repository PR before and
after fetching its complete native comments, reviews and inline reviews. An
authenticated Codex completion source prefix that cannot resolve to an exact
commit blocks; unrelated prose with an unresolved commit-like string does not.
The `FORK_ACCEPTED_BASELINE` repository variable must match the latest verified
release candidate and provenance digest. Advance it only after publishing and
re-verifying that exact release.

Use the exact privately pinned `warelik/machine-maintenance` source through the
public loader and lock. Verify its revision and module SHA-256 before importing it;
never vendor its source into this public repository or release artifacts.

Prove actual import, instruction and cross-reference access, decompilation,
annotation and save/reopen persistence in the image. Match platform, version,
image ID, labels, official distribution identity, packaging revision and the
empty patch-set digest. Publish one checked image archive, provenance and
checksums without replacing a published asset. Publication is not installation.

Ordinary packaging failures belong to native Codex repair. Ordinary untrusted
repair candidates may change only declarative `scripts/cases/*.json` regression
data: literal arguments and expected values or named exceptions, interpreted
by the trusted configuration. A code or workflow fix uses a separate native
Codex trusted-configuration update from the current default branch. Machines
create, review, verify and adopt that update; the owner does not perform those
steps manually. Python tests,
packaging code, the case interpreter and workflow are never executable inputs
from an ordinary repair candidate. Do not
add application patches, features, controllers or queues. Do not weaken tests,
review prompts, criteria, integrity, isolation or publication controls to make
a build pass.

Test proposed repairs without write credentials, against both the trusted Python
suite and proposed declarative cases. Recheck both exact-SHA review scopes and
selectively adopt only verified files; never merge `.repair/` evidence into the
default branch. The common adoption check proves every product and regression blob
is unchanged, then the same workflow run continues to final validation, build and
publication. A mechanical adoption does not dispatch a second validation cycle.
Bound repair by
elapsed time and resource budgets; reaching a check or attempt count alone is
not a reason to stop or escalate. Preserve the last verified release and escalate
a real access boundary or exhausted repair through an existing GitHub issue with
evidence, attempted actions and remaining tradeoffs.

GitHub never deploys to a VPS and has no VPS credentials. Preserve user projects,
analysis databases, secrets and active work. Keep committed material portable
and public-safe: no private paths, hostnames, operator transcripts or secrets.
Use the simplest existing workflow that meets the whole contract; do not grow
this packaging fork into a separate product.
