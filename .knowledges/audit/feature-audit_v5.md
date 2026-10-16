# Feature Audit v5 — Remediation of v4 Findings

**Date:** 2026-10-16

**Baseline:** 52a52d2539450d39bbd3abc6f679cb95855de7bc plus the local fixes
listed below.

**Status:** Both v4 findings remediated within their documented scope and
locally verified. Production changes are uncommitted and unreleased.
Historical v4 evidence remains available for comparison.

## F1 — Presence operators validate facts: fixed

Present facts are checked for JSON serializability before exists/not_exists
can produce a known result. Invalid facts remain unknown: they cannot satisfy
an allow or rule out a candidate deny. Missing facts retain the original
presence semantics. A present null remains valid and satisfies exists.

The regression suite tests both operators with allow and deny rules, on both
memory and SQLite stores. Cases include missing keys, null, false, valid
strings, NaN, positive/negative infinity, functions, and invalid nested
objects/arrays. All 80 combinations pass.

The original public-API probe from audit v4 was rerun. All eight previous
unexpected allows now return allowed=false, err=nil, as documented. See
[corrected probe output](verification_v5/probe-results-fixed.txt) and the
[original output](verification_v4/probe-results.txt).

## F2 — Initial audit-file directory synchronization: fixed on Unix

NewFileAuditSink now performs these steps before returning a usable sink:

1. Open/create the regular audit file and validate its existing JSONL tail.
2. Synchronize the file.
3. On Unix platforms, synchronize the supplied path's parent directory and,
   when a leaf symlink targets another directory, the resolved target parent.
4. Propagate initialization errors and close the file handle rather than
   returning a sink that can acknowledge events without initialization.

Parent synchronization also runs for existing files. A previous initialization
failure may have created the file without persisting its directory entry, so
an existence check alone would not make retry safe. Failed initialization
preserves existing audit evidence. Directory handles are closed after sync;
open/sync/close failures propagate. Per-event append/fsync behavior is retained.

Regression tests cover initialization ordering, file/parent synchronization
failure, no returned sink or leaked file after failure, evidence preservation,
retry after failure, incomplete-tail rejection before synchronization, and a
new target file reached through a dangling symlink.

The [normal-path syscall evidence](verification_v5/fsync-trace-fixed-excerpt.txt)
shows file synchronization, then the parent directory, then per-event file
synchronization. The [symlink-path evidence](verification_v5/symlink-trace-fixed-excerpt.txt)
shows synchronization of the target file and both parent directories.

The probes use tmpfs to inspect syscall ordering. They are not power-loss
simulations or proof of persistent hardware behavior. The correction addresses
Linux's documented [directory fsync requirement](https://man7.org/linux/man-pages/man2/fsync.2.html).
Parent directories must already exist and permit directory opens; storage and
filesystem guarantees still apply.

### Platform compatibility

Unix platforms perform directory synchronization. Non-Unix platforms, including
Windows, retain historical file flushing only; no directory-entry crash-durability
guarantee is claimed there. This avoids making an existing Windows sink fail
on an unsupported directory fsync. A Windows test binary was cross-compiled
successfully with CGO disabled; Windows runtime/durability was not tested.
No public API, dependency, Go minimum, or toolchain version changed.

## Verification

| Check | Result |
| --- | --- |
| Targeted policy/audit regression suite, race enabled | Passed, 1.137s |
| Core full suite: go test -race -count=1 ./... | Passed, 4.711s |
| http, fiber, echo, gin race suites | All passed |
| examples race build | All five packages compiled; no tests present |
| integration/mysql race suite | Compiled/passed; live test skipped without a DSN |
| All seven modules: go vet ./... and go mod tidy -diff | Passed |
| Core full suite with GOTOOLCHAIN=go1.26.0 | Passed, 2.660s |
| Windows amd64 test binary cross-compilation, CGO disabled | Passed; not executed |
| Core govulncheck -test ./... | No vulnerabilities found |
| Examples govulncheck ./... | No called vulnerable symbols; one required-module advisory remains uncalled |
| Original v4 probe and file/directory syscall traces | Corrected behavior observed |
| Formatting, diff whitespace, local report links | Passed |

Live PostgreSQL/MySQL and Redis Cluster were not rerun for these policy and
local-filesystem changes; no SQL query or Redis client code changed. The earlier
remote CI run predates these local fixes and is not evidence that they passed
GitHub Actions. Broader platform/storage verification remains deployment work.

No commit, push, merge, or release was performed for this remediation.
