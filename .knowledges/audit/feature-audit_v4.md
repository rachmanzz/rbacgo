# Feature Audit v4 — Post-Dependabot Review

> Historical findings. See [feature-audit_v5.md](feature-audit_v5.md) for remediation and verification.

**Date:** 2026-10-16

**Revision:** 52a52d2539450d39bbd3abc6f679cb95855de7bc

**Scope:** Review the latest dependency remediation and the recently added
policy, registry, SQL, and audit APIs. Verify current CI status and exercise
suspected edge cases without changing production code.

**Result:** Two P2 findings remain. No P0/P1 finding was confirmed in this
review. Passing CI and implemented feature coverage do not establish that every
edge case is correct. This report supplements the historical completion and
verification records in feature-audit_v3.md and dependabot-fix_v1.md.

## Findings

### F1 — P2: Presence operators bypass invalid-attribute validation

**Location:** policy.go:164–170; JSON validation only starts at line 183.

conditionMatches returns immediately for exists/not_exists, before checking
whether a present fact is JSON-serializable. An invalid fact is therefore
reported as definitely present instead of unknown. This contradicts the
feature guide's contract that invalid facts cannot satisfy an allow and that
candidate deny rules with unknown facts fail closed.

**Reproduction:** A role has an allow for document/approve conditioned on
approval exists, plus an ordinary document/read permission and a deny for
read conditioned on approval not_exists. Supply approval=math.NaN() or a
function. Both approve and read return allowed=true, err=nil. The same results
occur with memory and SQLite stores: eight unexpected allows across the two
backends and two invalid fact types.

**Impact:** A computed or otherwise malformed fact can grant an operation or
skip a protective deny despite the documented conservative policy semantics.
The application still owns trusted facts; NaN can arise from server-side
calculations without malicious fact injection.

**Recommended correction:** For present facts, validate JSON serializability
before resolving exists/not_exists. Invalid present facts should produce an
unknown condition, while absent facts should retain the normal presence
semantics. Add allow/deny regression coverage for NaN, infinity, functions,
and invalid nested values for both presence operators, preserving valid null.

**Evidence:** [Probe source](verification_v4/probe.go.txt),
[observed output](verification_v4/probe-results.txt).

### F2 — P2: Newly created audit filenames are not durably synchronized

**Location:** observability.go:120–140 and 160–168.

NewFileAuditSink creates the file with O_CREATE. Emit appends and calls Sync
on the file descriptor, but no code opens/synchronizes the containing directory.
On Linux, fsync of file data and inode metadata does not necessarily persist
its directory entry; the [Linux fsync manual](https://man7.org/linux/man-pages/man2/fsync.2.html)
requires an explicit directory fsync for that guarantee.

**Impact:** Immediately after creating a new audit log, Emit may acknowledge
an event even though the new filename is not guaranteed to survive a crash or
power loss on persistent storage. This leaves a gap in the durable-acknowledgment
contract beyond the already documented tmpfs and transactional-outbox limits.
An existing file whose directory entry was already persisted is a different case.

**Recommended correction:** Durably synchronize creation of a new audit file
and its parent directory, with platform-specific handling and errors propagated
before successful acknowledgment. Add filesystem-operation tests for directory
sync/error ordering; retain the explicit deployment-storage caveats.

**Evidence:** [Syscall excerpt](verification_v4/fsync-trace-excerpt.txt)
shows O_CREAT followed by fsync on the file and no directory fsync. This probe
used tmpfs to inspect syscall behavior. It was not a power-loss simulation or
a measurement of actual loss on a persistent filesystem; the durability risk
is inferred from the implementation and the documented Linux syscall contract.

## Verification and healthy areas

- [Latest GitHub CI](https://github.com/rachmanzz/rbacgo/actions/runs/38894900917)
  completed successfully on the audited SHA: all 12 jobs passed, including
  seven module jobs, fuzzing, security, compliance, MySQL 8.4 and Redis Cluster.
- The four reviewed Dependabot PRs (#8, #11, #12, #13) are closed and unmerged.
  Their version changes were incorporated directly in the audited main revision.
  No open PR remained when checked through gh.
- All seven manifests declare go 1.26.0 and toolchain go1.27.2. The current
  Dependabot YAML parses and covers all seven module directories.
- The targeted existing policy/operator/audit/registry/factory race suite passed
  locally (1.104s), and go vet ./... passed. These tests did not catch F1.
- git diff --check passed before this report was added.
- No additional dependency regression was confirmed in this review. Security
  scan scope and residual uncalled advisories remain as recorded in the earlier
  dependency report; this audit did not run a new standalone vulnerability scan.

## Reproducing the isolated probe

From the repository root, copy verification_v4/probe.go.txt to a temporary .go
file and run it through go run. The probe uses public APIs, memory/SQLite stores,
and a temporary audit file. It prints the counterexamples; it does not change
application source or durable policy data. strace -f -yy with the
openat,fsync,fdatasync syscall filter produces the synchronization evidence.

No production fixes, commit, push, merge, or release were performed by this
audit. Only this English report and its reproduction evidence were added.
