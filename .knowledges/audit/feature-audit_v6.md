# Feature Audit v6 — Review of v5 Remediation

**Date:** 2026-10-16

**Revision:** The local working tree based on 52a52d2, including the uncommitted
policy/audit fixes described in feature-audit_v5.md.

**Scope:** Review the latest presence-validation and audit-initialization
changes, regression coverage, failure cleanup, and documentation consistency.

**Result:** No new actionable finding was identified within this review's
scope. The two v4 findings remain remediated as specified in v5. This is a
bounded review of those fixes, not a guarantee that the entire library is free
of defects or production-ready in every deployment.

## Review conclusions

- Present facts are validated before either presence operator returns a known
  result. Missing keys and valid null preserve their documented behavior.
- Unknown facts remain conservative in deny rules. Another definitively false
  AND condition correctly excludes a deny; unknown facts do not override that
  false condition or produce an unintended grant from a conditional allow.
- Audit initialization validates the existing tail, synchronizes file data,
  synchronizes Unix parent directories, and only then returns a usable sink.
- Initialization errors close the file without deleting or truncating evidence.
  Reopening after failure also performs synchronization, rather than assuming
  an existing filename proves a previous initialization was durable.
- Relative audit paths and dangling leaf symlinks are handled. Directory
  handles are closed after synchronization. No mutable global test hooks were
  introduced; injected operations are scoped to one constructor invocation.
- No public API, dependency, minimum Go, or toolchain change was introduced by
  the remediation. Non-Unix directory-entry limits are stated consistently in
  code comments, the guide, limitations, and audit v5.

## Independent verification

The existing targeted regression suite was rerun with race detection ten times:

~~~sh
go test -race -count=10 \
  -run 'TestPresenceRulesRejectInvalidFacts|TestAuditInitialization|TestPolicyOperators|TestDurableAuditAndMetrics' ./...
go vet ./...
git diff --check
~~~

All completed successfully. The repeated race suite took 2.197s. It covers the
80 presence-policy combinations, constructor order/failures/retries, incomplete
tails, symlink creation, and durable-audit/metrics behavior from the existing
tests. Static review checked the error paths that surround these tests.

A separate [public-API probe](verification_v6/probe.go.txt) added cases outside
the initial matrix:

- Malformed json.RawMessage and cyclic maps as attribute facts.
- Both exists/not_exists in role decision evaluation using AND conditions,
  with a separate condition either definitely false or true.
- Memory and SQLite backends: all 16 mixed-condition checks passed.
- Relative-path audit file creation and two subsequent reopens retained all
  three events in order.

Observed probe output:

~~~text
PASS: 16 mixed-condition checks; relative-path audit creation and two reopens preserved 3 events
~~~

Copy the saved probe to a temporary .go file and run it from the repository
root to reproduce. It creates and removes only its own temporary audit files;
it does not modify application source or durable policy data.

## Verification boundaries

- The full seven-module race/vet/tidy checks, minimum Go 1.26.0 run, Windows
  cross-compilation, syscall traces, and security scans remain recorded in v5.
  This review did not repeat every check or run a new dependency scan.
- Windows runtime behavior and directory-entry durability were not tested.
  Non-Unix platforms intentionally retain file flushing without an equivalent
  directory-entry guarantee.
- No power-loss simulation, persistent-hardware durability test, or live SQL/
  Redis integration rerun was performed. These fixes do not change SQL queries
  or Redis client operations.
- The latest local fixes have not been pushed. Earlier remote CI success must
  not be interpreted as verification of this uncommitted working tree.

No application code was changed by this audit. Only this English report and its
independent probe source were added. No commit or push was performed.
