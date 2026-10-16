# Feature Audit v3 — Completion and Verification

**Project:** rbacgo

**Date:** 2026-10-16

**Scope:** The findings in v1, the remediations and deferred opportunities in v2, and the user's request to finish those opportunities.

**Status:** Requested implementation work completed and locally verified in the working tree. New APIs are unreleased. This report supersedes the completion status in v1/v2; those files remain historical evidence.

## 1. Feature maturity and suitability

The library now implements the previously deferred lifecycle, observability,
policy-model, storage, and verification work. Its feature set remains suitable
for a Go authorization library: opt-in extensions preserve default exact RBAC,
existing Role/Permission layouts, and trusted bootstrap APIs. Framework adapters
share core policy and registry behavior rather than defining different semantics.

Local tests provide evidence for the documented behaviors and failure paths.
They do not establish universal production readiness, framework-version
compatibility, or deployment-specific revocation/durability guarantees. Applications
still own authentication, tenant membership, trusted resource facts, routing,
resource filtering, and operational retention/export policies.

## 2. Completion matrix

| Audit area | Completed implementation | Evidence and explicit contract |
| --- | --- | --- |
| Administrative authorization | RegisterRoleAs, RegisterRolesAs, AssignRoleAs, ListRolesAs | Checked management capability and tenant isolation; trusted bootstrap APIs retained |
| Operational logging | WithLogger using slog | Backend/version/invalidation errors tested; opt-in |
| Bounded tenant registry | Shared registry with capacity/LRU and automatic idle eviction | Capacity failure when entries are leased; explicit retry through eviction |
| Factory lifecycle | Context-aware factories, timeout, panic/invalid-result rejection | Cooperative cancellation and late-result cleanup; callbacks cannot be forcibly killed |
| Graceful shutdown | Acquire/release leases, draining eviction/clear, terminal Shutdown | All middleware hold leases through handlers; HTTP request-drain regression; owned resources close |
| Metrics | Atomic decision/cache/mutation/error counters and cumulative latency | Snapshot API; application supplies authenticated exporter |
| Durable audit API | AuditSink and JSONL FileAuditSink with synchronous append/fsync | Concurrent writers through one sink, incomplete-tail rejection, fail-closed decisions, committed-mutation error semantics |
| Wildcard/superadmin | Opt-in whole-field star matching | Exact matching remains default; explicit deny overrides star/star |
| Role metadata | Checked APIs and separate memory/SQL persistence | Descriptive only; original Role layout unchanged |
| Attribute policies and deny rules | Inherited allow/deny rules, AND conditions, attribute references, JSON operators | Missing/invalid allow facts fail; candidate deny unknowns fail closed; large integers retain precision |
| Atomic bulk policy updates | ApplyPolicyBatch and optional AtomicPolicyStore | Memory copy-swap or SQL transaction; rollback verified, including metadata/rules/assignments |
| Additional SQL dialect | Explicit MySQL/InnoDB support | Live MySQL 8.4.11 and 9.6.0; separate MIT test driver module |
| SQL concurrent-write integrity | Transaction-scoped meta-row lock for PostgreSQL/MySQL writers | Overlapping graph and role deletion regressions; cross-pool/process database lock |
| Redis Cluster | Scan every primary and route individual deletes | Three-primary live cluster, cross-slot keys, literal-prefix isolation, stale-fill fencing |
| English documentation | Feature guide, README, PRD, limitations, status/plan/phases, dependency notices, examples | Clear compatibility/failure semantics; historical claims marked; executable policy example |
| Verification and security | Race suites, live integrations, repeated concurrent workloads, benchmarks, vulnerability scans, CI jobs | Dated local results and raw scan/benchmark evidence below |

## 3. Important correctness findings resolved during completion

- SQL graph changes on disjoint roles could both pass cycle detection under
  overlapping transactions. A PostgreSQL regression reproduced two successful
  commits that together created a cycle before the fix. The transaction lock
  now permits one update and rejects the other with ErrCycleDetected. MySQL
  8.4.11 and 9.6.0 also pass the concurrent-update check.
- Role detail writes and assignments must not race role deletion. Tests hold a
  deletion transaction open while metadata, rules, or assignment writes wait;
  after commit those writes return ErrRoleNotFound. Re-registering the role
  does not resurrect stale details or assignments.
- Non-JSON attribute facts must not turn inequality/membership negation into
  an unintended allow. Invalid facts are treated as unknown and covered by
  operator tests, alongside exact large-integer comparisons.
- A factory that ignores cancellation must not hold a request indefinitely.
  Factory timeout bounds the caller's wait and late results are closed when
  they arrive; the callback itself still requires cooperation to terminate.

## 4. Local verification

All commands below completed successfully after the final SQL fix. Live services
were isolated audit containers, subsequently removed. Default unit tests also
cover memory and SQLite. Examples compile as five packages and contain no tests.

| Check | Result |
| --- | --- |
| Core: go test -race -count=1 -tags integration ./... with PostgreSQL/cluster variables set | Passed, 6.478s |
| Core: go vet ./... | Passed |
| Repeated mixed/extended concurrent workloads and registry/factory tests under race, count=10 | Passed, 3.581s |
| http, gin, echo, fiber: go test -race -count=1 ./... and go vet ./... | All passed |
| examples: go test -race -count=1 ./... and go vet ./... | All five packages compiled; vet passed |
| MySQL 8.4.11: integration/mysql race suite | Passed, 1.388s |
| MySQL 9.6.0: integration/mysql race suite | Passed, 1.416s |
| integration/mysql: go vet ./... | Passed |
| All seven modules: go mod tidy -diff | Passed without changes |
| Executable policy example | Approval allowed=true; locked invoice allowed=false; no metrics errors |
| Formatting, diff whitespace, workflow YAML syntax | Passed |

Live PostgreSQL was **18.3**, using pgx/stdlib. Redis Cluster was **7.4.11**,
three primaries covering all 16,384 slots, without replicas. The cluster test
covers prefix flushing and stale-fill protection; this was not a failover,
partition, or resharding soak test. The extended in-memory workload uses eight
workers with 100 operations each; the repeated command runs it ten times.
These are bounded concurrency checks, not a production-scale endurance test.

The revised CI includes PostgreSQL regressions, MySQL 8.4 integration, and an
isolated Redis Cluster job. Workflow YAML was parsed locally; the revised
GitHub Actions workflows have not run remotely because this work was not pushed.

## 5. Security and compatibility

The user explicitly approved raising the minimum Go version to **1.26.0 for
Fiber, Gin, and examples** to apply x/net v0.60.0 and its associated dependency
updates. Core, http, echo, and the separate MySQL integration module retain
minimum Go 1.25.7. Every module recommends toolchain **Go 1.27.2**, also used
for local verification and CI. These minimum declarations do not mean that an
older standard library has the same security fixes as the recommended toolchain.

Symbol-level govulncheck scans completed with exit status zero across all seven
modules; the MySQL driver was also scanned with -test to include its actual test
imports. No called vulnerable symbols were reported. Some scans still report
one advisory in a required module whose vulnerable code is not called. This is
not a claim that every transitive module is advisory-free or that a later scan
will have the same result. See the dated [raw scan files](verification_v3/).

Dependency inventory and third-party notices include the separate
**go-mysql-org/go-mysql v1.16.0** driver (MIT, including its bundled BSD notice),
without adding the driver to the core runtime requirements. Framework major
lines remain Fiber v3, Echo v5, and Gin v1. Other drivers/majors require explicit
application verification.

## 6. Measurements and claim corrections

Linux amd64, Intel i7-1165G7 @ 2.80GHz, Go 1.27.2, eight logical workers.
[Raw benchmark output](verification_v3/benchmarks.txt).

| Workload | ns/op | B/op | allocs/op |
| --- | --- | --- | --- |
| Explicit LRU hit | 125.0 | 16 | 1 |
| Default cache hit | 121.3 | 16 | 1 |
| Uncached rebuild | 478.0 | 576 | 7 |
| Owned cache hit | 196.6 | 16 | 1 |
| Attribute decision | 6,121 | 2,534 | 58 |
| Append/fsync audit decision on tmpfs | 2,044 | 644 | 5 |
| Parallel enforcement | 153.4 | 16 | 1 |

The audit benchmark used a /tmp file on **tmpfs**. It exercises the API but does
not measure persistent-disk latency or prove recovery after power loss. Use a
persistent filesystem for retained audit data and measure that storage path.
Warm in-memory lookup complexity does not describe graph resolution, attribute
rules, Redis network costs, or fsync. No universal latency is promised.

Documentation now distinguishes namespace isolation from caller authorization,
post-commit bookkeeping from atomic policy-data updates, and asynchronous
invalidation from instantaneous distributed revocation. PermissionView remains
an ordinary allow snapshot, not a final contextual access decision. Conditional
allows add grants; they do not restrict existing broad grants.

## 7. Remaining deliberate boundaries

The requested audit-completion list has implementations; no item from that list
is silently deferred. The following boundaries remain explicit:

- No arbitrary policy scripting, administration UI, per-field authorization, or
  automatic application resource filtering.
- No distributed transaction/outbox across policy writes and audit persistence.
  AuditWriteError.Committed signals a mutation that already succeeded before an
  audit failure. Multi-query decisions are not atomic policy snapshots.
- SQL writers serialize per table prefix, trading write throughput for graph
  integrity. Credentials need meta INSERT/UPDATE/SELECT permissions; direct SQL
  writers can bypass invariants and invalidation.
- Caller-owned pools, clients, invalidators, and audit sinks remain caller-owned.
  Registry Get retains no lease; use Acquire when cleanup may run concurrently.
- Cache invalidation/cluster flush remains best-effort under failures. Use finite
  TTLs and deployment-specific revocation tests. Shared versions are hints.
- Metrics have no bundled exporter; audit has no rotation/retention service,
  tamper resistance, or cross-host file locking. Applications supply these.

See [feature guide](../../docs/feature-guide.md) and
[known limitations](../../limitation.md) for the complete API contracts.
No commit, push, tag, or release was performed for this completion work.
