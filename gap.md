# Feature Status and Remaining Boundaries — rbacgo

- **Last updated:** 2026-10-16
- **Reference:** .knowledges/audit/feature-audit_v3.md and docs/feature-guide.md
- **Release status:** Working-tree changes; not tagged or published.

## Completed feature-audit work

| Area | Implemented | Boundary |
| --- | --- | --- |
| Core RBAC | Roles, assignments, hierarchy, cycle checks, ownership/group scopes | Authentication and trusted ownership context belong to the application |
| Wildcards/superadmin | Opt-in complete-field star matching | No path glob/regex; explicit deny still wins |
| ABAC and deny rules | Inherited allow/deny rules with JSON conditions and attribute references | Opt-in on every Enforcer; missing deny facts fail closed; no arbitrary scripts |
| Role metadata | Checked descriptive metadata APIs and memory/SQL persistence | Metadata never authorizes access; original Role struct unchanged |
| Administration | Checked As variants plus update/delete/unassign | Trusted provisioning APIs remain for bootstrap and compatibility |
| Atomic batches | Memory copy-swap and SQL transactions for policy data | Audit/version/cache work is post-commit; decisions are not atomic snapshots |
| Registry lifecycle | Shared implementation, optional capacity/idle eviction, cancellable factories, leases, shutdown | Capacity bounds cached entries; callbacks must cooperate; direct Get holds no lease |
| Observability | Metrics, slog warnings, durable JSONL audit sink | No bundled public exporter, rotation service, or distributed audit outbox |
| SQL backends | SQLite, PostgreSQL, explicit MySQL syntax | Tested drivers/versions are recorded in audit v3; other dialects need a custom Store |
| Redis Cluster | Per-primary scanning and routed single-key deletes | Best-effort under partitions/resharding; not instantaneous global revocation |
| Documentation | English feature guide, corrected examples/claims, explicit persistence/lifecycle contracts | Keep versioned audit evidence and current guidance aligned |
| Verification | Race suites, live DB/cluster integration, security scans, concurrency workloads, benchmarks | Results are dated workload-specific evidence, not universal guarantees |
| Compatibility/security | Patched Go 1.27.2 toolchain and x/net v0.60.0 family | User approved Go 1.26 minimum for Fiber/Gin/examples; core/http/echo retain 1.25.7 |

## Deliberate integration boundaries

The requested audit feature backlog has implementations. Administration UI,
per-field database authorization, policy scripting, database change watching,
distributed atomic decision snapshots, tamper-proof logs, and transactional
audit outboxes were not part of that feature-completion list and are not
promised by these APIs. Exact boundaries and operational failure semantics are
specified in limitation.md and the feature guide.

Publishing a release, tagging, committing, and pushing require a separate
explicit user request under AGENTS.md. No release-readiness guarantee follows
from the completion of this implementation work.
