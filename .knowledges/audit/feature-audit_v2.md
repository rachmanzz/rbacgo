# Feature Audit v2 — Remediation Verification

> Historical audit. See [feature-audit_v3.md](feature-audit_v3.md) for the current completion status.

**Project:** rbacgo

**Date:** 2026-10-16

**Scope:** Follow-up to `feature-audit_v1.md`, evaluated against the current working tree

**Status:** Concrete audit findings remediated and locally verified; feature opportunities remain explicitly deferred. New APIs are unreleased.

## 1. Implemented remediations

| Original finding | Remediation | Compatibility and limits |
| --- | --- | --- |
| Registry cleanup only forgot Enforcers | Added `Evict(tenant) bool` and `ClearAndClose()` to all four adapters | Existing `Clear()` still only forgets entries. New cleanup waits for detached factories outside the registry lock, then calls Enforcer.Close. It does not drain active requests or prohibit fresh entries. |
| Transient factory errors were cached indefinitely | `Evict` removes failed entries so the next Get retries provisioning | Automatic retries remain absent; failed results are still cached until explicitly removed. |
| Administrative authorization was inconsistent or unclear | Added `RegisterRoleAs`, `RegisterRolesAs`, `AssignRoleAs`, and `ListRolesAs` | These check the configured tenant-scoped management capability. Existing trusted APIs remain available for bootstrap and compatibility. Applications must authenticate the actor and authorize tenant membership. |
| Logger hooks existed only as a PRD requirement | Added optional `WithLogger(*slog.Logger)` | Logs selected permission lookup, invalidation publish, and policy-version failures. Disabled by default; not metrics, a durable audit trail, or complete backend error reporting. |
| SQL support exceeded the demonstrated dialect coverage | Added a tested-driver matrix and narrowed support to PostgreSQL and SQLite | Other drivers for these dialects require application verification; other dialects require a custom Store. |
| Performance and invalidation wording implied universal guarantees | Qualified warm in-memory cache complexity, historical benchmarks, Redis costs, and best-effort invalidation | No universal latency or instantaneous distributed revocation guarantee. |
| Tenant ownership language implied caller authorization | Documented trusted tenant resolution, actor identity, and direct Store bypass boundaries | Namespace isolation does not authenticate callers or establish administrative authority. |
| Owned-permission limitations contradicted the feature | Documented self/grp/any separately from general ABAC | General attribute-expression policy rules remain outside the current model. |
| Examples used outdated signatures or omitted required tenant options | Updated README and PRD examples; verified both complete core examples | New API examples require the working tree or a subsequent release, not the existing installation tag. |
| Completion and coverage statements were too broad | Reworked gap.md and labeled historical implementation evidence | Historical measurements are retained as historical evidence, not current quality guarantees. |
| Documentation language and duplicated warnings needed cleanup | Translated identified Indonesian feature-history excerpts and consolidated the Redis Cluster warning | User-facing feature guidance is in English. |

Adapter/example module manifests were also synchronized with the current core
dependency requirements so their tests and examples build against the local
module replacements. This was not a request to upgrade the product's supported
framework majors.

## 2. Verification performed

- Core: `go test -race ./...` and `go vet ./...` passed.
- Each adapter (`http`, `gin`, `echo`, `fiber`): `go test -race ./...` and
  `go vet ./...` passed.
- Examples module: `go test -race ./...` compiled all four example packages;
  those packages contain no tests. `go vet ./...` passed.
- New tests cover denied administrative operations without policy changes,
  configured management permissions, assignment cache invalidation, cross-tenant
  authority boundaries, and partial batch-registration behavior.
- New lifecycle tests cover subscriber cleanup, preserving other tenants,
  reprovisioning, explicit retry after factory failure, cleanup during blocked
  provisioning, and continued progress for another tenant while cleanup waits.
- New logger tests cover operational failure messages, local version fallback,
  successful mutations despite bookkeeping failures, fail-closed permission
  lookups, and rejection of a nil logger.
- The complete README quick-start and PRD core example both compiled and ran.
  The quick-start produced `true`, `true`, `false` as documented.
- Changed Go files are gofmt-clean; `git diff --check` passed.

The PostgreSQL integration-tagged suite, dependency vulnerability scans, online
license/freshness verification, load tests, and new benchmark measurements were
not run as part of this remediation. SQL queries and dialect behavior were not
changed. CI retains its PostgreSQL integration coverage; that is not a claim
that it ran locally during this work.

## 3. Remaining opportunities and operational limits

- Automatic registry capacity limits, idle eviction, factory cancellation,
  and graceful draining of active requests require additional lifecycle design.
- Enforcer.Close stops its invalidation subscriber and closes its env-owned
  Redis client. It does not close SQL/store resources or caller-owned Redis
  clients/invalidators. Registry cleanup inherits that scope; full resource
  ownership and shutdown remain application integration concerns.
- Metrics and durable decision/policy-change audit logging need a separately
  designed API and storage/retention behavior.
- Wildcard/superadmin matching, role metadata, general ABAC, deny rules, and
  atomic bulk policy updates remain feature opportunities, not implemented fixes.
- Other SQL dialects and Redis Cluster-wide cache flushes remain unsupported.
- Shared policy versions remain best-effort hints. They are not atomic policy
  revisions and may diverge or move backward after source outages.
- A subsequent release is needed before the new APIs can be installed from a
  published version. No release, commit, or push was performed by this remediation.

## 4. Assessment after remediation

The administrative and operational boundaries are clearer, the registry offers
explicit resource cleanup, and the documented claims more closely match the
implementation and available evidence. The core remains suitable for evaluation
as a focused Go RBAC library. The changes do not establish universal production
readiness or complete the deferred policy and operations roadmap.
