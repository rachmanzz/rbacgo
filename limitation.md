# Known Limitations — rbacgo

- **Status:** Draft
- **Last updated:** 2026-08-02

## 1. Scope limitations (v1)

- **RBAC only.** No ABAC / attribute-based policy rules. Decisions are based solely on
  role membership and exact `resource` + `action` matching.
- **No wildcard permissions.** Patterns such as `resource:*` or `*:read` are not supported
  in v1. Nice-to-have backlog (user decision 2026-08-08, ADR-024): when implemented,
  matching order is exact match → `resource:*` → `*:action` → `*:*`; a role holding
  `*:*` acts as superadmin (no separate bypass option needed); exact-match behavior
  stays unchanged (backward compatible).
- **No role metadata.** Roles carry only name, permissions, and parents. Nice-to-have
  backlog (ADR-024): optional `Metadata map[string]string` on `Role` — descriptive
  only, no effect on validation, enforcement, SQL schema, or tenant scoping.
- **No superadmin special-case.** "Superadmin" is modeled as a role holding the `*:*`
  wildcard permission (backlog design, ADR-024), not as a dedicated option or bypass
  path in the Enforcer.
- **No per-field (column-level) authorization.** Authorization is at the resource/action
  level only.
- **No administration UI** for managing roles or permissions.

## 2. Framework support limitations

- **Fiber v3 only** — Fiber v2 users cannot use the adapter.
- **Echo v5 only** — Echo v4 users cannot use the adapter.
- **Gin v1 latest** — only the current major line.
- **Chi** has no dedicated adapter; Chi users must use the stdlib `http` adapter (Chi is
  built on `net/http`).
- **`http` adapter is not an aggregator** — it is a standalone stdlib package and does not
  re-export the other adapters.

## 3. Engine & storage limitations

- **Pluggable store, SQLite default.** Default store is embedded SQLite (`:memory:`
  unless a file path is given); data resets on restart when using `:memory:`. The SQL
  store relies on a user-supplied `*sql.DB` (pgx5/pgxpool/stdlib, go-sqlite3, or any
  `database/sql` driver); pool/driver behavior is the responsibility of the user's chosen
  library.
- **Env config is read once at construction** (`WithConfigFromEnv`, prefix `RBAC_`). No
  hot-reload — restart required to apply env changes. Explicit options override env vars;
  env vars override defaults.
- **LRU cache trade-offs.** Within one process, mutations invalidate the cache
  immediately. Across processes/instances sharing one store, coherence is bounded
  by TTL — external changes to storage are not visible until TTL expiry unless
  explicit invalidation is called — **unless** the instances exchange
  invalidation events over Redis pub/sub (`WithCacheInvalidator`), which makes
  mutations on any instance evict the affected snapshots on every subscriber
  immediately (events are best-effort: a network partition or publish failure
  degrades back to TTL-bounded coherence).
- **Cache is on by default.** `New()` installs an in-memory LRU (1024 entries, 5m TTL), so
  each enforcer holds up to that many effective-permission snapshots in memory. Use
  `WithConfigFromEnv` + `RBAC_CACHE=none` to disable, or `WithLRU` to swap the backend.
- **Redis backend** adds a network round-trip on cache misses; cold starts are slower than
  in-memory.
- **`policy_version` default is in-memory.** Without a shared source (SQL `meta` table via
  the SQL store, or `NewRedisPolicyVersion` + `WithPolicyVersionStore`), each process keeps
  its own counter; multi-instance deployments must point every instance at the same shared
  source for consistent versions.
- **Hierarchy resolution cost** grows with the depth/breadth of the role graph; mitigated
  by caching effective permission sets.
- **Recursive hierarchy traversal.** `Enforce`/`HasRole` (effective-permission and inherited-role
  collection), SQL cycle checks (`checkCycles`), and the memory store's `detectCycle` traverse
  the parent graph recursively. Pathologically deep hierarchies (hundreds of thousands of
  levels) can exhaust the goroutine stack; keep hierarchies shallow and wide instead.
- **Registration is quadratic on pathological chains.** Each role insert runs a
  cycle check over its transitive parents, so building a linear chain of N roles
  costs O(N²) (verified: 10,000-level chains register in ~1s, 100,000 levels do
  not complete in 3 minutes). Real hierarchies are shallow; a cycle check after
  every insert is the price of rejecting cycles at registration time.
- **No auto-reload / hot-swap** of policies from storage without redeploy.
- **Tenant is fixed per Enforcer.** `WithTenant` is required and cannot be
  changed after construction; an application serving many tenants builds one
  Enforcer per tenant (the documented pattern). Tenant-ID uniqueness across
  enforcers is the application's responsibility — the library guarantees
  role-name and assignment isolation per tenant, not that two enforcers never
  use the same tenant id (same tenant id is intentional for multi-instance
  scaling). **Tenant IDs must not contain the internal separator `::`**
  (rejected at construction): a tenant like `a::b` would share store keys
  with tenant `a`'s role `b::x` and break isolation. Role/user names may
  contain `::` safely: within one tenant they are full suffixes of their
  scoped keys, so they remain unambiguous per tenant.

## 4. Concurrency & performance notes

- Engine and cache are designed to be safe for concurrent reads/writes, but correctness of
  user-provided `Store` implementations is the responsibility of the implementer.
- Cache hit decision is targeted at under 1 ms; uncached decisions depend on the store.
- **Per-tenant adapter memory.** Each `TenantRegistry` caches one Enforcer per
  tenant for the process lifetime (factory runs once per tenant, by design).
  Every cached Enforcer holds its own LRU (default 1024 snapshots, 5m TTL),
  so a registry serving N tenants keeps roughly N × cache-budget in memory.
  With a shared SQL store the per-tenant footprint is small; with per-tenant
  memory stores it is the whole tenant dataset. Bound tenant IDs (no
  user-controlled unbounded tenant names) and call `Clear()` to release
  cached Enforcers when tenants are decommissioned.
- **Memory store user keys.** The in-memory store retains one (empty) entry
  per user ID ever assigned, so its footprint grows with the number of
  distinct user IDs, not with current assignments.

## 5. Delivery limitations (current repo state)

- Engine, stores, cache, and all four adapters are implemented and tested (P1–P4 complete).
- First public release `v0.1.0-1` tagged per Go multi-module conventions
  (`v0.1.0-1`, `http/v0.1.0-1`, `fiber/v0.1.0-1`, `echo/v0.1.0-1`, `gin/v0.1.0-1`).
- CI pipeline (`.github/workflows/ci.yml`) runs build/vet/race tests, Postgres integration
  tests, `govulncheck`, and compliance checks.
