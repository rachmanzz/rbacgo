# Known Limitations — rbacgo

- **Status:** Draft
- **Last updated:** 2026-08-02

## 1. Scope limitations (v1)

- **RBAC only.** No ABAC / attribute-based policy rules. Decisions are based solely on
  role membership and exact `resource` + `action` matching.
- **No wildcard permissions.** Patterns such as `resource:*` or `*:read` are not supported
  in v1.
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
- **LRU cache trade-offs.** Cache coherence is bounded by TTL; external changes to storage
  are not visible until TTL expiry unless explicit invalidation is called.
- **Redis backend** adds a network round-trip on cache misses; cold starts are slower than
  in-memory.
- **Hierarchy resolution cost** grows with the depth/breadth of the role graph; mitigated
  by caching effective permission sets.
- **No auto-reload / hot-swap** of policies from storage without redeploy.

## 4. Concurrency & performance notes

- Engine and cache are designed to be safe for concurrent reads/writes, but correctness of
  user-provided `Store` implementations is the responsibility of the implementer.
- Cache hit decision is targeted at under 1 ms; uncached decisions depend on the store.

## 5. Delivery limitations (current repo state)

- No code exists yet — everything is at planning/documentation stage.
- No CI pipeline yet; release tagging process not yet scripted.
