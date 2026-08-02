# Implementation Plan — rbacgo

- **Status:** Draft
- **Module path:** `github.com/rachmanzz/rbacgo`
- **Reference:** `PRD.md`
- **Last updated:** 2026-08-02

---

## 1. Scope

Build a framework-agnostic RBAC library for Go with a monorepo layout, a core engine,
pluggable storage (SQL primary + LRU cache over in-memory/Redis), and per-framework
adapters for `net/http` (stdlib, also serves Chi), Fiber v3, Echo v5, and Gin v1 latest.

## 2. Repository structure (target)

```
rbacgo/
├─ go.mod            # core engine module (github.com/rachmanzz/rbacgo)
├─ rbac/             # model, enforcer, role hierarchy resolution
├─ store/            # Store interface + SQL store + LRU wrapper
├─ http/  (go.mod)   # stdlib net/http middleware (also serves Chi)
├─ fiber/ (go.mod)   # Fiber v3 adapter
├─ echo/  (go.mod)   # Echo v5 adapter
├─ gin/   (go.mod)   # Gin v1 adapter
├─ examples/         # runnable examples per adapter
├─ AGENTS.md
├─ PRD.md
├─ plan.md
├─ gap.md
├─ limitation.md
└─ decision-log.md
```

## 3. Milestones

### M1 — Core engine + storage (v0.1)
- Domain model: `Permission`, `Role`, `User`.
- Role hierarchy resolution (BFS/DFS over parents) with cycle detection.
- `Enforce(userID, resource, action) bool`.
- `Store` interface; SQL store implementation (PostgreSQL- and SQLite-compatible schema).
  The SQL store is **pluggable at the driver/pool level**: it takes a user-supplied
  `*sql.DB`, so users bring their own driver/pool (pgx5, pgxpool via the pgx `stdlib`
  adapter, go-sqlite3, or any `database/sql` implementation).
- **Default store: embedded SQLite** — `:memory:` by default, file path for persistence
  (`WithSQLite(path)`), zero-config `rbacgo.New()`.
- Config from environment: `WithConfigFromEnv()` reads `RBAC_*` vars (prefix configurable
  via `WithEnvPrefix`) — store, SQLite path, cache, Redis settings (FR-9, ADR-009).
- In-memory cache; concurrency-safe engine.
- Table-driven unit tests for model, hierarchy, cycle detection, enforcement.

### M2 — LRU cache layer (v0.2)
- Shared LRU abstraction (TTL + eviction).
- In-memory LRU backend.
- Redis LRU backend.
- Cache invalidation on role/permission/assignment changes.
- Benchmarks: decision with cache hit under 1 ms.

### M3 — Adapters (v0.3)
- `http` adapter: `func(http.Handler) http.Handler` middleware, 401/403 handlers,
  user-ID extraction hook, resource/action extraction hook.
- Fiber v3 adapter: idiomatic middleware mapping to Fiber context.
- Echo v5 adapter: idiomatic middleware mapping to Echo context/error model.
- Gin v1 adapter: idiomatic middleware mapping to Gin context.
- Adapter test suites using each framework's test utilities.

### M4 — Examples, docs & release (v1.0)
- Runnable examples per adapter under `examples/`.
- README, godoc, installation snippets.
- Multi-module release tagging (`http/v1.0.0`, `fiber/v1.0.0`, ...).

## 4. Multi-module strategy

- Root `go.mod` is the core module.
- Each adapter directory has its own `go.mod`.
- During local development, adapters use `replace github.com/rachmanzz/rbacgo => ../`
  (or relative path) to depend on the local core.
- Releases use per-module version tags per Go multi-module conventions.

## 5. Installation commands (target)

```sh
go get github.com/rachmanzz/rbacgo               # core engine
go get github.com/rachmanzz/rbacgo/http          # stdlib / Chi
go get github.com/rachmanzz/rbacgo/fiber         # Fiber v3
go get github.com/rachmanzz/rbacgo/echo          # Echo v5
go get github.com/rachmanzz/rbacgo/gin           # Gin v1
```

## 6. Definition of Done

- Core engine test coverage ≥ 80%.
- Cycle detection verified by tests.
- Cache hit decision benchmark under 1 ms.
- Each adapter has at least one passing test and one runnable example.
- No breaking API changes without a major version bump.

## 7. Risk & Mitigation

| Risk | Mitigation |
| --- | --- |
| Framework API drift (Fiber v3, Echo v5 are recent) | Pin adapter deps; re-verify versions before release |
| Multi-module tag complexity | Follow Go multi-module release guide; script tags in CI |
| Redis cache consistency | TTL bounds; optional invalidation hooks |
| Over-grant via hierarchy | Cycle detection + tests asserting minimal privilege |

## 8. Open follow-ups

- Wildcard permissions (v2).
- ABAC policies (post-v1).
- Auto-reload of policies from SQL (post-v1).
