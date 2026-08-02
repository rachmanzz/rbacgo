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
- Multi-module release tagging starting at `v0.1.0-1`
  (`http/v0.1.0-1`, `fiber/v0.1.0-1`, ...).

## 4. Multi-module strategy

- Root `go.mod` is the core module.
- Each adapter directory has its own `go.mod`.
- During local development, adapters use `replace github.com/rachmanzz/rbacgo => ../`
  (or relative path) to depend on the local core.
- Releases use per-module version tags per Go multi-module conventions.

## 5. Installation commands (target)

```sh
go get github.com/rachmanzz/rbacgo@v0.1.0-1       # core engine
go get github.com/rachmanzz/rbacgo/http@v0.1.0-1  # stdlib / Chi
go get github.com/rachmanzz/rbacgo/fiber@v0.1.0-1 # Fiber v3
go get github.com/rachmanzz/rbacgo/echo@v0.1.0-1  # Echo v5
go get github.com/rachmanzz/rbacgo/gin@v0.1.0-1   # Gin v1
```

The first public release is the pre-release `v0.1.0-1`, so pin the version explicitly
(Go does not select pre-releases for `@latest`). All five commands are verified to work
end-to-end against the published tags.

## 6. Hard audit findings & remediation (2026-08-02)

Reference: full hard audit performed 2026-08-02 on the released `v0.1.0-1` state
(all 6 modules: core, 4 adapters, examples). Execution tracked in `phases.md` P5.

### 6.1 Verified clean (no action needed)

- **Toolchain:** all go.mod carry `go 1.25.7` + `toolchain go1.25.12`; tidy-clean, gofmt-clean.
- **CVEs:** `govulncheck` exit 0 on all 6 modules; only residual is GO-2026-5932
  (x/crypto openpgp — informational, `Fixed in: N/A`, never called) — documented in README.
- **Freshness:** all direct deps current (go-sqlite3 v1.14.49, go-redis v9.21.0,
  miniredis v2.38.0, pgx v5.10.0, Fiber v3.4.0, Echo v5.3.1, Gin v1.12.0).
- **Licenses:** MIT LICENSE; no MPL-2.0; THIRD_PARTY_NOTICES covers all runtime deps.
- **Tests:** core 83.9% (≥ 80%), adapters 100% incl. option-function tests, `-race` clean.
- **Benchmark:** 142.5 ns/op cache hit (claim 147 ns/op).
- **CI:** YAML valid; `-run TestSQLStorePostgres` matches; DSN CI (:5432) vs local (:5433) wired;
  `permissions: contents: read`.
- **Release:** all 5 tags identical to HEAD for publishable files (`*.go`, go.mod, go.sum);
  Postgres 17 integration PASS; no secrets/junk tracked.

### 6.2 Findings & planned fixes

| # | Finding | Severity | Fix | Status |
| --- | --- | --- | --- | --- |
| F1 | README "cycle detection" example cannot reach `ErrCycleDetected` — `admin{Parents:[editor]}` returns `ErrParentNotFound` first (parents must exist in both stores); no role-update API exists, so cycles are structurally impossible via the public API (defensive path only) | LOW | Rewrite example: show `ErrParentNotFound` rule; explain cycle check is defensive/internal | **Done** (P5.1) |
| F2 | README `sqlstore "github.com/rachmanzz/rbacgo" // or the store package` — no `store` subpackage exists | LOW | Remove misleading alias/comment | **Done** (P5.2) |
| F3 | `examples/go.mod` requires adapters at `v0.0.0` (works only via local `replace`) — inconsistent with pinned-release narrative | LOW | Pin `v0.1.0-1` + keep local replaces; `go mod tidy` | **Done** (P5.3) |
| F4 | `miniredis` (direct, test-only dep) absent from THIRD_PARTY_NOTICES; CI compliance grep checks only 5 names | LOW | Document policy (runtime deps only) in notices header; optionally extend CI grep (miniredis, pgx) | **Done** (P5.4) — miniredis + pgx now in notices AND CI grep; policy line added |
| F5 | CI actions pinned to tags (`checkout@v4`, `setup-go@v5`), no `timeout-minutes` | LOW (optional hardening) | Pin to SHA refs; add job timeouts | Deferred (optional) |
| F6 | Postgres service started for all 6 matrix rows, used only by core | INFO (optional) | Condition service to core row or split job | Deferred (optional) |
| F7 | `gap.md` benchmark figure 147 ns/op vs measured 142.5 ns/op | INFO | None (machine-dependent, still accurate) | Accepted |
| F8 | Root module indirect deps older than adapters (x/text v0.29.0 vs v0.40.0, x/sync v0.17.0 vs v0.22.0; x/net v0.56.0 vs v0.57.0) | INFO | None (indirect, no vulns, policy is direct-only; re-check at release) | Accepted |
| F9 | No `.gitignore` in repo | LOW | Add minimal `.gitignore` (binaries, coverage.out, .env, editor dirs) | **Done** (P5.5) |

## 7. Definition of Done

- Core engine test coverage ≥ 80%.
- Cycle detection verified by tests.
- Cache hit decision benchmark under 1 ms.
- Each adapter has at least one passing test and one runnable example.
- No breaking API changes without a major version bump.

## 8. Risk & Mitigation

| Risk | Mitigation |
| --- | --- |
| Framework API drift (Fiber v3, Echo v5 are recent) | Pin adapter deps; re-verify versions before release |
| Multi-module tag complexity | Follow Go multi-module release guide; script tags in CI |
| Redis cache consistency | TTL bounds; optional invalidation hooks |
| Over-grant via hierarchy | Cycle detection + tests asserting minimal privilege |

## 9. Open follow-ups

- Wildcard permissions (v2).
- ABAC policies (post-v1).
- Auto-reload of policies from SQL (post-v1).
