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
- **Tests:** core 100.0% (≥ 80%), adapters 100% incl. option-function tests, `-race` clean.
- **Benchmark:** 142.5 ns/op cache hit (claim 147 ns/op).
- **CI:** YAML valid; `-run TestSQLStorePostgres` matches; DSN CI (:5432) vs local (:5433) wired;
  `permissions: contents: read`.
- **Release:** all 5 tags identical to HEAD for publishable files (`*.go`, go.mod, go.sum);
  Postgres 17 integration PASS; no secrets/junk tracked.
- **Licenses (round 2):** full transitive graph re-scanned via `go list -m all` on all 5 published
  modules — zero MPL/GPL/LGPL/AGPL/unlicense; graph is MIT/BSD-2/BSD-3/Apache-2.0/ISC only.
- **govulncheck (round 2):** re-run on all 6 modules — all exit 0; GO-2026-5932 informational only.
- **Freshness (round 2):** all direct deps current; only indirect updates exist (fasthttp,
  gofiber/schema, gofiber/utils, x/sync, x/text, ...) — F8-class, no action.
- **No `+incompatible` modules; all pseudo-versions are legitimate upstream** (pgservicefile, chzyer/*).

### 6.2 Findings & planned fixes

| # | Finding | Severity | Fix | Status |
| --- | --- | --- | --- | --- |
| F1 | README "cycle detection" example cannot reach `ErrCycleDetected` — `admin{Parents:[editor]}` returns `ErrParentNotFound` first (parents must exist in both stores); no role-update API exists, so cycles are structurally impossible via the public API (defensive path only) | LOW | Rewrite example: show `ErrParentNotFound` rule; explain cycle check is defensive/internal | **Done** (P5.1) |
| F2 | README `sqlstore "github.com/rachmanzz/rbacgo" // or the store package` — no `store` subpackage exists | LOW | Remove misleading alias/comment | **Done** (P5.2) |
| F3 | `examples/go.mod` requires adapters at `v0.0.0` (works only via local `replace`) — inconsistent with pinned-release narrative | LOW | Pin `v0.1.0-1` + keep local replaces; `go mod tidy` | **Done** (P5.3) |
| F4 | `miniredis` (direct, test-only dep) absent from THIRD_PARTY_NOTICES; CI compliance grep checks only 5 names | LOW | Document policy (runtime deps only) in notices header; optionally extend CI grep (miniredis, pgx) | **Done** (P5.4) — miniredis + pgx now in notices AND CI grep; policy line added |
| F5 | CI actions pinned to tags (`checkout@v4`, `setup-go@v5`), no `timeout-minutes` | LOW (optional hardening) | Pin to SHA refs; add job timeouts | **Done** (P5.6) — checkout v4.4.0 + setup-go v5.6.0 pinned to SHA; `timeout-minutes` on all jobs |
| F6 | Postgres service started for all 6 matrix rows, used only by core | INFO (optional) | Condition service to core row or split job | **Done** (P5.7) — split `test` job into `test-core` (PG service) + `test-adapters` (matrix, no service) |
| F7 | `gap.md` benchmark figure 147 ns/op vs measured 142.5 ns/op | INFO | None (machine-dependent, still accurate) | Accepted |
| F8 | Root module indirect deps older than adapters (x/text v0.29.0 vs v0.40.0, x/sync v0.17.0 vs v0.22.0; x/net v0.56.0 vs v0.57.0) | INFO | None (indirect, no vulns, policy is direct-only; re-check at release) | Accepted |
| F9 | No `.gitignore` in repo | LOW | Add minimal `.gitignore` (binaries, coverage.out, .env, editor dirs) | **Done** (P5.5) |

### 6.3 Hard audit round 2 (2026-08-02, code-level)

Code-level audit of every source file (core + 4 adapters), driver docs in the module cache,
full module-graph license scan, and git hygiene. Execution tracked in `phases.md` P5 sub-tasks.

| # | Finding | Severity | Fix | Status |
| --- | --- | --- | --- | --- |
| R1 | Default `:memory:` SQLite store is not concurrency-safe: the database/sql pool may open a 2nd connection, which opens a **brand-new empty in-memory DB** ("no such table: roles" / silently missing data under concurrent access). Driver README confirms each `:memory:` connection is a separate DB. Violates the "concurrency-safe out of the box" claim (FR-7); tests passed only because they run sequentially | HIGH | `SetMaxOpenConns(1)` + `SetMaxIdleConns(1)` when DSN is `:memory:`; concurrent regression test (fails pre-fix with `no such table: roles`) | **Done** (P5.8) |
| R2 | README: "defaults (embedded `:memory:` SQLite + in-memory LRU) work out of the box" — plain `rbacgo.New()` enables **no** cache; LRU is opt-in (`WithLRU`/`WithConfigFromEnv`) | LOW | Reword README paragraph; clarify LRU opt-in | **Done** (P5.9) |
| R3 | third-party.md §4 recommends Dependabot/Renovate; no dependabot config present | LOW | Add `.github/dependabot.yml` (weekly; gomod for all 6 modules + github-actions) | **Done** (P5.10) |
| R4 | Same `:memory:` pool bug reachable via `RBAC_STORE=sql` + `RBAC_DATABASE_URL=:memory:` — env.go creates the `*sql.DB` internally (sqlite3 driver) without capping the pool | HIGH | Cap `SetMaxOpenConns(1)`/`SetMaxIdleConns(1)` for sqlite3 `:memory:` DSN in env.go; regression test `TestConfigFromEnvSQLiteMemorySingleConnection` (fails pre-fix with `opened 2 connections`) | **Done** (P5.11) |
| R5 | Error-path coverage gaps from round-2 audit (EnforceCtx 75%, collectEffective 76.5%, collectRoleNames 66.7%, checkCycles 73.1%, NewSQLStore 71.4%, sqlstore AddRole 70.4%, newSQLiteStore 72.7%, redisLRU Set 75%) | LOW (test gap) | Add `error_paths_test.go` covering store-failure propagation, injected-cycle/defensive paths, SQL error paths (closed DB + dropped tables + non-insertable view), Redis JSON/scan errors, env error paths; total coverage 84.0% → **94.4%** (collectRoleNames 100%) | **Done** (P5.12) |
| R6 | Final 3 uncovered statements are the `sql.Open` error branch (`New` default store, `WithConfigFromEnv` STORE=sql, `newSQLiteStore`) — unreachable because the sqlite3/pgx drivers are always registered (blank import). Remaining SQL defensive branches (Scan column-count mismatch, rows iteration errors, BeginTx/query failures, in-tx errors) are also unproducible with the real sqlite3 driver | LOW (test-only) | Add unexported `var sqlOpen = sql.Open` seam at the two call sites (`sqlite.go`, `env.go`) and `TestSQLOpenFailurePaths` swapping it to force failures; add a scripted mock `database/sql` driver (`mock_driver_test.go`, zero new deps) to exercise the SQL defensive branches; core coverage 94.4% → **100.0%** | **Done** (P5.13) |

### 6.4 Bug audit round 3 (2026-08-02, code + dynamic verification)

Line-by-line review of all production files (core + 4 adapters); candidates verified dynamically
(race detector, mutation probes). Execution tracked in `phases.md` P5.14.

| # | Finding | Severity | Fix | Status |
| --- | --- | --- | --- | --- |
| B1 | `memoryStore.GetRole` returns aliases to internal storage: caller mutation corrupts the store (verified: index-write persisted) and concurrent GetRole+mutation trips the race detector; violates the concurrency-safe contract | MEDIUM-HIGH | Return a deep copy (Permissions/Parents slices); regression tests incl. concurrent copy test | **Done** (P5.14) |
| B2 | Redis cache prefix default `rbacgo:cache:` shared by multiple apps on one Redis → cached permission sets leak across applications (authorization leak) | MEDIUM (docs/ops) | README warning: unique prefix per app/tenant required | **Done** (P5.14) |
| B3 | `NewRedisLRU(nil, ...)` panics on first use (nil-interface call) instead of failing fast at construction | LOW | Nil-guard with clear panic message + test | **Done** (P5.14) |
| B4 | Single-connection cap for in-memory SQLite applied only to exact DSN `":memory:"`; `file:memdb1?mode=memory` / `file::memory:` bypass it (per-connection DBs, same R1 symptom) | LOW (edge) | `isMemoryDSN` helper (contains `:memory:` or `mode=memory`) used in `newSQLiteStore` and the env path; variant regression test | **Done** (P5.14) |
| B5 | Hierarchy traversal is recursive (`collectEffective`, `collectRoleNames`, `checkCycles`, `detectCycle`); pathological deep chains can exhaust the stack | LOW (pathological) | Documented in limitation.md §3 | **Done** (P5.14) |
| B6 | `validRole` accepted whitespace-only names (`" "`) and whitespace-padded resource/action | LOW | `strings.TrimSpace` validation; test case added | **Done** (P5.14) |
| B7 | Adapters panic deep inside the request path on a nil `*Enforcer` | LOW | Fail-fast `panic("rbacgo: nil enforcer")` in all 4 constructors + tests | **Done** (P5.14) |
| B8 | `sqlStore.AssignRole` not transactional (exists-check + 2 inserts) | INFO | Not reachable via public API (no role-delete API); no action | Accepted |
| B9 | Redis `Flush` SCAN pattern uses the raw prefix; glob metacharacters (`[`, `*`, `?`, `\`) in a prefix would match wrong keys | INFO (edge) | Glob-escape prefix in the SCAN pattern; miniredis regression test | **Done** (P5.14) |

### 6.5 Role management API (2026-08-02, feature)

User-requested extension: **DeleteRole** + **UnassignRole**, gated by a
role-management capability. Design decisions (see decision-log ADR-006):

- Deletion is capability-gated: only callers holding the management permission
  (default `("roles", "manage")`, configurable via `WithRoleManagementPermission`)
  may delete/unassign roles; others get `ErrPermissionDenied`.
- Optional store interfaces `RoleDeleter` / `RoleUnassigner` keep existing
  custom stores source-compatible; unsupported stores report `ErrUnsupported`.
- Assigned roles are protected: `DeleteRole` fails with `ErrRoleInUse` until
  every assignment is removed (unassign first).
- Deleting a parent role cascades: child roles lose the deleted role from their
  parent list (own permissions and assignments untouched).
- Cache semantics: `DeleteRole` flushes the whole lookup cache; `UnassignRole`
  drops only the target user's entry.
- Execution tracked in `phases.md` P5.15; core coverage stays 100.0%.

### 6.6 Frontend permission payload (2026-08-02, feature)

User-approved design for exposing access rights to a frontend as a
framework-agnostic JSON snapshot (`Enforcer.PermissionView`):

- `PermissionView{user_id, roles, permissions}` — `roles` = direct
  assignments; `permissions` = effective set (own + inherited) flattened to
  `resource -> sorted actions`, deduplicated.
- Cache-aware: reuses `permissionsFor`, so LRU/Redis caching applies.
- Deterministic output: actions and roles sorted; empty users serialize as
  `[]` / `{}` (never `null`).
- Security stance: the payload is a UX hint for menus/route guards; every
  protected endpoint must still `Enforce` server-side, and identity must come
  from the session, not the request body.
- Execution tracked in `phases.md` P5.16; decision-log ADR-011.

### 6.7 SQL table prefix (2026-08-02, feature)

User-requested: namespace SQL tables per application/tenant sharing one DB
(mirrors the Redis key prefix):

- `WithTablePrefix(prefix)` SQLStoreOption — validated identifier fragment
  (letters/digits/underscore, no leading digit; empty = default names).
- Applied via `NewSQLStore(db, opts...)` / `WithSQLStore(db, opts...)`
  (variadic, backward compatible) and `RBAC_SQL_TABLE_PREFIX` env var.
- All 5 tables (`roles`, `role_permissions`, `role_parents`, `users`,
  `user_roles`) and every query are built from the prefix; migration creates
  the prefixed tables.
- Execution tracked in `phases.md` P5.17; decision-log ADR-013.

### 6.8 policy_version (2026-08-02, feature)

User-approved: FE-friendly policy change detection for `PermissionView`:

- `policy_version` field in the snapshot: monotonic counter incremented on
  every successful policy mutation (RegisterRole, AssignRole, UnassignRole,
  DeleteRole); failed mutations never bump it.
- Stored as `atomic.Uint64` in the Enforcer (concurrency-safe); FE compares
  the number across snapshots and re-renders only on change.
- In-memory counter = consistent for the instance serving the endpoint;
  multi-instance consistency is solved by §6.9 (shared source) without
  changing the JSON contract.
- Execution tracked in `phases.md` P5.18; decision-log ADR-014.

### 6.9 shared policy_version for multi-instance (2026-08-02, feature)

User-approved ("policy_version harus ada di db dan redis"): the counter must
be consistent across instances, so it lives in shared storage:

- New optional interface `store.PolicyVersioner` (`PolicyVersion(ctx)`,
  `NextPolicyVersion(ctx)`); `sqlStore` implements it over a `meta` table
  (one row per `policy_version`), so every SQL instance on the same database
  shares one counter (per table-prefix).
- New `NewRedisPolicyVersion(client, key)` (default key `rbacgo:policy_version`)
  implements it over Redis `GET`/`INCR` for deployments that use Redis.
- `Enforcer` picks its source via `WithPolicyVersionStore`, otherwise the
  store when it implements `PolicyVersioner`, and falls back to the local
  in-memory counter whenever the shared source errors (best-effort bump;
  a committed mutation never fails because of the version bookkeeping).
- API additive: custom stores that do not implement `PolicyVersioner` keep
  working unchanged (local counter).
- Execution tracked in `phases.md` P5.19; decision-log ADR-015.

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
