# Work Phases — rbacgo

- **Status:** Draft
- **Purpose:** Divide ALL planned work (from AGENTS.md, PRD.md, plan.md, gap.md,
  limitation.md, decision-log.md) into clear, sequential work phases.
- **Last updated:** 2026-08-02

---

## Phase Overview

| Phase | Name | Goal | Milestone ref |
| --- | --- | --- | --- |
| P0 | Foundations & Repository Setup | Docs finalized, repo initialized, conventions locked | — |
| P1 | Core Engine + Storage | Framework-agnostic RBAC engine, Store interface, SQL store | plan M1 |
| P2 | LRU Cache Layer | Cache abstraction, in-memory + Redis backends | plan M2 |
| P3 | Adapters | stdlib http, Fiber v3, Echo v5, Gin v1 middlewares | plan M3 |
| P4 | Examples, Docs & Release | Runnable examples, README, godoc, version tags | plan M4 |
| P5 | Hard Audit Remediation | Close all LOW findings from the 2026-08-02 hard audit | plan §6 |
| P6 | Post-v1 Extensions | Wildcards, ABAC, auto-reload (future) | PRD §10, §11 |

---

## P0 — Foundations & Repository Setup

**Inputs:** AGENTS.md, all planning docs.
**Goal:** Frozen requirements, rules, and repo conventions before any code.

### Tasks
- [x] `AGENTS.md` — non-negotiable rules (ADR-007).
- [x] `PRD.md` — requirements, scope, architecture, API draft.
- [x] `plan.md` — milestones and implementation strategy.
- [x] `gap.md` — current-vs-target gap analysis, priorities.
- [x] `limitation.md` — known limitations and anti-goals.
- [x] `decision-log.md` — ADR-001..009.
- [x] `third-party.md` — dependency inventory, licenses, update policy, in-house LRU (ADR-008).
- [x] `phases.md` — this phase breakdown.
- [x] Re-verify framework versions (Fiber v3, Echo v5, Gin v1) before starting P3.
- [x] Confirm module path `github.com/rachmanzz/rbacgo` and repo access.
### Exit criteria
- [x] All docs consistent with each other.
- [x] Versions pinned/verified.
- [x] Any doc contradictions resolved before code starts.

---

## P1 — Core Engine + Storage (v0.1)

**Reference:** PRD §4, §6 (FR-1,2,3,6), §7; plan M1; gap P0 items.

### Tasks
- [x] Initialize root module `go.mod`.
- [x] Domain model: `Permission`, `Role`, `User` (PRD §4).
- [x] Enforcer: `Enforce(userID, resource, action) bool` (FR-3).
- [x] Role hierarchy resolution + **cycle detection** (FR-2, PRD §4).
- [x] `Store` interface (FR-6) + SQL store implementation — pluggable via user-supplied
  `*sql.DB` (pgx5/pgxpool/stdlib, go-sqlite3, or any `database/sql` driver).
- **Default store: embedded SQLite** — `rbacgo.New()` works zero-config (`:memory:`);
  file path supported for persistence.
- [x] Config from env (`WithConfigFromEnv`, prefix `RBAC_` default, `WithEnvPrefix` override) —
  store, SQLite path, cache capacity/TTL, Redis settings (FR-9, ADR-009).
- [x] In-memory cache; concurrency-safe engine (FR-7).
- [x] Table-driven tests: model, hierarchy, cycle detection, enforcement (≥ 80% core coverage).
- [x] Benchmarks for uncached lookup as baseline.

### Acceptance criteria
- [x] Enforcement returns correct decisions for direct + inherited permissions.
- [x] Cycles are rejected on registration.
- [x] `rbacgo.New()` works zero-config via embedded SQLite (`:memory:`); file-path persistence
  reloads state.
- [x] SQL store persists and reloads state.
- [x] All tests green; coverage ≥ 80%.

---

## P2 — LRU Cache Layer (v0.2)

**Reference:** PRD §6 FR-6, §7; plan M2; gap P1 items; limitation §3.

### Tasks
- [x] In-house LRU abstraction (capacity, TTL, eviction) — no external dep (ADR-008).
- [x] In-memory LRU backend.
- [x] Redis LRU backend.
- [x] Cache invalidation hooks on role/permission/assignment changes.
- [x] Integration tests: cache hit/miss, TTL expiry, eviction, invalidation.
- [x] Benchmark: cache hit decision **under 1 ms**.

### Acceptance criteria
- [x] Both backends pass the same behavior suite.
- [x] Invalidation propagates correctly in-memory and via Redis.
- [x] Cache-hit benchmark < 1 ms.

---

## P3 — Adapters (v0.3)

**Reference:** PRD §2 (Goals), §5 (Adapter relationship), §6 FR-4/5, §8; decision-log ADR-002/003.

### Tasks
- **stdlib `http` adapter** (also serves Chi):
  - `func(http.Handler) http.Handler` middleware.
  - User-ID extraction hook, resource/action extraction hook.
  - Customizable 401/403 handlers (FR-4).
- **Fiber v3 adapter** — idiomatic middleware, 403 JSON response (FR-5).
- **Echo v5 adapter** — idiomatic middleware, `echo.NewHTTPError` mapping (FR-5).
- **Gin v1 adapter** — idiomatic middleware, `AbortWithStatusJSON` mapping (FR-5).
- [x] Each adapter as its own `go.mod` module with `replace` to local core.
- [x] Adapter test suites using each framework's test utilities.

### Acceptance criteria
- [x] One passing test suite per adapter.
- [x] Consistent option API across adapters (same semantics, PRD §12).
- [x] 401 vs 403 behavior matches PRD §9.

---

## P4 — Examples, Docs & Release (v0.1.0-1)

**Reference:** PRD §10 M4, §12; plan M4; gap P2 items.

### Tasks
- [x] Runnable example per adapter under `examples/`.
- [x] README with install snippets and quick start.
- [x] godoc-quality doc comments on all exported symbols.
- [x] Multi-module release tags starting at `v0.1.0-1`
  (`http/v0.1.0-1`, `fiber/v0.1.0-1`, ...).
- [x] Final version re-verification (Fiber v3.4, Echo v5.3, Gin v1.12 — latest as of 2026-08-02).

### Acceptance criteria
- [x] Each adapter has a runnable example.
- [x] Installation commands from plan.md §5 work end-to-end.
- [x] Tags published per Go multi-module conventions.

---

## P5 — Hard Audit Remediation (v0.1.0-1)

**Reference:** plan §6 (hard audit 2026-08-02); AGENTS.md guards.
**Goal:** Close every LOW finding; keep changes additive-only; re-verify the release state.

### Tasks
- [x] **F1** — Rewrite README "Role hierarchy & cycle detection" example: `ErrParentNotFound`
      fires first when a parent is missing (both stores); `ErrCycleDetected` is a defensive
      path that cannot be reached through the public API (no role-update API).
- [x] **F2** — README: remove misleading `sqlstore "github.com/rachmanzz/rbacgo" // or the
      store package` (no `store` subpackage exists).
- [x] **F3** — `examples/go.mod`: pin adapters to `v0.1.0-1`, keep local `replace`; `go mod tidy`.
- [x] **F4** — `THIRD_PARTY_NOTICES`: add explicit policy line (test-only deps excluded,
      e.g. miniredis/pgx are direct go.mod deps but not redistributed); extend CI compliance
      grep to miniredis + pgx as a consistency guard.
- [x] **F9** — Add minimal `.gitignore` (binaries, `coverage.out`, `.env`, editor dirs).
- [x] **(optional) F5** — Pin CI actions to SHA refs; add `timeout-minutes` to jobs.
      Done: `actions/checkout@v4.4.0` + `actions/setup-go@v5.6.0` pinned to SHA; every job has
      `timeout-minutes`.
- [x] **(optional) F6** — Move Postgres service to the core matrix row only.
      Done: `test` job split into `test-core` (with PG service + integration test) and
      `test-adapters` (matrix http/fiber/echo/gin/examples, no service); `gofmt` runs once.
- [x] Re-verify all 6 modules: `go mod tidy -diff`, build, vet, `-race` tests, coverage
      (core ≥ 80%, adapters 100%), `govulncheck` (exit 0; GO-2026-5932 informational only),
      Postgres 17 integration test.
- [x] **R1** (P5.8) — Fix default `:memory:` SQLite store not being concurrency-safe
      (`SetMaxOpenConns(1)` + `SetMaxIdleConns(1)` in `newSQLiteStore`) + concurrent regression
      test `TestSQLiteMemoryConcurrentAccess` (verified to fail pre-fix with "no such table: roles").
- [x] **R2** (P5.9) — README: correct "defaults ... in-memory LRU work out of the box" → LRU is
      opt-in (`WithLRU`/`WithConfigFromEnv`).
- [x] **R3** (P5.10) — Add `.github/dependabot.yml` (weekly; gomod for all 6 modules + github-actions).
- [x] **R4** (P5.11) — Fix same `:memory:` pool bug in the env path (`STORE=sql` + `DATABASE_URL=:memory:`):
      cap the internally-created sqlite3 pool; regression test `TestConfigFromEnvSQLiteMemorySingleConnection`.
- [x] **R5** (P5.12) — Add `error_paths_test.go` to close the documented error-path coverage gaps
      (store-failure propagation, defensive cycle/missing-parent paths, SQL error paths, Redis
      JSON/scan errors, env error paths); core coverage 84.0% → 94.4% (collectRoleNames 100%).
- [x] **R6** (P5.13) — Drive core coverage to 100%: unexported `var sqlOpen = sql.Open` seam at the
      two call sites (`sqlite.go`, `env.go`) + `TestSQLOpenFailurePaths` (swaps it to force the three
      otherwise-unreachable `sql.Open` branches); scripted mock `database/sql` driver
      (`mock_driver_test.go`, zero new deps) for SQL defensive branches the real sqlite3 driver
      cannot produce (Scan column-count mismatch, rows iteration errors, BeginTx/query failures,
      in-tx roleExists errors, checkCycles cycle/recursion); `_query_only` DSN for migration-failure
      paths; core coverage 94.4% → **100.0%**.
- [x] Re-verify after round-2 fixes: build, vet, full `-race` suite (incl. new concurrent + error-path tests),
      coverage (core 100.0%), `go mod tidy -diff` (6/6), `govulncheck` (exit 0), Postgres 17 integration.
- [x] Commit + push — done: `4536507` pushed to `main` (R6, 2026-08-02, on explicit request).

### Bug audit round 3 (P5.14, 2026-08-02) — fix all findings
- [x] **B1** — `memoryStore.GetRole` deep copy (Permissions/Parents) + mutation/concurrent regression tests.
- [x] **B2** — README: Redis prefix must be unique per app/tenant (cross-app cache leak).
- [x] **B3** — `NewRedisLRU` nil-client fail-fast panic + test.
- [x] **B4** — `isMemoryDSN` (covers `:memory:` variants) in `newSQLiteStore` + env path; variant test.
- [x] **B5** — Recursion-depth limitation documented in limitation.md §3.
- [x] **B6** — `validRole` rejects whitespace-only names/resource/action; test case added.
- [x] **B7** — Nil-enforcer fail-fast panic in all 4 adapters + tests.
- [x] **B8** — Accepted as INFO (AssignRole not transactional; unreachable via public API).
- [x] **B9** — Redis `Flush` glob-escapes the prefix in the SCAN pattern + miniredis test.
- [x] Re-verify after bug audit: build, vet, full `-race` suite (6 modules), coverage, `go mod tidy -diff`,
      `govulncheck`, Postgres 17 integration.
- [x] Commit + push — done: `af5a258` pushed to `main` (round 3, 2026-08-02, on explicit request).

### Acceptance criteria (round 3)
- [x] All B1–B9 closed or explicitly accepted (B8 accepted as INFO); no regressions.
- [x] Docs consistent: plan §6.4, phases P5.14, limitation.md, README.

### Role management API (P5.15, 2026-08-02) — DeleteRole / UnassignRole

User-requested feature: delete roles and unassign them from users, gated by a
role-management capability. Design: plan §6.5, decision-log ADR-006.

- [x] `errors.go`: `ErrPermissionDenied`, `ErrRoleInUse`, `ErrUnsupported`.
- [x] `store.go`: optional interfaces `RoleDeleter` + `RoleUnassigner` (existing
      stores keep compiling unchanged; unsupported stores → `ErrUnsupported`).
- [x] `memory_store.go`: `DeleteRole` (not-found / in-use guards; deletes role and
      cascades the parent link out of child roles) + `UnassignRole` (not-found guard,
      idempotent no-op for unheld roles).
- [x] `sqlstore.go`: transactional `DeleteRole` (roleExists → roleInUse → cascade
      child links → own parents → permissions → role) + `UnassignRole`; new queries
      `roleInUse`, `deleteParentLinks`, `deleteRoleParents`, `deleteRolePerms`,
      `deleteRole`, `unassignRole`.
- [x] `options.go`: `WithRoleManagementPermission(resource, action)` — default
      `("roles", "manage")`, blank values rejected.
- [x] `enforcer.go`: `manageRes`/`manageAct` fields + `requireManagement` gate;
      `DeleteRole`/`UnassignRole` with cache invalidation (flush / target-user drop).
- [x] `role_mgmt_test.go`: gate denied / unsupported store / capability-check error,
      memory-store paths, SQL mock error paths, end-to-end flow with LRU cache,
      custom permission override; core coverage stays **100.0%**.
- [x] Postgres 17 integration: `UnassignRole`/`DeleteRole` flows incl. `ErrRoleInUse`,
      parent-cascade, capability gate, capability loss after delete.
- [x] README "Role management" section + plan §6.5.
- [ ] Final verification sweep (build, vet, `-race` 6 modules, coverage, `go mod tidy -diff`,
      `govulncheck`, Postgres 17 integration).
- [ ] Commit + push — **only on explicit user request** (AGENTS.md).

### PermissionView for frontend responses (P5.16, 2026-08-02)

User-approved design: `GET /me/permissions` payload with `user_id`, `roles`
(direct assignments), `permissions` (effective, deduplicated, sorted). Library
stays framework-agnostic — it produces the JSON-ready snapshot, not the HTTP
response.

- [x] `model.go`: `PermissionView` struct with `json` tags (`user_id`, `roles`, `permissions`).
- [x] `enforcer.go`: `PermissionView(ctx, userID)` — roles from `GetRoles`,
      effective set from `permissionsFor` (cache-aware), sorted + always
      non-nil (JSON `[]` / `{}` for empty users).
- [x] `permission_view_test.go`: flattened inheritance + sorted actions, exact
      JSON shape, empty user, cache path, store-error propagation; core
      coverage stays **100.0%**.
- [x] README "Exposing permissions to a frontend" + plan §6.6 + ADR-011.
- [ ] Final verification sweep (build, vet, `-race` 6 modules, coverage, `go mod tidy -diff`,
      `govulncheck`, Postgres 17 integration).
- [ ] Commit + push — **only on explicit user request** (AGENTS.md).

### SQL table prefix (P5.17, 2026-08-02)

User-requested: prefix all SQL table names so multiple apps/tenants can share
one database without collisions (mirrors the existing Redis key prefix).

- [x] `sqlstore.go`: `SQLStoreOption` + `WithTablePrefix` (identifier-safe
      validation: letters/digits/underscore, no leading digit); `NewSQLStore`
      now accepts options (variadic — backward compatible); `buildQueries`
      templates all 5 table names from the prefix.
- [x] `options.go`: `WithSQLStore(db, opts...)` passes SQLStoreOptions through.
- [x] `env.go`: `RBAC_SQL_TABLE_PREFIX` (STORE=sql only).
- [x] `table_prefix_test.go`: isolation of two prefixes on one SQLite file,
      prefixed-table creation, invalid prefixes rejected, env path valid +
      invalid; core coverage stays **100.0%**.
- [x] Postgres 17 integration: `WithTablePrefix("pg2_")` namespace on the same
      DB (isolation + enforcement); prefixed tables cleaned up.
- [x] README SQL store section + plan §6.7 + ADR-013.
- [ ] Final verification sweep (build, vet, `-race` 6 modules, coverage, `go mod tidy -diff`,
      `govulncheck`, Postgres 17 integration).
- [ ] Commit + push — **only on explicit user request** (AGENTS.md).

### policy_version for FE cache invalidation (P5.18, 2026-08-02)

User-approved: `PermissionView` carries a monotonic `policy_version` so
frontends detect policy changes by comparing one number instead of diffing
payloads (multi-tab / long-session refresh).

- [x] `enforcer.go`: `policyVersion atomic.Uint64` (race-safe); bumped only on
      successful mutations (RegisterRole / RegisterRoles per role / AssignRole
      / UnassignRole / DeleteRole) via `bumpPolicyVersion`.
- [x] `model.go`: `PermissionView.PolicyVersion` with `json:"policy_version"`.
- [x] `permission_view_test.go`: exact JSON shape incl. version, monotonic
      increment across the full mutation flow (failed mutations must NOT
      bump), concurrent reader/mutator race test; core coverage stays
      **100.0%**.
- [x] README (payload example + FE usage pattern) + plan §6.8 + ADR-014.
- [x] Final verification sweep (build, vet, `-race` 6 modules, coverage, `go mod tidy -diff`,
      `govulncheck`, Postgres 17 integration).
- [ ] Commit + push — **only on explicit user request** (AGENTS.md).

### shared policy_version for multi-instance (P5.19, 2026-08-02)

User-approved: in-memory `policy_version` cannot keep instances consistent, so
the version must live in shared storage — SQL (source of truth) **and** Redis —
exactly as user decided ("policy_version harus ada di db dan redis").

- [x] `store.go`: new optional interface `PolicyVersioner` (`PolicyVersion`,
      `NextPolicyVersion`) — custom stores may implement it without breaking
      changes (additive).
- [x] `sqlstore.go`: `meta` table (`key`/`value`), queries
      `policyVersion`/`nextPolicyVersion` (INSERT..ON CONFLICT..DO UPDATE
      table-qualified so Postgres accepts it), both methods on `sqlStore` —
      shared across every SQL instance on the same database; prefixed tables
      get a per-prefix `meta`.
- [x] `redis_policy_version.go` (new): `NewRedisPolicyVersion(client, key)` —
      dedicated `PolicyVersioner` over Redis `GET`/`INCR` (default key
      `rbacgo:policy_version`).
- [x] `options.go`: `WithPolicyVersionStore` (nil → error).
- [x] `enforcer.go`: `versionSource()` (explicit source wins, else store if it
      implements `PolicyVersioner`), `bumpPolicyVersion(ctx)` bumps the shared
      source first and falls back to the local counter on source error
      (best-effort — never fails an already-committed mutation),
      `currentPolicyVersion(ctx)` reads the source with local fallback.
- [x] `policy_version_shared_test.go` (new): SQL meta default (0/4), two
      SQLite instances over one file share the version, two memory-store
      instances share one Redis key, default-key + missing-key handling,
      `WithPolicyVersionStore(nil)`, failing-source error branches (stub
      `redis.Cmdable`), source-error fallback to local counter.
- [x] PG17 integration: meta tables added to cleanup; store and a second fresh
      instance agree on version after enforcer-level mutations.
- [x] Verification: core 100.0% coverage, `-race -count=3`, gofmt/vet clean,
      tidy clean, govulncheck clean, PG17 green, adapters green.
- [x] plan §6.9 + ADR-015.
- [ ] Commit + push — **only on explicit user request** (AGENTS.md).

### Fuzzing core invariants (P5.20, 2026-08-02)

User-approved: close the "100% coverage ≠ proof" gap with native Go fuzzing
(`testing.F`, stdlib only — no ffuf or other dependency needed).

- [x] `fuzz_test.go` (new): three targets with a deterministic PRNG seeded from
      the input bytes, so every corpus entry reproduces exactly:
  - `FuzzHierarchyResolution` — library `EnforceCtx` / `HasRole` /
    `PermissionView` must match an independent BFS oracle for arbitrary role
    graphs, names (incl. empty/space/unicode), and permissions.
  - `FuzzGraphSafety` — no panic, errors only from the documented sentinels,
    and any successfully registered graph stays acyclic.
  - `FuzzPolicyVersionMonotonic` — reported version always equals the count of
    successful mutations.
- [x] Fuzzing immediately caught a test-oracle bug (assign semantics):
      `AssignRole` is idempotent (duplicate = success, no state change, but
      still bumps `policy_version`); oracle now mirrors both behaviors and the
      regression is pinned.
- [x] Ran: ~1.9M execs total across the three targets (927K hierarchy / 478K
      safety / 444K version), all green.
- [x] CI job `fuzz`: 30 s per target per run.
- [x] Full suite stays green: coverage 100.0%, `-race`, gofmt/vet clean.
- [ ] Commit + push — **only on explicit user request** (AGENTS.md).

### Acceptance criteria
- [x] All F1–F9 items closed or explicitly accepted (F7, F8 = accepted as INFO).
- [x] Round-2 findings closed: R1 (sqlite `:memory:` concurrency fix + regression test),
      R2 (README cache claim), R3 (dependabot.yml), R4 (env-path `:memory:` concurrency fix),
      R5 (error-path coverage → 94.4%), R6 (core coverage → 100.0%).
- [x] No regressions; all verification sweeps green.
- [x] Docs consistent: README, plan §6, phases P5, gap.md, third-party.md.
- [x] Release tags `v0.1.0-1` remain identical for all publishable files.

---

## P6 — Post-v1 Extensions (future)

**Reference:** PRD §10 Future, §11; limitation §1; decision-log ADR-004.

### Tasks (not yet scheduled)
- Wildcard permissions (`resource:*`, `*:read`) — target v2.
- ABAC / attribute-based policies layered on roles.
- Auto-reload / hot-swap of policies from SQL.
- Per-field (column-level) authorization helpers.

### Trigger
- Driven by user request; each item must be scoped in a new PRD/ADR entry before work.

---

## Guards (applies to ALL phases)

- **AGENTS.md** rules are mandatory: high-care processing, no unauthorized changes,
  no over-assumption, additive-only changes, git operations only on explicit request.
- Update `decision-log.md` whenever a new decision is made.
- Update `gap.md` to reflect completed/remaining items after each phase.
- Re-check `limitation.md` for anything that changes scope.
