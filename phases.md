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
| P5 | Post-v1 Extensions | Wildcards, ABAC, auto-reload (future) | PRD §10, §11 |

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

## P4 — Examples, Docs & Release (v1.0)

**Reference:** PRD §10 M4, §12; plan M4; gap P2 items.

### Tasks
- [x] Runnable example per adapter under `examples/`.
- [x] README with install snippets and quick start.
- [x] godoc-quality doc comments on all exported symbols.
- Multi-module release tags (`http/v1.0.0`, `fiber/v1.0.0`, ...).
- Final version re-verification (Fiber v3, Echo v5, Gin v1).

### Acceptance criteria
- [x] Each adapter has a runnable example.
- Installation commands from plan.md §5 work end-to-end.
- Tags published per Go multi-module conventions.

---

## P5 — Post-v1 Extensions (future)

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
