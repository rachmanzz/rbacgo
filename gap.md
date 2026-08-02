# Gaps Analysis — rbacgo

- **Status:** Draft
- **Last updated:** 2026-08-02

## 1. Purpose

Document the gap between the current repository state and the target defined in `PRD.md`
and `plan.md`, so work can be prioritized and tracked.

## 2. Current state vs target

| Area | Current state | Target (PRD/plan) | Gap |
| --- | --- | --- | --- |
| Core engine (`rbac/`) | Not started | Model, enforcer, hierarchy + cycle detection | Implement from scratch |
| Storage (`store/`) | Not started | `Store` interface, SQL store (**default embedded SQLite**), LRU (memory/Redis) | Implement from scratch |
| Config (`WithConfigFromEnv`) | Not started | Env config with default prefix `RBAC_` (FR-9, ADR-009) | Implement |
| `http` adapter | Not started | stdlib middleware (serves Chi) | Implement |
| `fiber` adapter | Not started | Fiber v3 middleware | Implement |
| `echo` adapter | Not started | Echo v5 middleware | Implement |
| `gin` adapter | Not started | Gin v1 middleware | Implement |
| Multi-module layout | Single repo, no modules | Root `go.mod` + per-adapter `go.mod` | Initialize modules |
| Examples | None | Runnable examples per adapter | Write |
| Tests | None | ≥ 80% core coverage, adapter suites, benchmarks | Write |
| CI | None | Release tags, build/test pipeline (future) | Set up |
| Docs | `AGENTS.md`, `PRD.md` + this set | README, godoc, install snippets | Write |
| Version verification | Done for PRD (Fiber v3.4, Echo v5.3, Gin v1.12) | Keep in sync | Re-verify before release |

## 3. Priority order

1. **P0** — Init modules; core engine + `Store` interface + SQL store (M1).
2. **P0** — Role hierarchy + cycle detection (M1).
3. **P1** — LRU cache layer, in-memory + Redis backends (M2).
4. **P1** — `http` adapter (M3).
5. **P2** — Fiber/Echo/Gin adapters (M3).
6. **P2** — Examples, README, release tags (M4).

## 4. Things that block progress

- None at this time. Framework versions to target are already verified.
- Future blocker to watch: Echo v5 and Fiber v3 are relatively new majors; their APIs may
  shift within 2026. Re-verify pinned adapter versions before tagging.

## 5. Anti-goals (intentionally out of scope)

- ABAC / attribute-based policies.
- Administration UI.
- Per-field authorization.
- An aggregator package that re-exports all adapters.
- Wildcard permissions (v2).
