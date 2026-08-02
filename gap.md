# Gaps Analysis — rbacgo

- **Status:** Draft
- **Last updated:** 2026-08-02

## 1. Purpose

Document the gap between the current repository state and the target defined in `PRD.md`
and `plan.md`, so work can be prioritized and tracked.

## 2. Current state vs target

| Area | Current state | Target (PRD/plan) | Gap |
| --- | --- | --- | --- |
| Core engine | **Done** (root package `rbacgo`) | Model, enforcer, hierarchy + cycle detection | ✅ Complete |
| Storage | **Done** | `Store` interface, SQL store (**default embedded SQLite**), LRU (memory/Redis) | ✅ Complete |
| Config (`WithConfigFromEnv`) | **Done** | Env config with default prefix `RBAC_` (FR-9, ADR-009) | ✅ Complete |
| `http` adapter | **Done** | stdlib middleware (serves Chi) | ✅ Complete |
| `fiber` adapter | **Done** | Fiber v3 middleware | ✅ Complete |
| `echo` adapter | **Done** | Echo v5 middleware | ✅ Complete |
| `gin` adapter | **Done** | Gin v1 middleware | ✅ Complete |
| Multi-module layout | **Done** | Root `go.mod` + per-adapter `go.mod` | ✅ Complete |
| Examples | **Done** (`examples/`) | Runnable examples per adapter | ✅ Complete |
| Tests | **Done** | ≥ 80% core coverage (84.3%), adapter suites, benchmarks (147 ns/op cache hit) | ✅ Complete |
| Docs | **Done** | README, THIRD_PARTY_NOTICES, godoc, install snippets | ✅ Complete (godoc polish before tag) |
| CI | None | Release tags, build/test pipeline (future) | Set up before release |
| Version verification | Done (Fiber v3.4, Echo v5.3, Gin v1.12) | Keep in sync | Re-verify before release |

## 3. Priority order

All P0–P4 items are complete. Remaining before v1.0 release:

1. **CI** — build/test pipeline, dependency freshness + vulnerability check
   (`govulncheck`, `go list -m -u`), `THIRD_PARTY_NOTICES` generation step.
2. **Release** — per-module version tags (`http/v1.0.0`, `fiber/v1.0.0`, ...).
3. **Re-verify** — adapter versions + licenses before tagging (Fiber v3, Echo v5,
   Gin v1).

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
