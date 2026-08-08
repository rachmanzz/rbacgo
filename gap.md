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
| Tests | **Done** | ≥ 80% core coverage (83.9%), adapter suites (100%), Postgres integration test, benchmarks (147 ns/op cache hit) | ✅ Complete |
| Docs | **Done** | README, THIRD_PARTY_NOTICES, LICENSE, godoc, install snippets | ✅ Complete |
| CI | **Done** | `.github/workflows/ci.yml`: build/vet/race per module, Postgres integration, `govulncheck`, compliance (LICENSE + notices + direct-deps freshness) | ✅ Complete |
| Version verification | **Done** | Fiber v3.4, Echo v5.3, Gin v1.12; published `v0.1.0-1` + per-adapter tags | ✅ Complete |
| Release tags | **Done** | `v0.1.0-1`, `http/v0.1.0-1`, `fiber/v0.1.0-1`, `echo/v0.1.0-1`, `gin/v0.1.0-1` (verified end-to-end) | ✅ Complete |

## 3. Priority order

All P0–P4 items are complete and the first pre-release (`v0.1.0-1`) is published. Remaining
follow-ups:

1. **Stable release** — tag `v0.1.0` (drop `-1`) once the pre-release is validated; no code
   changes expected.
2. **Re-verify** — adapter versions + licenses before each release (`go list -m -u`,
   `govulncheck`, Dependabot/Renovate).

## 4. Things that block progress

- None at this time. Framework versions to target are already verified and the first
  pre-release (`v0.1.0-1`) is published.
- Future blocker to watch: Echo v5 and Fiber v3 are relatively new majors; their APIs may
  shift within 2026. Re-verify pinned adapter versions before tagging.

## 5. Anti-goals (intentionally out of scope)

- ABAC / attribute-based policies.
- Administration UI.
- Per-field authorization.
- An aggregator package that re-exports all adapters.
- Wildcard permissions (v2) — design agreed (ADR-024): exact → `resource:*` → `*:action`
  → `*:*`; `*:*` = superadmin role.
- Role metadata (`Metadata map[string]string`) — ADR-024.
