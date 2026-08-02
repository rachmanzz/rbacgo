# Decision Log — rbacgo

- **Status:** Draft
- **Format:** ADR-style entries, newest last
- **Last updated:** 2026-08-02

---

## ADR-001 — Monorepo with per-framework Go modules

- **Date:** 2026-08-02
- **Status:** Accepted

### Context
The library must be installable per-framework (fiber, echo, chi, gin, stdlib) so users pull
only what they need.

### Decision
Use a monorepo where the repo root is the core module (`github.com/rachmanzz/rbacgo`) and
each adapter directory (`http/`, `fiber/`, `echo/`, `gin/`) is its own Go module with a
separate `go.mod`. Releases use per-module version tags (e.g. `http/v0.1.0-1`).

### Alternatives considered
- Single module with subpackages — simpler, but no independent versioning per adapter.
- Separate repos per adapter — more repo/CI overhead, harder to keep engine in sync.

### Consequences
- Users install only the adapter they need (`go get github.com/rachmanzz/rbacgo/fiber`).
- Requires `replace` directives during local development and multi-module tagging discipline.

---

## ADR-002 — `http` adapter is stdlib middleware, not an aggregator

- **Date:** 2026-08-02
- **Status:** Accepted

### Context
Earlier drafts called the non-framework adapter "universal" and described it as re-exporting
all adapters.

### Decision
The package is a standalone adapter built on the standard library `net/http` — it wraps the
core engine in a `func(http.Handler) http.Handler` middleware. It serves plain `net/http`
users and Chi users directly (Chi is built on `net/http`). It does **not** aggregate or
re-export the Fiber/Echo/Gin adapters.

### Consequences
- Zero framework dependencies for stdlib users.
- Chi gets no dedicated adapter; users import `rbacgo/http`.
- Framework adapters each map the engine decision to their own context/error conventions.

---

## ADR-003 — Supported framework versions: Fiber v3, Echo v5, Gin v1 latest, http latest

- **Date:** 2026-08-02
- **Status:** Accepted

### Context
Framework majors are shifting (Fiber v3 GA in 2026-02, Echo v5 GA in 2026-01).

### Decision
Target only the current majors, verified online on 2026-08-02:
- Fiber v3 (v3.4.x)
- Echo v5 (v5.3.x)
- Gin v1 latest (v1.12.x)
- `net/http` (latest Go stdlib)

Older majors (Fiber v2, Echo v4) are explicitly not supported.

### Consequences
- Cleaner adapter code, no legacy compatibility branches.
- Users on older framework majors must upgrade to use the adapters.

---

## ADR-004 — Feature scope: Core RBAC + role hierarchy

- **Date:** 2026-08-02
- **Status:** Accepted

### Context
Scope needed a decision among core-only, hierarchy, wildcards, and ABAC-like policies.

### Decision
v1 includes core RBAC (roles, permissions, user-role assignment) plus **role hierarchy**
(parent/child inheritance) with cycle detection. Wildcards, ABAC, and per-field authz are
explicitly deferred (wildcards to v2).

### Consequences
- More expressive than core-only; reduced permission duplication via inheritance.
- Adds hierarchy resolution complexity; mitigated by cycle detection and effective-set caching.

---

## ADR-005 — Pluggable storage: SQL primary + LRU cache (in-memory/Redis)

- **Date:** 2026-08-02
- **Status:** Accepted

### Context
Permission data needs persistence and fast lookups; storage must be replaceable.

### Decision
- Define a `Store` interface.
- Ship a **SQL store** (PostgreSQL- and SQLite-compatible schema) as the primary persistent
  backend. The SQL store is **pluggable at the driver/pool level**: it accepts a
  user-supplied `*sql.DB`, so users keep their own driver and pool — `pgx`/`pgxpool`
  (via the pgx `stdlib` adapter) for PostgreSQL, `go-sqlite3` for SQLite, or any other
  `database/sql` implementation.
- Ship an **LRU cache layer** with configurable TTL and eviction, backed by **in-memory** or
  **Redis**.
- **Default store: embedded SQLite** (`:memory:` unless a file path is given) when no store
  is configured — zero-setup for users, persistent on demand.

### Consequences
- Zero-config default: `rbacgo.New()` works out of the box (embedded SQLite, no external
  server); scalable PostgreSQL + Redis available for production.
- Requires a stable `Store` interface and concurrency-safe design.
- Users are free to customize connection pooling, drivers, and settings (e.g. `pgxpool`
  settings) without waiting on rbacgo.
- Cache coherence bounded by TTL; explicit invalidation hooks recommended.

**Amendment (2026-08-02):** the SQL store's PostgreSQL dialect is now covered by an
integration test (`sqlstore_postgres_test.go`, `//go:build integration`, run against a real
PostgreSQL 17). It surfaced and fixed a real dialect bug: the recursive cycle-check issued
queries on an open transaction while rows were still open, which PostgreSQL rejects with
"conn busy" (SQLite tolerated it). `checkCycles` now collects parents and closes rows before
recursing.

---

## ADR-006 — Go version target: latest stable

- **Date:** 2026-08-02
- **Status:** Accepted

### Context
Need a minimum/expected Go toolchain for the library.

### Decision
Target the latest stable Go release (2026). The core engine logic keeps **zero** third-party
dependencies (stdlib only); the module ships optional backends — embedded SQLite (`go-sqlite3`)
and Redis cache (`go-redis`) — which are the module's only third-party dependencies. Adapters
depend only on their framework plus the core module.

**Amendment (2026-08-02):** toolchain pinned to **`go 1.25.7` + `toolchain go1.25.12`** in all
`go.mod` files (root, adapters, examples). `go 1.25.7` is the minimum supported version; the
`toolchain` directive forces builds onto the CVE-patched `go1.25.12` (fixes the 2026 stdlib
toolchain CVEs: GO-2026-5856/5037/4971/4947/4946/4870/4602/4601) via `GOTOOLCHAIN=auto`
without raising the minimum Go requirement.

### Consequences
- Can use modern stdlib features; no legacy compatibility burden.
- Users must be on a recent Go toolchain to consume the adapters.

---

## ADR-009 — Environment configuration with default prefix `RBAC_`

- **Date:** 2026-08-02
- **Status:** Accepted

### Context
Users deploy rbacgo across environments (dev/staging/prod) and want store/cache settings
without recompiling.

### Decision
- Provide environment-variable configuration for all store/cache settings.
- Default prefix: **`RBAC_`** (e.g. `RBAC_STORE`, `RBAC_SQLITE_PATH`, `RBAC_CACHE`,
  `RBAC_CACHE_TTL`, `RBAC_REDIS_ADDR`).
- Prefix is configurable via `WithEnvPrefix("X_")` so users can namespace per app/service.
- Env values are read **once at construction time** (`WithConfigFromEnv()`); explicit
  options passed to `New` take precedence over env vars.
- Implementation uses only the Go stdlib (`os`, `strconv`, `time`) — no new dependencies
  (ADR-006, ADR-008).

### Alternatives considered
- Hot-reload of env config at runtime — rejected; adds complexity and race risk.
- No env support (programmatic only) — rejected; forces redeploys for environment changes.

### Consequences
- Twelve-factor style deployment support out of the box.
- Precedence rule documented: explicit options > env vars > defaults.
- No auto-reload; restart required to pick up env changes.

---

## ADR-008 — Third-party policy: latest versions, MIT-compatible only; in-house LRU

- **Date:** 2026-08-02
- **Status:** Accepted

### Context
Dependencies must always be on the latest stable version and their licenses must be
compatible with rbacgo's MIT license. Two candidates were MPL-2.0 (weak copyleft):
`hashicorp/golang-lru` and `go-sql-driver/mysql`.

### Decision
- Document all third-party libraries, pinned versions, and licenses in `third-party.md`.
- Keep every direct dependency on the **latest** stable release (Dependabot/Renovate +
  `go get -u`, re-verify before release).
- **LRU cache is implemented in-house** (small, fixed-capacity, TTL-aware). Reject
  `hashicorp/golang-lru` (MPL-2.0) — keeps the cache layer MIT-only and the core engine
  logic dependency-free (ADR-006).
- Core engine logic stays at **zero** third-party dependencies (stdlib only). The module's
  only third-party dependencies are the optional backends: embedded SQLite (`go-sqlite3`)
  and Redis cache (`go-redis`); `miniredis` is test-only.
  **Amendment (2026-08-02):** the earlier "zero-dependency module" wording was inaccurate —
  the core engine *logic* is dependency-free, not the module as a whole.
  **Amendment 2 (2026-08-02):** `pgx` v5.10.0 (`github.com/jackc/pgx/v5`) added as a
  **test-only** dependency for the PostgreSQL integration test
  (`sqlstore_postgres_test.go`, `//go:build integration`), which was validated against a real
  PostgreSQL 17 server. It is not imported by any runtime code.
- `go-sql-driver/mysql` (MPL-2.0): **removed (2026-08-02).** MySQL is **not** supported;
  the SQL store targets PostgreSQL and SQLite only.

### Alternatives considered
- `hashicorp/golang-lru` (MPL-2.0) — rejected due to license policy.
- `karlseguin/ccache` (MIT) — viable, but in-house keeps zero-dep and full control.

### Consequences
- Cache behavior fully under our control; no MPL code in the repo.
- No MySQL support; PostgreSQL + SQLite (both MIT) are the only SQL backends.

---

## ADR-007 — Non-negotiable repository rules (AGENTS.md)

- **Date:** 2026-08-02
- **Status:** Accepted

### Context
Repository-wide behavior rules for AI agents and contributors.

### Decision
Maintain `AGENTS.md` with mandatory rules: high-care processing, no unauthorized changes,
no over-assumption, never reduce/break features (additive-only unless explicitly approved),
and git operations only on explicit user request.

### Consequences
- Any future work in this repo must honor these constraints.
- This decision log and all planning docs live in the repo root for traceability.

## ADR-010 — Capability-gated role management (DeleteRole / UnassignRole)

- **Date:** 2026-08-02
- **Status:** Accepted
- **Reference:** plan §6.5, phases P5.15

### Context
User-requested feature: delete roles and unassign roles from users. Deleting a
role is privileged, so it must not be callable by arbitrary users.

### Decision
- Add `Enforcer.DeleteRole(userID, roleName)` and
  `Enforcer.UnassignRole(userID, targetUserID, roleName)`, both gated by a
  **role-management capability**: the caller must hold the permission
  `("roles", "manage")` by default, overridable per-enforcer via
  `WithRoleManagementPermission(resource, action)`.
- Capability is checked with the normal enforcement pipeline
  (`EnforceCtx`), so it composes with hierarchy and caching.
- Stores opt in through optional interfaces `RoleDeleter` / `RoleUnassigner`;
  stores that do not implement them return `ErrUnsupported` (backward
  compatible — no breaking change to `Store`).
- A role still assigned to any user cannot be deleted (`ErrRoleInUse`);
  `UnassignRole` must be called first. Deleting a parent role cascades the
  parent link out of child roles.
- Cache invalidation: `DeleteRole` flushes all cached permission sets;
  `UnassignRole` drops only the target user's entry.

### Consequences
- Role management requires an explicit capability role (e.g. `("roles",
  "manage")`); without one, all delete/unassign calls return
  `ErrPermissionDenied`.
- Custom `Store` implementations continue to compile and work; the new
  operations simply report `ErrUnsupported` there.

## ADR-011 — PermissionView: framework-agnostic frontend permission payload

- **Date:** 2026-08-02
- **Status:** Accepted
- **Reference:** plan §6.6, phases P5.16

### Context
Frontends need the user's effective access rights to render menus, hide
buttons, and guard routes. rbacgo is framework-agnostic, so it must not write
HTTP responses.

### Decision
- Add `Enforcer.PermissionView(ctx, userID) PermissionView` returning a
  JSON-ready snapshot: `{"user_id", "roles", "permissions"}`.
- `roles` = directly assigned roles; `permissions` = effective set (own +
  inherited) flattened to `resource -> sorted actions`, deduplicated, cache
  aware.
- Deterministic serialization: roles/actions sorted; empty sets serialize as
  `[]`/`{}` (never `null`).
- The payload is a UX hint only: every protected endpoint must still
  `Enforce` server-side, and the user identity must come from the
  authenticated session, never from the request body.

### Consequences
- Apps implement their own HTTP handler (one `Encode` call) on top of
  `PermissionView`; the library stays framework-free.
- Frontend logic must never be treated as an authorization decision.

## ADR-013 — SQL table prefix (WithTablePrefix)

- **Date:** 2026-08-02
- **Status:** Accepted
- **Reference:** plan §6.7, phases P5.17

### Context
Multiple applications or tenants sharing one database collide on the fixed
table names (roles, role_permissions, ...). The Redis cache already supports a
key prefix; the SQL store did not.

### Decision
- Add `SQLStoreOption` with `WithTablePrefix(prefix)`; applied through
  variadic `NewSQLStore(db, opts...)` and `WithSQLStore(db, opts...)`
  (backward compatible — existing call sites unchanged) and the
  `RBAC_SQL_TABLE_PREFIX` env var (STORE=sql only).
- The prefix is validated as a safe identifier fragment (letters, digits,
  underscore; must not start with a digit) because it is interpolated into
  SQL as a table-name identifier; empty prefix keeps the default names.
- All queries and the schema migration are built from the prefixed names.

### Consequences
- Table-name collisions are solved per store, keeping the store API and
  `Store` interface untouched.
- Invalid prefixes fail fast at construction (or env-config time), before any
  SQL runs.

## ADR-014 — policy_version in PermissionView

- **Date:** 2026-08-02
- **Status:** Accepted
- **Reference:** plan §6.8, phases P5.18

### Context
Frontends cache the permission payload and need cheap change detection to
refresh menus/routes when the policy changes elsewhere (admin actions, other
tabs). Diffing a large permission object on every render is wasteful and
error-prone.

### Decision
- Add `policy_version` (uint64) to `PermissionView`, monotonically incremented
  on every successful policy mutation: RegisterRole (and per-role within
  RegisterRoles), AssignRole, UnassignRole, DeleteRole. Failed mutations never
  bump it.
- Held as `atomic.Uint64` in the Enforcer, so concurrent reads and mutations
  are race-free.
- The FE contract is one number: store it, compare it, re-render on change.
  ETag/304 optimization is left to the app; the JSON contract stays stable.
- The counter is in-memory: consistent for the instance serving the endpoint.
  Multi-instance deployment can replace the source of the number later without
  changing the payload contract.

## ADR-015 — shared policy_version (SQL meta + Redis)

- **Date:** 2026-08-02
- **Status:** Accepted
- **Reference:** plan §6.9, phases P5.19

### Context
ADR-014 kept the counter in-memory per instance. In a multi-instance
deployment each Enforcer then reports a different `policy_version` for the
same policy state, defeating change detection. User decision: the version
must be shared — "policy_version harus ada di db dan redis".

### Decision
- Introduce optional interface `store.PolicyVersioner` with
  `PolicyVersion(ctx) (uint64, error)` and
  `NextPolicyVersion(ctx) (uint64, error)`.
- `sqlStore` implements it over a `meta` table using
  `INSERT ... ON CONFLICT(key) DO UPDATE SET value = meta.value + 1 RETURNING meta.value`
  (table-qualified so Postgres does not reject the column as ambiguous).
  Every SQL instance on the same database reads the same counter; a per-prefix
  `meta` table keeps prefixed schemas self-contained.
- `NewRedisPolicyVersion(client, key)` implements the same interface with
  Redis `GET`/`INCR` (default key `rbacgo:policy_version`) for deployments
  already using Redis — the same key shared across instances.
- `Enforcer` resolution order: explicit `WithPolicyVersionStore` → store if it
  implements `PolicyVersioner` → local `atomic.Uint64` fallback.
- Bumping is best-effort: the shared source is bumped first, but a source
  error silently falls back to the local counter — a committed policy mutation
  must never fail because of version bookkeeping. Reads also fall back to the
  local counter so `PermissionView` never errors on a transient source failure.
- The earlier idea of mirroring the counter through the generic Redis LRU
  cache was rejected: `redisLRU.Get` unmarshals into `permissionSet` only and
  `Flush` clears every key, so the dedicated `RedisPolicyVersion` is used
  instead.
- Contract unchanged: the JSON still exposes one `policy_version` number.


### Consequences
- FE change detection becomes trivial and reliable; multi-tab staleness is
  detectable without polling.
- The payload gains one field; existing consumers must ignore unknown
  top-level fields (JSON-compatible).
