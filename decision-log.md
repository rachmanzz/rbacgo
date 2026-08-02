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
separate `go.mod`. Releases use per-module version tags (e.g. `http/v1.0.0`).

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

---

## ADR-006 — Go version target: latest stable

- **Date:** 2026-08-02
- **Status:** Accepted

### Context
Need a minimum/expected Go toolchain for the library.

### Decision
Target the latest stable Go release (2026). Core engine keeps **zero** third-party
dependencies; adapters depend only on their framework plus the core module.

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
  dependency-free (ADR-006).
- Core engine module stays at **zero** third-party dependencies.
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
