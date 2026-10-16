# PRD — rbacgo: A Framework-Agnostic RBAC Library for Go

- **Status:** Draft
- **Author:** rbacgo team
- **Module path:** `github.com/rachmanzz/rbacgo`
- **Go version:** all modules minimum 1.26.0; toolchain 1.27.2
- **Last updated:** 2026-10-16

---

## 1. Overview & Problem Statement

Authorization logic is almost always duplicated across Go web frameworks. A team building
services on Echo, Fiber, Gin, and plain `net/http` ends up re-implementing role checking,
middleware, and 403 handling four times, with subtle differences in behavior and API.

`rbacgo` solves this by providing a single, reusable Role-Based Access Control engine that is
completely framework-agnostic, plus thin adapters for the most common HTTP frameworks. Users
install only the adapter they need.

**What this library does not do:** it does not try to unify the frameworks under one
abstraction layer. Each adapter follows the conventions of its framework while sharing the same
core engine and storage.

---

## 2. Goals & Non-Goals

### Goals
- Provide a framework-agnostic RBAC engine (roles, permissions, user-role assignment).
- Support role **hierarchy** (parent/child inheritance) with cycle detection.
- Ship standalone adapters for:
  - **`http`** — standard library `net/http` middleware (latest Go release, also serves Chi users).
  - **fiber** — Fiber v3 only (see fiber/go.mod for the tested version).
  - **echo** — Echo v5 only (see echo/go.mod for the tested version).
  - **gin** — Gin v1 (see gin/go.mod for the tested version).
- Older framework versions (e.g. Fiber v2, Echo v4) are **not** supported; users must
  upgrade to the listed majors to use the adapters.
- Allow **per-framework installation** so users pull only the packages they need.
- Provide **pluggable storage**:
  - SQL store as the primary persistent backend.
  - LRU cache layer backed by **in-memory** or **Redis**.
- Return customizable 401/403 responses from middleware.

### Non-Goals
- An arbitrary policy scripting language or external attribute-fetching engine.
- Administration UI / dashboard.
- Per-field (column-level) authorization.
- A meta-package that re-exports every adapter (the `http` adapter is a standalone
  stdlib package, not an aggregator).
- Automatic database change watching for edits made outside the Enforcer APIs.

---

## 3. Target Users & Personas

- **Go API developer on net/http or Chi** — wants a plain `http.Handler` middleware with no
  framework dependency.
- **Go API developer on Fiber/Echo/Gin** — wants idiomatic middleware that plugs into the
  framework's context and error model.
- **Platform / auth team** — wants one shared RBAC engine + SQL persistence used consistently
  across multiple services regardless of framework.

---

## 4. Core Concepts & Domain Model

### Permission
A capability to perform an **action** on a **resource**.

```go
type Permission struct {
    Resource string // e.g. "users", "orders"
    Action   string // e.g. "read", "write", "delete"
}
```

### Role
A named set of permissions. A role may inherit from one or more **parent roles**; the
effective permission set is the union of its own permissions and all ancestors' permissions.

```go
type Role struct {
    Name        string
    Permissions []Permission
    Parents     []string // role names this role inherits from
}
```

### User / Subject
Identified by an ID (string) and assigned zero or more roles.

```go
type User struct {
    ID    string
    Roles []string
}
```

### Role Hierarchy & Cycle Detection
- Permission lookup resolves the transitive closure of role parents (BFS/DFS).
- The engine rejects or fails registration of a role graph that contains a cycle
  (e.g. `admin -> editor -> admin`) to guarantee termination of the resolution algorithm.
- Exact resource/action matching remains the default. WithWildcardPermissions
  enables complete-field star matching in the order exact, resource/star,
  star/action, star/star. WithPolicyRules adds inherited attribute allow/deny
  rules; any matching deny overrides allows, including superadmin.

### Decision
The engine returns a boolean decision for `Enforce(ctx, userID, resource, action)`.
Default mode checks the effective ordinary permission set; optional wildcard and
attribute rules extend matching. Deny wins, and errors fail closed. EnforceCtx
also reports underlying errors, including audit persistence failures.

---

## 5. Architecture (Monorepo)

### Repository layout

```
rbacgo/
├─ go.mod            # core engine module (github.com/rachmanzz/rbacgo)
├─ rbac/             # model, enforcer, role hierarchy resolution
├─ store/            # Store interface + SQL store + LRU wrapper
├─ http/  (go.mod)   # stdlib net/http middleware (also serves Chi)
├─ fiber/ (go.mod)   # Fiber adapter
├─ echo/  (go.mod)   # Echo adapter
├─ gin/   (go.mod)   # Gin adapter
└─ examples/         # runnable examples per adapter
```

### Multi-module strategy
- The repo root is the **core module**: `github.com/rachmanzz/rbacgo`.
- Each adapter directory (`http/`, `fiber/`, `echo/`, `gin/`) is its **own Go module** with a
  separate `go.mod`, enabling independent versioning and per-framework installation.
- During local development, adapter modules use a `replace` directive pointing at the core
  module; releases are tagged with version suffixes per Go multi-module conventions
  (e.g. `http/v0.1.0-1`, `fiber/v0.1.0-1`).

### Per-framework installation
```sh
# stdlib / net/http users (also Chi):
go get github.com/rachmanzz/rbacgo/http

# framework-specific:
go get github.com/rachmanzz/rbacgo/fiber
go get github.com/rachmanzz/rbacgo/echo
go get github.com/rachmanzz/rbacgo/gin

# core engine only:
go get github.com/rachmanzz/rbacgo
```

### Adapter relationship
- The `http` adapter is **not** an aggregator. It is a standalone package that wraps the core
  engine in a `func(http.Handler) http.Handler` middleware. Chi users reuse it directly
  because Chi is built on `net/http`.
- Fiber/Echo/Gin adapters map the engine decision onto their own context/error
  conventions (e.g. `ctx.Status(403).JSON(...)` for Fiber, `echo.NewHTTPError` for Echo,
  `c.AbortWithStatusJSON` for Gin).

---

## 6. Functional Requirements

- **FR-1 — Registration:** register roles, permissions, and user-role assignments through the
  engine and/or storage.
- **FR-2 — Role hierarchy:** a role may declare parent roles; permission resolution includes
  inherited permissions; cycles are detected and rejected.
- **FR-3 — Enforcement:** `Enforce(ctx, userID, resource, action) bool` resolves the subject's
  effective roles and returns the decision.
- **FR-4 — Middleware (stdlib):** provide `http.Handler` middleware that runs the enforce
  check and returns **403 Forbidden** (or **401 Unauthorized** when unauthenticated) on
  denial; the response body/status handler must be customizable.
- **FR-5 — Middleware (adapters):** Fiber, Echo, and Gin adapters expose idiomatic middleware
  built on the same engine and customization points.
- **FR-6 — Storage interface:** a `Store` interface abstracts persistence; shipped
  implementations:
  - **SQL store (primary):** PostgreSQL- and SQLite-compatible schema for
    `roles`, `role_permissions`, `role_parents`, `role_assignments`,
    `meta`, `role_rules`, and `role_metadata`. No own `users` table —
    user IDs are opaque strings in `role_assignments` (ADR-016/017). **Driver/pool integration:** the store accepts an existing
    `*sql.DB`. PostgreSQL and SQLite are auto-detected; MySQL syntax is selected explicitly.
    Drivers tested include pgx/stdlib, go-sqlite3, and go-mysql-org/go-mysql in
    its separate integration module. Other drivers require application verification,
    and other dialects require a custom Store.
  - **Default store: SQLite (embedded).** When no store is configured, the engine uses an
    embedded SQLite store — `:memory:` by default (zero setup), or a file path for
    persistence.
  - **Lookup cache:** effective permission sets per user. The in-memory backend
    is a bounded LRU with TTL; Redis uses TTL and server-configured eviction.
- **FR-7 — Concurrency safety:** engine and cache are safe for concurrent reads/writes.
- **FR-8 — Customizability:** allow custom 401/403 handlers, custom user-ID extraction from
  the request (header, JWT claim, session), and optional standard-library
  `slog` logging through `WithLogger` for permission lookup, invalidation publish,
  and shared policy-version failures. Logging is disabled by default.
- **FR-9 — Environment configuration:** the listed store/cache settings are configurable via
  environment variables. Variables use the default prefix **`RBAC_`** (configurable via
  `WithEnvPrefix("X_")`), read once at construction time:

  | Env var | Default | Purpose |
  | --- | --- | --- |
  | `RBAC_STORE` | `sqlite` | `sqlite`, `sql` (user-supplied `*sql.DB`), `memory` |
  | `RBAC_SQLITE_PATH` | `:memory:` | SQLite DSN / file path |
  | `RBAC_DATABASE_URL` | — | PostgreSQL URL (pgx) or SQLite DSN for STORE=sql |
  | `RBAC_SQL_TABLE_PREFIX` | — | SQL table prefix for STORE=sql |
  | `RBAC_CACHE` | `memory` | `memory`, `redis`, `none` |
  | `RBAC_CACHE_CAPACITY` | `1024` | LRU capacity |
  | `RBAC_CACHE_TTL` | `5m` | Cache TTL (Go duration string) |
  | `RBAC_REDIS_ADDR` | `localhost:6379` | Redis address |
  | `RBAC_REDIS_PASSWORD` | — | Redis password (optional) |
  | `RBAC_REDIS_DB` | `0` | Redis DB index |

---

## Feature extensions (implemented, unreleased)

- Opt-in wildcard permissions and inherited allow/deny attribute rules. Deny
  wins, including against superadmin; missing deny facts conservatively fail
  closed. Supported JSON condition operators are documented in the feature guide.
- Descriptive role metadata through separate persistence capabilities, preserving
  Role's original struct layout. Metadata does not authorize access.
- ApplyPolicyBatch atomically changes policy data in memory/SQL stores. Cache,
  audit, and best-effort version work follow commit; decisions are not atomic
  multi-query policy snapshots.
- Optional Metrics snapshots and durable AuditSink events. The built-in local
  file sink fsyncs each acknowledged event; audit failure denies authorization
  and marks already-committed mutations explicitly.
- Bounded registries, automatic idle eviction, context factories, request leases,
  and terminal resource cleanup through Shutdown.
- Explicit MySQL dialect and shard-aware Redis Cluster flushing. Neither cluster
  invalidation nor pub/sub promises instantaneous distributed revocation.

See docs/feature-guide.md for contracts, examples, ownership, and limitations.

## 7. Non-Functional Requirements

- **Performance target:** warm in-memory cache hits under 1 ms in a documented
  benchmark workload; no universal latency guarantee. Cache hits use constant-time
  lookup/LRU bookkeeping; misses traverse the role graph and Redis adds network I/O.
- **Compatibility:** CI selects Go 1.27.2 (all modules minimum 1.26.0); the core engine logic has **zero**
  third-party dependencies (stdlib only). The module ships optional backends — embedded SQLite
  (`go-sqlite3`) and Redis cache (`go-redis`) — which are the module's only third-party
  runtime dependencies; test dependencies are listed in third-party.md. Backend
  usage is optional, but these packages remain dependencies of the root module.
  Adapters add their framework dependencies. Adapter compatibility matrix —
  Fiber **v3**, Echo **v5**, Gin **v1**, `net/http` (pinned CI toolchain).
- **Backward compatibility:** public API is additive only; no breaking changes without a
  major version bump.
- **Security:** hierarchy resolution must not over-grant; cycles rejected; no permission
  escalation via malformed input.
- **Testability & quality:** table-driven tests for engine/hierarchy/cycle detection; adapter
  tests using each framework's test utilities; coverage target ≥ 80% on the core engine.

---

## 8. Public API

### Core engine

```go
package main

import (
    "context"
    "log/slog"
    "os"

    "github.com/rachmanzz/rbacgo"
)

func main() {
    ctx := context.Background()
    enforcer, err := rbacgo.New(
        rbacgo.WithTenant("acme"),
        rbacgo.WithLogger(slog.New(slog.NewJSONHandler(os.Stderr, nil))),
    )
    if err != nil { panic(err) }
    defer enforcer.Shutdown(ctx)
    // Trusted provisioning; authenticate and authorize callers before exposing it.
    if err := enforcer.RegisterRole(ctx, rbacgo.Role{
        Name: "editor",
        Permissions: []rbacgo.Permission{{Resource: "articles", Action: "write"}},
    }); err != nil { panic(err) }
    if err := enforcer.AssignRole(ctx, "user-123", "editor"); err != nil { panic(err) }
    _ = enforcer.Enforce(ctx, "user-123", "articles", "write")
}
```

`WithSQLStore(db, opts...)` accepts a caller-owned PostgreSQL or SQLite pool;
`WithSQLite(path)` selects file persistence. `WithConfigFromEnv()` configures
the listed environment settings; `WithTenant` remains required.
Use `WithLRU(NewMemoryLRU(capacity, ttl))` or
`WithLRU(NewRedisLRU(client, prefix, ttl))` for explicit cache configuration.

`RegisterRole`, `RegisterRoles`, `AssignRole`, and `ListRoles` are trusted
APIs with no actor authorization. Their `*As` variants require the actor's
configured role-management capability, as do `UpdateRole`, `DeleteRole`, and
`UnassignRole`. The application must authenticate actors and validate tenant
membership. Batch registration stops at its first error without rollback.

`EnforceOwned`/`EnforceOwnedCtx` add `self`, `grp`, and `any` scope checks.
`PermissionView` provides a frontend snapshot; its best-effort `policy_version`
is an invalidation hint, not an atomic revision or a push notification.

### stdlib / Chi (`http` adapter)

```go
import httpadapter "github.com/rachmanzz/rbacgo/http"

h := httpadapter.New(enforcer,
    httpadapter.WithResourceAction(func(r *http.Request) (string, string) {
        return resourceFromPath(r), r.Method
    }),
    httpadapter.WithUserID(func(r *http.Request) (string, bool) {
        id := userIDFromJWT(r)
        return id, id != ""
    }),
    httpadapter.WithDeniedHandler(my403Handler),
)
mux.Handle("/articles", h(http.HandlerFunc(listArticles)))
```

Each adapter shares the core TenantRegistry with optional capacity, idle TTL,
factory cancellation/timeouts, and middleware leases. Evict/ClearAndClose drain
leases before cleanup; Shutdown also rejects new acquisitions and stops the
janitor. Clear retains forget-only semantics. Context deadlines bound waits.
Caller-owned resources remain separate; see docs/feature-guide.md.

### Framework adapters (illustrative)

```go
// fiber
app.Use(fiberadapter.Middleware(enforcer, fiberadapter.WithUserID(...)))

// echo
e.Use(echoadapter.Middleware(enforcer, echoadapter.WithUserID(...)))

// gin
r.Use(ginadapter.Middleware(enforcer, ginadapter.WithUserID(...)))
```

---

## 9. Error Handling & Response Format

- **401 Unauthorized:** returned when no authenticated subject can be resolved from the
  request (no user ID). 
- **403 Forbidden:** returned when the subject is authenticated but lacks the required
  permission.
- **Default response:** JSON body `{"error": "forbidden"}` with the matching status code.
- **Customization:** users may override the denied/unauthorized handlers per adapter; the
  engine itself never writes HTTP responses — only middleware does.

---

## 10. Milestones & Roadmap

- **M1 — Core engine + storage (v0.1):** model, hierarchy + cycle detection, `Enforce`,
  `Store` interface, SQL store, in-memory cache.
- **M2 — LRU cache layer (v0.2):** shared LRU abstraction, in-memory and Redis backends,
  TTL + eviction.
- **M3 — Adapters (v0.3):** `http` (stdlib/Chi), Fiber, Echo, Gin middlewares + per-framework
  response customization.
- **M4 — Examples & docs (v1.0):** runnable examples per adapter, README, godoc, release
  tags with per-module versioning.
- **Future:** automatic detection of out-of-band policies from
  storage.

---

## 11. Open Questions / Future Work

- Opt-in wildcard matching is implemented (ADR-026); path globs/regex are not.
- Metadata is implemented through separate APIs/capabilities (ADR-026), keeping
  Role's original layout. The earlier field-based proposal is superseded.
- Superadmin uses opt-in `*:*` matching and remains subject to deny rules.
- Attribute conditions and deny rules are implemented; arbitrary scripting is not.
- Detecting direct/out-of-band SQL changes automatically remains outside scope;
  supported mutations are available without redeploy.
- Field/column-level authorization helpers.

---

## 12. Success Metrics

- Core engine test coverage ≥ 80%.
- Lookup performance with cache hit under 1 ms (benchmarked).
- Zero third-party dependencies in the core engine logic (the optional SQLite and Redis
  backends are the module's only third-party dependencies).
- At least one runnable example per adapter merged before v1.
- Adoptable API that is identical in spirit across all four adapters (same options,
  same semantics).
