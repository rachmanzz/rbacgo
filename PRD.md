# PRD — rbacgo: A Framework-Agnostic RBAC Library for Go

- **Status:** Draft
- **Author:** rbacgo team
- **Module path:** `github.com/rachmanzz/rbacgo`
- **Go version:** latest stable (2026)
- **Last updated:** 2026-08-02

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
  - **`http`** — standard library `net/http` middleware (also serves Chi users).
  - **fiber** — Fiber v2/v3.
  - **echo** — Echo v4.
  - **gin** — Gin v1.
- Allow **per-framework installation** so users pull only the packages they need.
- Provide **pluggable storage**:
  - SQL store as the primary persistent backend.
  - LRU cache layer backed by **in-memory** or **Redis**.
- Return customizable 401/403 responses from middleware.

### Non-Goals
- ABAC / attribute-based policy rules.
- Administration UI / dashboard.
- Per-field (column-level) authorization.
- A meta-package that re-exports every adapter (the `http` adapter is a standalone
  stdlib package, not an aggregator).
- Auto-policy-reload and live policy hot-swap (deferred to future work).

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
- Wildcard permissions are **out of scope** for v1; exact matching on `resource` + `action`
  is the only matching mode.

### Decision
The engine returns a boolean decision for `Enforce(userID, resource, action)`:
`true` if the subject holds any role whose effective permissions contain the pair.

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
  (e.g. `http/v1.0.0`, `fiber/v1.0.0`).

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
- **FR-3 — Enforcement:** `Enforce(userID, resource, action) bool` resolves the subject's
  effective roles and returns the decision.
- **FR-4 — Middleware (stdlib):** provide `http.Handler` middleware that runs the enforce
  check and returns **403 Forbidden** (or **401 Unauthorized** when unauthenticated) on
  denial; the response body/status handler must be customizable.
- **FR-5 — Middleware (adapters):** Fiber, Echo, and Gin adapters expose idiomatic middleware
  built on the same engine and customization points.
- **FR-6 — Storage interface:** a `Store` interface abstracts persistence; shipped
  implementations:
  - **SQL store (primary):** PostgreSQL/SQLite/MySQL-compatible schema for
    `roles`, `permissions`, `role_permissions`, `users`, `user_roles`,
    `role_hierarchy` (or adjacency via `parents`).
  - **LRU cache layer:** caches effective permission sets per user/role with configurable
    TTL and LRU eviction; backends: **in-memory** and **Redis**.
- **FR-7 — Concurrency safety:** engine and cache are safe for concurrent reads/writes.
- **FR-8 — Customizability:** allow custom 401/403 handlers, custom user-ID extraction from
  the request (header, JWT claim, session), and custom logger hooks.

---

## 7. Non-Functional Requirements

- **Performance:** cache hit decision under 1 ms; O(1) lookup via map + LRU on hot path.
- **Compatibility:** works with the latest stable Go release; core engine has **zero**
  third-party dependencies; adapters depend only on their framework + core.
- **Backward compatibility:** public API is additive only; no breaking changes without a
  major version bump.
- **Security:** hierarchy resolution must not over-grant; cycles rejected; no permission
  escalation via malformed input.
- **Testability & quality:** table-driven tests for engine/hierarchy/cycle detection; adapter
  tests using each framework's test utilities; coverage target ≥ 80% on the core engine.

---

## 8. Public API Draft

### Core engine

```go
package rbacgo

enforcer := rbacgo.New(
    rbacgo.WithSQLStore(db),        // primary persistence
    rbacgo.WithLRU(
        rbacgo.LRUBackendMemory(capacity, ttl),
        // or: rbacgo.LRUBackendRedis(redisClient, capacity, ttl),
    ),
)

enforcer.RegisterRole(rbacgo.Role{
    Name:        "editor",
    Permissions: []rbacgo.Permission{{Resource: "articles", Action: "write"}},
    Parents:     []string{"viewer"},
})

ok := enforcer.Enforce("user-123", "articles", "write") // true if permitted
```

### stdlib / Chi (`http` adapter)

```go
import "github.com/rachmanzz/rbacgo/http"

h := httpmiddleware.New(enforcer,
    httpmiddleware.WithResourceAction(func(r *http.Request) (string, string) {
        return resourceFromPath(r), r.Method
    }),
    httpmiddleware.WithUserID(func(r *http.Request) string {
        return userIDFromJWT(r) // your extraction logic
    }),
    httpmiddleware.WithDeniedHandler(my403Handler), // optional
)

mux.Handle("/articles", h(http.HandlerFunc(listArticles)))
```

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
- **Future (post-v1):** wildcard permissions, ABAC policies, auto-reload of policies from
  storage.

---

## 11. Open Questions / Future Work

- Wildcard matching (`resource:*`, `*:read`) — defer to v2.
- Attribute-based policies layered on roles.
- Auto-reload / hot-swap of policies from SQL without redeploy.
- Field/column-level authorization helpers.

---

## 12. Success Metrics

- Core engine test coverage ≥ 80%.
- Lookup performance with cache hit under 1 ms (benchmarked).
- Zero third-party dependencies in the core engine.
- At least one runnable example per adapter merged before v1.
- Adoptable API that is identical in spirit across all four adapters (same options,
  same semantics).
