# rbacgo

A framework-agnostic RBAC (Role-Based Access Control) library for Go, with thin
adapters for the most popular HTTP frameworks.

`rbacgo` gives you a single, reusable authorization engine — roles, permissions,
role hierarchy, and user-role assignment — plus idiomatic middleware for
`net/http`, Fiber v3, Echo v5, and Gin v1. Install only the adapter you need;
each one wraps the same core engine and storage.

## Features

- **Framework-agnostic core** — the engine logic is stdlib-only (zero third-party
  dependencies); the module ships optional SQLite and Redis backends.
- **Role hierarchy** — a role can inherit from parent roles; effective
  permissions are the union of all ancestors. Cycles are detected and rejected.
- **Pluggable storage** — SQL store (PostgreSQL / SQLite / any `database/sql`
  driver, pluggable at the pool level) and an in-memory store.
- **Default store: embedded SQLite** — `rbacgo.New()` works out of the box
  (`:memory:`), or point it at a file for persistence.
- **LRU cache layer** — in-memory and Redis backends with TTL and eviction.
- **Environment configuration** — `RBAC_`-prefixed env vars (configurable
  prefix), read once at construction.
- **Consistent adapter API** — the same options and semantics across `http`,
  `fiber`, `echo`, and `gin` adapters.

## Installation

Install only what you need:

```sh
# core engine only
go get github.com/rachmanzz/rbacgo@v0.1.0-1

# stdlib / net/http users (also Chi)
go get github.com/rachmanzz/rbacgo/http@v0.1.0-1

# framework-specific
go get github.com/rachmanzz/rbacgo/fiber@v0.1.0-1   # Fiber v3
go get github.com/rachmanzz/rbacgo/echo@v0.1.0-1    # Echo v5
go get github.com/rachmanzz/rbacgo/gin@v0.1.0-1     # Gin v1
```

> The first public release is the pre-release **`v0.1.0-1`**, so pin the version
> explicitly (Go does not select pre-releases for `@latest`). Once a stable
> `v0.1.x` is tagged, plain `go get github.com/rachmanzz/rbacgo/http` works too.

Each adapter is its own Go module with independent versioning
(`http/v0.1.0-1`, `fiber/v0.1.0-1`, ...).

## Quick start

Zero-config: `rbacgo.New()` uses an embedded SQLite store in memory. Every
enforcer is scoped to a **tenant** (organization, workspace, app…) with
`WithTenant`; roles, users, and cache entries are namespaced by it, so one
shared store can serve many tenants without cross-tenant access.

```go
package main

import (
	"context"
	"fmt"

	"github.com/rachmanzz/rbacgo"
)

func main() {
	ctx := context.Background()

	enforcer, err := rbacgo.New(rbacgo.WithTenant("acme"))
	if err != nil {
		panic(err)
	}

	// Roles with hierarchy: editor inherits viewer's permissions.
	enforcer.RegisterRole(ctx, rbacgo.Role{
		Name:        "viewer",
		Permissions: []rbacgo.Permission{{Resource: "articles", Action: "read"}},
	})
	enforcer.RegisterRole(ctx, rbacgo.Role{
		Name:        "editor",
		Permissions: []rbacgo.Permission{{Resource: "articles", Action: "write"}},
		Parents:     []string{"viewer"},
	})
	enforcer.AssignRole(ctx, "user-123", "editor")

	fmt.Println(enforcer.Enforce(ctx, "user-123", "articles", "read"))  // true  (inherited)
	fmt.Println(enforcer.Enforce(ctx, "user-123", "articles", "write")) // true  (own)
	fmt.Println(enforcer.Enforce(ctx, "user-123", "articles", "delete")) // false
}
```

## Owned permissions: `self`, `grp`, `any`

Create/update/delete checks often depend on **who owns the resource** and
**which group it belongs to**. Beyond exact `resource` + `action` matching,
an action may carry a scope:

| Permission                    | Meaning                                                              |
|-------------------------------|----------------------------------------------------------------------|
| `"article:delete"`            | **any** — delete any article, whoever owns it, any group             |
| `"article:delete:any"`        | same as the plain permission (explicit alias)                        |
| `"article:delete:self"`       | **self** — delete articles owned by the caller                       |
| `"article:delete:grp:hr"`     | **group** — delete articles of the `hr` group (department, team, ...)|
| `"article:create:self"`       | behaves like plain `create` (creation has no owner)                  |
| `"article:create:grp:hr"`     | create articles into the `hr` group only                             |

`EnforceOwned` decides with the resource's context passed per call — the
owner and the group:

```go
ok, err := enforcer.EnforceOwnedCtx(ctx, "user-123", article.Owner, article.Group, "article", "delete")
// ok == true when user-123 holds "article:delete" (any),
//        or owns the article AND holds "article:delete:self",
//        or the article's group is "hr" AND user-123 holds "article:delete:grp:hr".
```

Rules: a plain (or `:any`) permission wins over scoped ones — holding it
grants the operation everywhere. Any matching scope grants (`:self` and
`:grp:` compose: own resources anywhere, or group resources from anyone).
An empty owner never satisfies `:self`, and an empty group never satisfies
`:grp:` (both compared exactly). Querying a literal `"update:self"` through
`Enforce` is exact matching and ignores owner/group. `EnforceOwned` and
`EnforceOwnedCtx` exist like `Enforce`/`EnforceCtx` (the former treats store
errors as deny).

## Tenants

An Enforcer is scoped to exactly one tenant, and `WithTenant` is **required**
— `New` returns `ErrTenantRequired` without it. The tenant id can be anything
your application uses to identify an organization, workspace, or project.

- Roles, users, assignments, and cache keys are namespaced by the tenant
  inside the backing store; names API stays clean (`"viewer"`, not
  `"acme:viewer"`).
- One store can serve many tenants — `Store()` instances are shared by
  constructing multiple enforcers with the same store:
  ```go
  store := rbacgo.NewMemoryStore() // or one SQL store / DB per deployment
  acme, _ := rbacgo.New(rbacgo.WithTenant("acme"), rbacgo.WithStore(store))
  globex, _ := rbacgo.New(rbacgo.WithTenant("globex"), rbacgo.WithStore(store))
  acme.RegisterRole(ctx, rbacgo.Role{Name: "viewer", ...})
  globex.RegisterRole(ctx, rbacgo.Role{Name: "viewer", ...}) // same name, no clash
  ```
* Roles and assignments belong to the tenant's admin/owner: tenant A can
  never read, assign, unassign, or delete tenant B's roles even on a shared
  store — isolation is enforced by the library, not by calling convention.
* `TenantID()` returns the tenant of an enforcer.
* For 100+ isolated organizations prefer **one Enforcer per tenant** (memory
  store or SQLite file each), or a shared SQL database with a table prefix
  per tenant for stricter physical separation.

## Role hierarchy & cycle detection

Roles may declare parent roles. The engine resolves the transitive closure when
checking permissions. Two rules keep the hierarchy acyclic:

1. **Parents must already exist** — a role referencing a missing parent is rejected
   with `ErrParentNotFound`.
2. **Updates are in-place** — `UpdateRole` replaces permissions and parent
   links but never renames; the role name is the identity, so parents always
   reference stable names.

Together these make cycles *structurally impossible* through the public API. The
engine still ships a defensive cycle check (`detectCycle` in `memory_store.go` /
`checkCycles` in `sqlstore.go`) that guards the stores against direct manipulation.

```go
if err := enforcer.RegisterRole(ctx, rbacgo.Role{Name: "viewer"}); err != nil {
	panic(err)
}
err := enforcer.RegisterRole(ctx, rbacgo.Role{Name: "admin", Parents: []string{"missing"}})
// err == rbacgo.ErrParentNotFound  (parent must be registered first)
```

## Role management

Roles can be updated, deleted, unassigned from users, and enumerated. Because
mutations are privileged, they require the caller to hold a
**role-management capability**: the permission `("roles", "manage")` by
default (override with `WithRoleManagementPermission("acl", "manage")`). A
caller without the capability gets `ErrPermissionDenied`.

```go
// Only callers holding ("roles", "manage") may run these.
err := enforcer.UpdateRole(ctx, "admin-user", Role{
	Name:        "editor",
	Permissions: []Permission{{Resource: "/articles", Action: "DELETE"}},
	Parents:     []string{"viewer"},
})
// ErrParentNotFound   -> a parent does not exist
// ErrCycleDetected    -> the new parents would close a hierarchy cycle
// ErrPermissionDenied -> caller lacks the role-management capability

roles, err := enforcer.ListRoles(ctx) // all roles of this tenant, sorted

err := enforcer.DeleteRole(ctx, "admin-user", "editor")
// ErrRoleInUse  -> editor is still assigned to at least one user
// ErrPermissionDenied -> caller lacks the role-management capability

err = enforcer.UnassignRole(ctx, "admin-user", "user-123", "editor")
if err != nil {
	// ErrRoleNotFound when the role does not exist
}

err = enforcer.DeleteRole(ctx, "admin-user", "editor") // now succeeds
```

Rules:

1. **Update is an in-place replace** — the permissions and parent links of the
   role identified by `Name` are swapped atomically; the name itself cannot
   change (renaming is delete-and-recreate). Failed updates (missing parent,
   cycle, store error) roll back completely.
2. **Delete is protected** — a role still assigned to any user cannot be deleted
   (`ErrRoleInUse`). Unassign it first.
3. **Deleting a parent cascades** — child roles automatically lose the deleted
   role from their parent list; their own permissions and assignments remain.
4. **Cache invalidation** — successful mutations flush the whole lookup cache;
   unassignments drop the target user's cache entry immediately.
5. **Store support** — `UpdateRole`/`DeleteRole`/`UnassignRole`/`ListRoles` are
   optional store capabilities (`RoleUpdater`/`RoleDeleter`/`RoleUnassigner`/
   `RoleLister` interfaces). Stores that do not implement them report
   `ErrUnsupported`, so existing custom stores keep working unchanged.
6. **Listing is tenant-scoped** — `ListRoles` returns only the roles of the
   enforcer's tenant, with names and parents returned unscoped.

## Exposing permissions to a frontend

The library is framework-agnostic, so it returns a ready-to-serialize snapshot
instead of writing HTTP responses. `Enforcer.PermissionView` builds the
effective access rights of a user — directly assigned roles plus the
deduplicated permission set (own + inherited, sorted) — for a
`GET /api/v1/me/permissions` endpoint:

```go
view, err := enforcer.PermissionView(ctx, "user-123")
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(view) // in real apps: never return raw errors
```

```json
{
  "user_id": "user-123",
  "roles": ["editor"],
  "permissions": {
    "/articles": ["GET", "POST"],
    "/comments": ["GET"]
  },
  "policy_version": 3
}
```

`policy_version` increments on every successful policy mutation (role
registration, assignment, unassignment, deletion). Frontends store the version
next to the payload and re-render only when it changes — no payload diffing
needed, and multi-tab sessions detect stale access rights automatically:

```js
if (payload.policy_version !== lastVersion) {
  saveVersion(payload.policy_version)
  renderUI(payload)
}
```

By default the version is held in memory per instance. In multi-instance
deployments the counter is shared instead, so every instance reports the same
value for the same policy state:

- **SQL** — the source of truth: `sqlStore` keeps the counter in a `meta`
  table, so all instances on the same database agree automatically; no extra
  configuration needed.
- **Redis** — for deployments already using Redis, point all instances at the
  same key:

```go
version := rbacgo.NewRedisPolicyVersion(redisClient, "rbacgo:policy_version")
enforcer, err := rbacgo.New(
	rbacgo.WithStore(store),
	rbacgo.WithPolicyVersionStore(version),
)
```

If the shared source is unreachable the enforcer falls back to its local
counter; version bookkeeping never fails a policy mutation.

The frontend may use this payload to render menus, hide buttons, and guard
routes — but the backend must still call `Enforce` on every protected action;
the payload is a UX hint, not a security decision. Identity must come from the
authenticated session, never from the request body.

## Middleware adapters

All adapters share the same options: user-ID extraction (`WithUserID` —
**required**: the middleware does not read HTTP headers; the ID must come from
your auth layer, e.g. session, JWT claims, or auth middleware context),
resource/action derivation (default: URL path + HTTP method), and customizable
401/403 responses.

### Per-tenant middleware

The single-tenant middlewares gate every request with one fixed Enforcer. For
multi-tenant deployments (the documented pattern of one Enforcer per tenant
sharing one store), every adapter also ships a **per-tenant variant**: a
`TenantRegistry` lazily creates and caches one Enforcer per tenant (the
factory runs at most once per tenant, even under concurrent first requests),
and the middleware resolves the tenant from each request, fetches its
Enforcer, stores both in the request context, and enforces with the tenant's
Enforcer:

```go
import httpadapter "github.com/rachmanzz/rbacgo/http"

registry := httpadapter.NewTenantRegistry(func(tenant string) (*rbacgo.Enforcer, error) {
	return rbacgo.New(rbacgo.WithTenant(tenant), rbacgo.WithStore(sharedStore))
})

guard := httpadapter.NewTenant(registry,
	httpadapter.WithTenantResolver(func(r *http.Request) (string, bool) {
		t := r.Header.Get("X-Tenant-ID") // subdomain, JWT claim, ... your choice
		return t, t != ""
	}),
	httpadapter.WithTenantUserID(func(r *http.Request) (string, bool) {
		id := jwtFromRequest(r)
		return id, id != ""
	}),
)

// handlers read the resolved tenant + Enforcer (PermissionView, ListRoles, ...):
tenantID, _ := httpadapter.TenantFromContext(r.Context())
enf, _ := httpadapter.EnforcerFromContext(r.Context())
```

Tenant option names mirror the single-tenant ones with a `Tenant` prefix
(`WithTenantResolver`, `WithTenantUserID`, `WithTenantResourceAction`,
`WithTenantUnauthorizedHandler`, `WithTenantDeniedHandler`,
`WithTenantEnforcerErrorHandler`). The factory is the provisioning point: it
runs under a per-tenant `sync.Once`, so a tenant is created exactly once even
under concurrent load; `registry.Clear()` forgets all cached Enforcers so the next request
re-provisions a tenant (e.g. after redeploying role definitions).
`NewTenantRegistry` panics on a nil factory, as the middlewares panic on
missing required options. The net/http variant is built with `NewTenant`;
gin/fiber/echo expose the same middleware as `TenantMiddleware`. Context
helpers are `TenantFromContext`/`EnforcerFromContext` in every adapter
(fiber: read from `c.Context()`; gin/echo: from `c.Request().Context()`).

Response semantics: a missing or empty tenant is unauthenticated (401, same
as a missing user); a factory error is a server error (500, overridable with
`WithTenantEnforcerErrorHandler`); a tenant-scoped denial is 403.

### net/http (also Chi)

```go
import httpadapter "github.com/rachmanzz/rbacgo/http"

guard := httpadapter.New(enforcer,
	httpadapter.WithUserID(func(r *http.Request) (string, bool) {
		id := jwtFromRequest(r) // your auth logic
		return id, id != ""
	}),
	httpadapter.WithResourceAction(func(r *http.Request) (string, string) {
		return resourceFromPath(r), r.Method
	}),
	httpadapter.WithDeniedHandler(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}),
)

mux := http.NewServeMux()
mux.Handle("GET /articles", guard(http.HandlerFunc(listArticles)))
```

### Fiber v3

```go
import fiberadapter "github.com/rachmanzz/rbacgo/fiber"

app := fiber.New()
app.Use(fiberadapter.Middleware(enforcer, fiberadapter.WithUserID(...)))
```

### Echo v5

```go
import echoadapter "github.com/rachmanzz/rbacgo/echo"

e := echo.New()
e.Use(echoadapter.Middleware(enforcer, echoadapter.WithUserID(...)))
```

### Gin v1

```go
import ginadapter "github.com/rachmanzz/rbacgo/gin"

r := gin.Default()
r.Use(ginadapter.Middleware(enforcer, ginadapter.WithUserID(...)))
```

### 401 vs 403

- **401 Unauthorized** — no authenticated subject could be resolved from the
  request (missing/empty user ID).
- **403 Forbidden** — the subject is authenticated but lacks the required
  permission.

Default responses are JSON (`{"error":"unauthorized"}`, `{"error":"forbidden"}`);
override them with `WithUnauthorizedHandler` / `WithDeniedHandler`.

## Storage

### SQL store (primary)

The SQL store is pluggable at the **driver/pool** level: pass any existing
`*sql.DB` you own, using whatever driver you like — `pgx`/`pgxpool` (via the
pgx `stdlib` adapter) for PostgreSQL, `go-sqlite3` for SQLite, or anything else
implementing `database/sql`.

```go
import (
	"database/sql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/rachmanzz/rbacgo"
)

db, _ := sql.Open("pgx", "postgres://user:pass@localhost/db")
enforcer, err := rbacgo.New(rbacgo.WithSQLStore(db))
```

**Table prefix for shared databases** — when multiple applications or tenants
share one database, namespace the tables with `WithTablePrefix` so they do not
collide:

```go
enforcer, err := rbacgo.New(rbacgo.WithSQLStore(db, rbacgo.WithTablePrefix("myapp_")))
// tables: myapp_roles, myapp_role_permissions, myapp_role_parents,
//         myapp_role_assignments, myapp_meta
```

The prefix must be a safe identifier fragment (letters, digits, underscore;
not starting with a digit); an empty prefix keeps the default names. The env
path supports the same via `RBAC_SQL_TABLE_PREFIX` (STORE=sql only).

The store never creates its own `users` table: user IDs are opaque strings in
`role_assignments`, so it coexists with the application's own user table and
never touches it.

### Embedded SQLite (default)

```go
enforcer, err := rbacgo.New()                          // :memory: — zero setup
enforcer, err := rbacgo.New(rbacgo.WithSQLite("data/rbac.db")) // file persistence
```

### In-memory store

```go
enforcer, err := rbacgo.New(rbacgo.WithMemoryStore())
```

## Cache layer

Cache effective permission sets per user with an LRU and optional TTL. The
cache is invalidated automatically on role/permission/assignment changes.

```go
import "github.com/rachmanzz/rbacgo"

// In-memory LRU
enforcer, err := rbacgo.New(
	rbacgo.WithMemoryStore(),
	rbacgo.WithLRU(rbacgo.NewMemoryLRU(capacity, ttl)),
)

// Redis-backed LRU
import "github.com/redis/go-redis/v9"
rb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
enforcer, err := rbacgo.New(
	rbacgo.WithMemoryStore(),
	rbacgo.WithLRU(rbacgo.NewRedisLRU(rb, "rbac:", 5*time.Minute)),
)
```

> **Attention — LRU capacity & TTL.** The in-memory LRU implementation
> (`memoryLRU`, see [`cache.go`](cache.go), especially `NewMemoryLRU` and the
> `Set`/eviction logic) caches one effective permission set per **user**, held
> in memory until evicted. With many distinct users this can consume a
> significant amount of memory. **Please re-validate and calibrate the `capacity`
> and `ttl` you pass to `NewMemoryLRU` (or the `RBAC_CACHE_CAPACITY` /
> `RBAC_CACHE_TTL` env vars) against your expected number of active users** so
> that memory usage does not balloon. When memory is a hard constraint, prefer
> the Redis backend or set `RBAC_CACHE=none`.

> **Redis prefix uniqueness.** Every application (or tenant) that shares one
> Redis instance **must use its own unique cache prefix**
> (`NewRedisLRU(..., "myapp:", ...)`). The default prefix is `rbacgo:cache:`
> (also used by the `RBAC_CACHE=redis` env path); two applications using the
> same prefix with overlapping user IDs would serve each other's cached
> permission sets — a cross-application authorization leak.

> **Redis Cluster note.** The Redis LRU cache clears entries with a `SCAN` +
> `DEL` walk over the configured key prefix (used when a role is re-registered,
> since the affected users cannot be enumerated cheaply). On Redis **Cluster**,
> keys are sharded by hash slot, so a multi-key `DEL` for keys spread across
> slots requires `CLUSTER SETSLOT` handling — the plain `DEL` call will return a
> `CROSSSLOT` error and only single-key deletes are guaranteed. If you run a
> Redis Cluster, prefer the standalone Redis backend for the cache, or accept
> that invalidation may fall back to TTL expiry.

> **Redis Cluster note.** The Redis LRU cache clears entries with a `SCAN` +
> `DEL` walk over the configured key prefix (used when a role is re-registered,
> since the affected users cannot be enumerated cheaply). On Redis **Cluster**,
> keys are sharded by hash slot, so a multi-key `DEL` for keys spread across
> slots requires `CLUSTER SETSLOT` handling — the plain `DEL` call will return a
> `CROSSSLOT` error and only single-key deletes are guaranteed. If you run a
> Redis Cluster, prefer the standalone Redis backend for the cache, or accept
> that invalidation may fall back to TTL expiry.

## Performance

Decisions hit the lookup cache by default, so the hot path is a single map
read. Benchmarks (`go test -bench . -benchmem`) on Intel i7-8650U @ 1.90GHz,
Go 1.25.12, 2026-08-06 — memory store, one role/user, same decision repeated:

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `BenchmarkDefaultCacheHit` (plain `New()`) | 140 | 8 | 1 |
| `BenchmarkCacheHit` (explicit `WithLRU`) | 145 | 8 | 1 |
| `BenchmarkNoCacheMiss` (`RBAC_CACHE=none`) | 549 | 560 | 6 |

The default cache is ~3.9x faster than the uncached rebuild path per decision.
Cache misses fall back to building the effective permission set (O(R+M+P) over
the role graph); enable the cache or size `RBAC_CACHE_CAPACITY` to your active
user count to keep misses rare.

## Environment configuration

All store/cache settings are configurable via `RBAC_`-prefixed environment
variables (default prefix; override with `WithEnvPrefix("X_")`), read once at
construction via `WithConfigFromEnv()`:

```go
enforcer, err := rbacgo.New(rbacgo.WithConfigFromEnv())
```

Precedence: explicit options (e.g. `WithMemoryStore()`, `WithLRU(...)`) win
over environment variables, which in turn win over defaults.

Example:

```sh
export RBAC_STORE=sqlite
export RBAC_SQLITE_PATH=data/rbac.db
export RBAC_CACHE=redis
export RBAC_CACHE_TTL=10m
export RBAC_REDIS_ADDR=localhost:6379
```

| Env var | Default | Purpose |
| --- | --- | --- |
| `RBAC_STORE` | `sqlite` | `sqlite`, `sql` (user-supplied `*sql.DB`), `memory` |
| `RBAC_SQLITE_PATH` | `:memory:` | SQLite DSN / file path |
| `RBAC_DATABASE_URL` | — | Postgres/other DSN passed to the configured driver |
| `RBAC_CACHE` | `memory` | `memory`, `redis`, `none` |
| `RBAC_CACHE_CAPACITY` | `1024` | LRU capacity |
| `RBAC_CACHE_TTL` | `5m` | Cache TTL (Go duration string) |
| `RBAC_REDIS_ADDR` | `localhost:6379` | Redis address |
| `RBAC_REDIS_PASSWORD` | — | Redis password (optional) |
| `RBAC_REDIS_DB` | `0` | Redis DB index |

You do not need to set any of these to get started — `rbacgo.New()` works out of
the box with an embedded `:memory:` SQLite store and an in-memory LRU lookup
cache (1024 entries, 5m TTL), so every decision is an O(1) cache hit on
average. Replace the backend with `WithLRU(...)` (e.g. a Redis LRU), or call
`WithConfigFromEnv()` to control it via env vars (`RBAC_CACHE=none` disables
the cache entirely). Set the env vars above only for what you change; the
[Validation checklist](#validation-checklist) points to the env vars relevant to
each behavior you may need to adjust.

## Examples

Runnable examples live in [`examples/`](examples/):

```sh
cd examples
go run ./http    # stdlib / Chi
go run ./fiber   # Fiber v3
go run ./echo    # Echo v5
go run ./gin     # Gin v1
```

Each seeds a `viewer` / `editor` hierarchy and answers requests on `:8080`.
Try `curl -H "X-User-ID: alice" localhost:8080/articles` (the examples wire
`WithUserID` to that demo header only to be runnable; a real app reads the ID
from its own auth layer).

## Compatibility

- **Go:** latest stable release.
- **Core engine logic:** stdlib-only (zero third-party dependencies). The module's only
  third-party deps are the optional backends: embedded SQLite (`go-sqlite3`) and Redis
  cache (`go-redis`).
- **Adapters:** Fiber **v3**, Echo **v5**, Gin **v1 latest**, `net/http`
  (latest stdlib). Older majors are not supported.

## Validation checklist

> The defaults below are safe, but you **must validate** them against your own
> deployment before going to production. Each item links to the relevant code
> and the environment variables you may need.

1. **Tenant** — `WithTenant` is **required** and has no default (see
   `options.go`): every Enforcer is scoped to one tenant and the API rejects
   `New` without it (`ErrTenantRequired`). Pass the tenant id your app
   resolves (organization, workspace, project) and construct one Enforcer per
   tenant.

2. **User-ID extraction** — `WithUserID` is **required** and has no default
   (see `http/http.go`, `fiber/fiber.go`, `echo/echo.go`, `gin/gin.go`): the
   middleware never reads identity from HTTP headers. Wire it to your own
   authentication (JWT claims, session cookie, upstream proxy, ...).

3. **Resource/action mapping** — defaults to `(URL path, HTTP method)` (see
   `WithResourceAction` in the same adapter files). Validate that your
   registered permission resources exactly match the paths your routes serve
   (including the leading `/`) and that actions match your methods
   (`GET`, `POST`, ...). A mismatch fails closed (403), but verify it is what
   you intend.

4. **LRU capacity & TTL** — see the attention note in
   [Cache layer](#cache-layer). Re-validate `capacity`/`ttl` against your
   expected number of active users so memory does not balloon.
   Env vars: `RBAC_CACHE`, `RBAC_CACHE_CAPACITY`, `RBAC_CACHE_TTL`.

5. **SQL store driver** — when using `RBAC_STORE=sql` (or `WithSQLStore`), make
   sure the driver is imported and registered (e.g.
   `_ "github.com/jackc/pgx/v5/stdlib"` for Postgres) and that the database is
   reachable. Env vars: `RBAC_DATABASE_URL`.

6. **SQLite `:memory:` default** — the default store is an embedded in-memory
   SQLite database (see `sqlite.go`): data is process-local and lost on
   restart. Use `WithSQLite(path)` / `RBAC_SQLITE_PATH` for persistence, and a
   shared SQL store (e.g. Postgres) for multi-instance deployments.
   Env var: `RBAC_SQLITE_PATH`.

7. **Role hierarchy** — cycles are rejected at registration (see
   `detectCycle` in `memory_store.go` / `checkCycles` in `sqlstore.go`), but
   validate your role graph to avoid unintended over-granting through
   inheritance (decision-log ADR-004).

8. **401 vs 403 semantics** — default responses are JSON
   (`{"error":"unauthorized"}`, `{"error":"forbidden"}`). Validate that your
   client/UI expects them, and override with `WithUnauthorizedHandler` /
   `WithDeniedHandler` per adapter.

## Known residual (security)

`govulncheck` is clean on all six modules except one advisory: **GO-2026-5932** on
`golang.org/x/crypto/openpgp`. It is inherited transitively from Fiber v3 / Gin v1 and has
**no published fix** (the advisory marks the package unsafe-by-design). It is **not called**
by any rbacgo code path, so govulncheck reports it only informationally and still exits 0.
CI runs govulncheck in default symbol mode (see `.github/workflows/ci.yml`); the residual
is non-blocking there. Re-evaluate before every release — if a fix appears or the
transitive dependency drops, remove this note.

## Roadmap & non-goals

- v1: roles, hierarchy, SQL/SQLite/memory storage, LRU cache (memory + Redis),
  `http`/`fiber`/`echo`/`gin` adapters.
- Future: wildcard permissions, ABAC policies, auto-reload of policies.
- Out of scope: administration UI, per-field (column-level) authorization, an
  aggregator package that re-exports every adapter.

## License

[MIT](LICENSE). Third-party notices: see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

## Acknowledgments

This library was developed with the assistance of AI tooling.
