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
- **Pluggable storage** — PostgreSQL, SQLite, explicit MySQL syntax through a
  caller-owned `*sql.DB`, plus an in-memory store.
- **Default store: embedded SQLite** — `rbacgo.New(rbacgo.WithTenant("acme"))` uses
  `:memory:` storage; pass a file path for persistence.
- **Lookup cache** — a bounded in-memory LRU with TTL, or Redis with TTL
  and server-configured eviction. Redis is not a client-side bounded LRU.
- **Environment configuration** — `RBAC_`-prefixed env vars (configurable
  prefix), read once at construction.
- **Consistent adapter API** — the same options and semantics across `http`,
  `fiber`, `echo`, and `gin` adapters.
- **Optional policy extensions** — wildcard permissions, inherited allow/deny
  rules, trusted attribute conditions, descriptive role metadata, and atomic batches.
- **Operations** — bounded tenant registries with idle eviction/request leases,
  metrics snapshots, operational logging, and a synchronous durable audit sink.

See [Policy and Operations Guide](docs/feature-guide.md) for opt-in configuration,
examples, persistence guarantees, and lifecycle behavior.

## Installation

Install only what you need:

```sh
# core engine only
go get github.com/rachmanzz/rbacgo@v0.2.0-4

# stdlib / net/http users (also Chi)
go get github.com/rachmanzz/rbacgo/http@v0.2.0-4

# framework-specific
go get github.com/rachmanzz/rbacgo/fiber@v0.2.0-4   # Fiber v3
go get github.com/rachmanzz/rbacgo/echo@v0.2.0-4    # Echo v5
go get github.com/rachmanzz/rbacgo/gin@v0.2.0-4     # Gin v1
```

> The commands above pin the existing pre-release tag **`v0.2.0-4`**.
> Go does not select pre-releases for `@latest`. New APIs described below
> (policy extensions, bounded registries, metrics/audit, and `*As` APIs) are working-tree additions
> and require a subsequent release or a local module replacement.

Each adapter is its own Go module with independent versioning
(`http/v0.2.0-4`, `fiber/v0.2.0-4`, ...).

## Quick start

No database setup is required: `New(WithTenant("acme"))` uses embedded SQLite
in memory. Calling `New()` without a tenant returns `ErrTenantRequired`. Every
enforcer is scoped to a **tenant** (organization, workspace, app…) with
`WithTenant`; roles, users, and cache entries are namespaced by it, so one
shared store can serve many tenant namespaces. Your application must validate
that the authenticated caller may access the resolved tenant.

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
	if err := enforcer.RegisterRole(ctx, rbacgo.Role{
		Name:        "viewer",
		Permissions: []rbacgo.Permission{{Resource: "articles", Action: "read"}},
	}); err != nil {
		panic(err)
	}
	if err := enforcer.RegisterRole(ctx, rbacgo.Role{
		Name:        "editor",
		Permissions: []rbacgo.Permission{{Resource: "articles", Action: "write"}},
		Parents:     []string{"viewer"},
	}); err != nil {
		panic(err)
	}
	if err := enforcer.AssignRole(ctx, "user-123", "editor"); err != nil {
		panic(err)
	}

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
* Enforcer operations use tenant-scoped keys even on shared storage. This
  isolates tenant namespaces; it does not authenticate callers or establish
  tenant membership. Resolve tenants from trusted authentication data and
  authorize access before selecting an Enforcer. Direct use of `Store()`
  bypasses the Enforcer's namespace and authorization checks.
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

An update can introduce a cycle even when every parent already exists. The
shipped stores validate the proposed graph and reject cyclic registrations or
updates with `ErrCycleDetected` (`detectCycle` in `memory_store.go` /
`checkCycles` in `sqlstore.go`). Custom stores must enforce the same invariant.

```go
if err := enforcer.RegisterRole(ctx, rbacgo.Role{Name: "viewer"}); err != nil {
	panic(err)
}
err := enforcer.RegisterRole(ctx, rbacgo.Role{Name: "admin", Parents: []string{"missing"}})
// err == rbacgo.ErrParentNotFound  (parent must be registered first)
```

## Role management

Role-management APIs have two explicit authorization boundaries. Capability-
checked methods require the actor to hold `("roles", "manage")` in this tenant
(override with `WithRoleManagementPermission("acl", "manage")`). A caller
without that capability gets `ErrPermissionDenied`.

| Operation | Capability-checked API | Trusted provisioning API (no caller check) |
| --- | --- | --- |
| Register a role | `RegisterRoleAs(ctx, actorID, role)` | `RegisterRole(ctx, role)` |
| Register a batch | `RegisterRolesAs(ctx, actorID, roles...)` | `RegisterRoles(ctx, roles...)` |
| Assign a role | `AssignRoleAs(ctx, actorID, targetUserID, roleName)` | `AssignRole(ctx, userID, roleName)` |
| List roles | `ListRolesAs(ctx, actorID)` | `ListRoles(ctx)` |
| Update / delete / unassign | `UpdateRole` / `DeleteRole` / `UnassignRole` | None |

Use the trusted APIs only in provisioning code or behind application-level
administrative authorization. Bootstrap the first manager with `RegisterRole`
and `AssignRole`, then use the checked methods for user-facing administration.
Derive `actorID` from the authenticated session, never from an untrusted body
field. Batch registration is ordered, not atomic: earlier successes remain
committed when a later role fails.

```go
// Only callers holding ("roles", "manage") may run these.
err := enforcer.UpdateRole(ctx, "admin-user", rbacgo.Role{
	Name:        "editor",
	Permissions: []rbacgo.Permission{{Resource: "/articles", Action: "DELETE"}},
	Parents:     []string{"viewer"},
})
// ErrParentNotFound   -> a parent does not exist
// ErrCycleDetected    -> the new parents would close a hierarchy cycle
// ErrPermissionDenied -> caller lacks the role-management capability

roles, err := enforcer.ListRolesAs(ctx, "admin-user") // tenant-scoped, sorted

err = enforcer.DeleteRole(ctx, "admin-user", "editor")
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
4. **Cache invalidation** — role register/update/delete flushes the local lookup
   cache; assignment/unassignment drops the target user's entry. With
   `WithCacheInvalidator`, events are published to other subscribers. Delivery
   is asynchronous and best-effort; lost events leave remote caches stale
   until TTL expiry or a later invalidation. This is not instantaneous revocation.
5. **Store support** — `UpdateRole`/`DeleteRole`/`UnassignRole`/`ListRoles` are
   optional store capabilities (`RoleUpdater`/`RoleDeleter`/`RoleUnassigner`/
   `RoleLister` interfaces). Stores that do not implement them report
   `ErrUnsupported`, so existing custom stores keep working unchanged.
6. **Listing is tenant-scoped** — `ListRoles` returns only the roles of the
   enforcer's tenant, with names and parents returned unscoped.

## Exposing permissions to a frontend

The library is framework-agnostic, so it returns a ready-to-serialize snapshot
instead of writing HTTP responses. `Enforcer.PermissionView` builds the
ordinary RBAC allow snapshot of a user — directly assigned roles plus the
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

Conditional policies/denies are not applied to this snapshot; use backend
enforcement for each resource context.

`policy_version` increments on every successful policy mutation (role
registration, update, assignment, unassignment, deletion), subject to shared
source availability. Frontends store the version
next to the payload and re-render only when it changes — no payload diffing
needed. Each tab must fetch a fresh snapshot to detect changes; the version
is not a push notification mechanism:

```js
if (payload.policy_version !== lastVersion) {
  saveVersion(payload.policy_version)
  renderUI(payload)
}
```

By default the version is held in memory per instance. In multi-instance
deployments use a shared source to align versions across instances:

- **SQL** — the source of truth: `sqlStore` keeps the counter in a `meta`
  table, so all instances on the same database agree automatically; no extra
  configuration needed.
- **Redis** — for deployments already using Redis, point all instances at the
  same key:

```go
version := rbacgo.NewRedisPolicyVersion(redisClient, "rbacgo:policy_version")
enforcer, err := rbacgo.New(
	rbacgo.WithTenant("acme"),
	rbacgo.WithStore(store),
	rbacgo.WithPolicyVersionStore(version),
)
```

If the shared source is unreachable the enforcer falls back to its local
counter; version bookkeeping never fails a policy mutation. During an outage,
versions can diverge or move backward when the shared source recovers. A version
is an invalidation hint, not an atomic revision binding roles and permissions.

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
factory runs at most once per cached entry, even under concurrent first requests),
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

Tenant options mirror single-tenant options with a Tenant prefix. All adapters
share the core TenantRegistry. The original factory constructor remains; use
NewTenantRegistryWithOptions or NewTenantRegistryContext for optional capacity,
idle TTL, and factory timeouts. Middleware holds a registry lease until the
handler returns, so eviction/shutdown can drain active requests.

EvictContext removes one entry and waits for its leases/factory. ClearAndClose
cleans a snapshot and remains reusable; Shutdown permanently rejects new leases
and stops the idle janitor. Clear preserves its older forget-only behavior.
Context-aware cleanup can return on a deadline while cleanup continues. A
factory must cooperate with cancellation; cached failures can be evicted to
retry. See the [lifecycle guide](docs/feature-guide.md#bounded-registries-and-graceful-shutdown)
for ownership, deadlines, and deadlock boundaries.

Missing/empty tenants or users return 401; factory/capacity/shutdown errors use
WithTenantEnforcerErrorHandler (500 by default); a denial is 403. Tenant/user
resolvers must use trusted authentication data. Arbitrary client-supplied tenant
headers do not establish tenant membership.

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

The SQL store accepts a caller-owned `*sql.DB`. Supported dialects are
**PostgreSQL, SQLite, and explicit MySQL**. The repository tests SQLite through
`go-sqlite3`, PostgreSQL through `pgx`/`stdlib`, and MySQL through a separate
`go-mysql-org/go-mysql` test module. Other drivers require application verification. Accepting `database/sql` does not
provide support for other SQL dialects. Use a custom `Store` for those.

| Backend | Driver tested in this repository | Verification |
| --- | --- | --- |
| SQLite | `github.com/mattn/go-sqlite3` | Root tests |
| PostgreSQL | `github.com/jackc/pgx/v5/stdlib` | Integration-tagged tests in CI |
| MySQL (explicit dialect) | `github.com/go-mysql-org/go-mysql/driver` | Separate `integration/mysql` suite |
| Other SQL dialects | None | Use a custom Store |

```go
import (
	"database/sql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/rachmanzz/rbacgo"
)

db, _ := sql.Open("pgx", "postgres://user:pass@localhost/db")
enforcer, err := rbacgo.New(rbacgo.WithTenant("acme"), rbacgo.WithSQLStore(db))
```

**Table prefix for shared databases** — when multiple applications or tenants
share one database, namespace the tables with `WithTablePrefix` so they do not
collide:

```go
enforcer, err := rbacgo.New(rbacgo.WithTenant("acme"), rbacgo.WithSQLStore(db, rbacgo.WithTablePrefix("myapp_")))
// tables: myapp_roles, myapp_role_permissions, myapp_role_parents,
//         myapp_role_assignments, myapp_meta, myapp_role_rules, myapp_role_metadata
```

The prefix must be a safe identifier fragment (letters, digits, underscore;
not starting with a digit); an empty prefix keeps the default names. The env
path supports the same via `RBAC_SQL_TABLE_PREFIX` (STORE=sql only).

The store never creates its own `users` table: user IDs are opaque strings in
`role_assignments`, so it coexists with the application's own user table and
never touches it.

### Embedded SQLite (default)

```go
enforcer, err := rbacgo.New(rbacgo.WithTenant("acme")) // :memory:
enforcer, err := rbacgo.New(rbacgo.WithTenant("acme"), rbacgo.WithSQLite("data/rbac.db")) // file persistence
```

### In-memory store

```go
enforcer, err := rbacgo.New(rbacgo.WithTenant("acme"), rbacgo.WithMemoryStore())
```

## Cache layer

Cache effective permission sets per user with the in-memory LRU or Redis TTL backend. The
cache is invalidated automatically on role/permission/assignment changes.

```go
import "github.com/rachmanzz/rbacgo"

// In-memory LRU
enforcer, err := rbacgo.New(
	rbacgo.WithTenant("acme"),
	rbacgo.WithMemoryStore(),
	rbacgo.WithLRU(rbacgo.NewMemoryLRU(capacity, ttl)),
)

// Redis-backed TTL cache
import "github.com/redis/go-redis/v9"
rb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
enforcer, err := rbacgo.New(
	rbacgo.WithTenant("acme"),
	rbacgo.WithMemoryStore(),
	rbacgo.WithLRU(rbacgo.NewRedisLRU(rb, "rbac:", 5*time.Minute)),
)
```

> **Cross-instance invalidation.** When several application processes (or
> instances) share one RBAC store, separate local caches retain snapshots until
> they expire (TTL) unless invalidation is delivered. Sharing a Redis cache
> backend also shares cache entries; independent memory stores still do not
> share policy data.
> Wire them together with `WithCacheInvalidator` and a Redis pub/sub channel so
> received mutation events evict affected snapshots on subscribers without
> waiting for their TTL. Delivery is asynchronous and best-effort:
>
> ```go
> rb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
> invalidator := rbacgo.NewRedisInvalidator(rb, "rbacgo:invalidation")
> enforcer, err := rbacgo.New(
> 	rbacgo.WithTenant("acme"),
> 	rbacgo.WithMemoryStore(),
> 	rbacgo.WithCacheInvalidator(invalidator),
> )
> ```
>
> Events are **best-effort**: publish failures are logged only when
> `WithLogger` is configured, and never fail the mutation. Delivery failures
> are not exposed by `CacheInvalidator`; coherence can degrade to TTL-bounded
> behavior. The Redis client given to `NewRedisInvalidator` is shared, not
> closed by the enforcer; only a client created internally via
> `WithConfigFromEnv` (`RBAC_CACHE=redis`) is owned and closed by `Close()`.
> Close caller-owned invalidators and Redis clients separately after their
> Enforcers have stopped using them. Both Enforcers must share persistent
> policy storage; independent memory stores do not share policy data.
>
> > **Attention — LRU capacity & TTL.** The in-memory LRU implementation
> (`memoryLRU`, see [`cache.go`](cache.go), especially `NewMemoryLRU` and the
> `Set`/eviction logic) caches one effective permission set per **user**, held
> in memory until evicted. With many distinct users this can consume a
> significant amount of memory. **Please re-validate and calibrate the `capacity`
> and `ttl` you pass to `NewMemoryLRU` (or the `RBAC_CACHE_CAPACITY` /
> `RBAC_CACHE_TTL` env vars) against your expected number of active users** so
> that memory usage does not balloon. When memory is a hard constraint, prefer
> the Redis backend or set `RBAC_CACHE=none`.

> **Redis prefix uniqueness.** Every independent policy dataset sharing one
> Redis instance **must use its own unique cache prefix**
> (`NewRedisLRU(..., "myapp:", ...)`). The default prefix is `rbacgo:cache:`
> (also used by the `RBAC_CACHE=redis` env path); two applications using the
> same prefix with overlapping tenant/user IDs would serve each other's cached
> permission sets — a cross-application authorization leak.

> **Redis Cluster.** With a `*redis.ClusterClient`, FlushContext scans every
> primary and routes single-key deletes to avoid CROSSSLOT. The integration test
> covers three primaries. It is not an atomic snapshot during concurrent writes
> or resharding; failures can leave entries until TTL expiry. See the
> [cluster guide](docs/feature-guide.md#mysql-and-redis-cluster).

Custom `CacheBackend` implementations must be concurrency-safe. Implement
`GenerationCacheBackend` as well when sharing a cache across Enforcers: its
conditional writes prevent stale lookups from refilling invalidated entries.
The supplied memory and Redis backends implement it. Without that interface,
fill protection is limited to mutations observed by a single Enforcer.

## Performance

The default in-memory cache performs constant-time lookup and LRU bookkeeping
on a warm hit, with locking and TTL checks. Misses rebuild permissions from
the store; Redis hits include network I/O and JSON decoding. Measurements on
Intel i7-1165G7 @ 2.80GHz, Linux amd64, Go 1.27.2, 2026-10-16,
with eight logical workers:

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| Default cache hit | 121.3 | 16 | 1 |
| Explicit LRU hit | 125.0 | 16 | 1 |
| Uncached rebuild | 478.0 | 576 | 7 |
| Owned cache hit | 196.6 | 16 | 1 |
| Attribute decision | 6,121 | 2,534 | 58 |
| Audit decision (temporary tmpfs file) | 2,044 | 644 | 5 |
| Parallel enforcement | 153.4 | 16 | 1 |

The audit benchmark includes append/fsync on **tmpfs**, so it does not measure
persistent-disk durability latency. These synthetic workloads are not deployment
latency guarantees. See [audit v3](.knowledges/audit/feature-audit_v3.md) for
verification details and raw measurements.
Cache misses build the effective permission set by traversing ancestors; shared
ancestors may be revisited. Size `RBAC_CACHE_CAPACITY` to the workload and
measure hit rate and latency under representative concurrency.

## Environment configuration

The settings listed below are configurable via `RBAC_`-prefixed environment
variables (default prefix; override with `WithEnvPrefix("X_")`), read once at
construction via `WithConfigFromEnv()`:

```go
enforcer, err := rbacgo.New(rbacgo.WithTenant("acme"), rbacgo.WithConfigFromEnv())
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
| `RBAC_DATABASE_URL` | — | PostgreSQL URL (pgx) or SQLite DSN for `STORE=sql` |
| `RBAC_SQL_TABLE_PREFIX` | — | SQL table prefix for `STORE=sql` |
| `RBAC_CACHE` | `memory` | `memory`, `redis`, `none` |
| `RBAC_CACHE_CAPACITY` | `1024` | LRU capacity |
| `RBAC_CACHE_TTL` | `5m` | Cache TTL (Go duration string) |
| `RBAC_REDIS_ADDR` | `localhost:6379` | Redis address |
| `RBAC_REDIS_PASSWORD` | — | Redis password (optional) |
| `RBAC_REDIS_DB` | `0` | Redis DB index |

No environment variables are required to start with `New(WithTenant("acme"))`.
The defaults are embedded `:memory:` SQLite and an in-memory LRU lookup cache
(1024 entries, 5m TTL). Cache misses and expiry still require store access.
Replace the backend with `WithLRU(...)` (e.g. a Redis TTL cache), or call
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
go run ./policy  # attributes, deny rules, atomic batch, metrics, durable audit
```

Each seeds a `viewer` / `editor` hierarchy and answers requests on `:8080`.
Try `curl -H "X-User-ID: alice" localhost:8080/articles` (the examples wire
`WithUserID` to that demo header only to be runnable; a real app reads the ID
from its own auth layer).

## Compatibility

- **Go:** core, http, and echo retain minimum `go 1.25.7`.
  The recommended/CI toolchain is `go1.27.2` for current security fixes.
  Fiber, Gin, and examples require Go 1.26.0 after the approved x/net patch update.
- **Core algorithms:** use standard-library data structures. The root module
  still has runtime dependencies for SQLite (`go-sqlite3`) and Redis
  (`go-redis`), even when an application selects the memory backend. Test
  dependencies are listed separately in `third-party.md`.
- **Adapters:** Fiber **v3**, Echo **v5**, Gin **v1**, `net/http`. The pinned
  framework versions in each adapter's `go.mod` are tested; other versions
  require verification. Older majors are not supported.

## Operational logging

`WithLogger` accepts a standard-library `*slog.Logger`. Logging is disabled
by default. It emits warnings with `tenant` and `error` attributes for failed
`EnforceCtx`/`EnforceOwnedCtx` permission lookups, invalidation publishes, and
shared policy-version reads/increments that fall back to a local counter.

```go
logger := slog.New(slog.NewJSONHandler(os.Stderr, nil)) // log/slog, os
// Pass WithLogger when constructing your tenant's Enforcer.
enforcer, err := rbacgo.New(
    rbacgo.WithTenant("acme"),
    rbacgo.WithLogger(logger),
)
```

Handlers must support concurrent use. Logging is synchronous, so avoid blocking
handlers on request paths. Best-effort bookkeeping failures still do not fail
policy mutations. This feature is not a durable decision or policy-change audit
trail and does not report every backend failure. For counters and durable events,
configure `WithMetrics` and `WithAuditSink`; see the
[observability guide](docs/feature-guide.md#metrics-and-durable-audit).

## Validation checklist

> Review the defaults and integration boundaries below against your own
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

## Security verification

Go 1.27.2 and patched x/net dependencies are selected following the vulnerability
scan. The resulting Go 1.26 minimum for Fiber/Gin/examples was explicitly approved.
See [.knowledges/audit/feature-audit_v3.md](.knowledges/audit/feature-audit_v3.md)
for dated scan/test evidence. Symbol-level scans do not prove that every possible
application integration is safe; rerun them for each deployment and release.

## Scope and non-goals

The library provides RBAC plus opt-in wildcard matching, attribute conditions,
and deny rules. Metadata and atomic policy batches are available through optional
store capabilities. It does not provide an administration UI, per-field database
authorization, an arbitrary policy scripting language, or an adapter aggregator.
Database change watching, distributed atomic decision snapshots, and a
transactional audit outbox are not promised. See limitation.md for exact boundaries.

## License

[MIT](LICENSE). Third-party notices: see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).

## Acknowledgments

This library was developed with the assistance of AI tooling.
