# rbacgo

A framework-agnostic RBAC (Role-Based Access Control) library for Go, with thin
adapters for the most popular HTTP frameworks.

`rbacgo` gives you a single, reusable authorization engine — roles, permissions,
role hierarchy, and user-role assignment — plus idiomatic middleware for
`net/http`, Fiber v3, Echo v5, and Gin v1. Install only the adapter you need;
each one wraps the same core engine and storage.

## Features

- **Framework-agnostic core** — zero third-party dependencies.
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
go get github.com/rachmanzz/rbacgo

# stdlib / net/http users (also Chi)
go get github.com/rachmanzz/rbacgo/http

# framework-specific
go get github.com/rachmanzz/rbacgo/fiber   # Fiber v3
go get github.com/rachmanzz/rbacgo/echo    # Echo v5
go get github.com/rachmanzz/rbacgo/gin     # Gin v1
```

Each adapter is its own Go module with independent versioning
(`http/v1.0.0`, `fiber/v1.0.0`, ...).

## Quick start

Zero-config: `rbacgo.New()` uses an embedded SQLite store in memory.

```go
package main

import (
	"context"
	"fmt"

	"github.com/rachmanzz/rbacgo"
)

func main() {
	ctx := context.Background()

	enforcer, err := rbacgo.New()
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

## Role hierarchy & cycle detection

Roles may declare parent roles. The engine resolves the transitive closure when
checking permissions and rejects graphs that contain a cycle (e.g.
`admin -> editor -> admin`) at registration time.

```go
enforcer.RegisterRole(ctx, rbacgo.Role{Name: "admin", Parents: []string{"editor"}})
err := enforcer.RegisterRole(ctx, rbacgo.Role{Name: "editor", Parents: []string{"admin"}})
// err == rbacgo.ErrCycleDetected
```

## Middleware adapters

All adapters share the same defaults and options: user-ID extraction (default:
`X-User-ID` header), resource/action derivation (default: URL path + HTTP
method), and customizable 401/403 responses.

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
	sqlstore "github.com/rachmanzz/rbacgo" // or the store package
)

db, _ := sql.Open("pgx", "postgres://user:pass@localhost/db")
enforcer, err := rbacgo.New(rbacgo.WithSQLStore(db))
```

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

## Environment configuration

All store/cache settings are configurable via `RBAC_`-prefixed environment
variables (default prefix; override with `WithEnvPrefix("X_")`), read once at
construction via `WithConfigFromEnv()`:

```go
enforcer, err := rbacgo.New(rbacgo.WithConfigFromEnv())
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
Try `curl -H "X-User-ID: alice" localhost:8080/articles`.

## Compatibility

- **Go:** latest stable release.
- **Core engine:** zero third-party dependencies.
- **Adapters:** Fiber **v3**, Echo **v5**, Gin **v1 latest**, `net/http`
  (latest stdlib). Older majors are not supported.

## Roadmap & non-goals

- v1: roles, hierarchy, SQL/SQLite/memory storage, LRU cache (memory + Redis),
  `http`/`fiber`/`echo`/`gin` adapters.
- Future: wildcard permissions, ABAC policies, auto-reload of policies.
- Out of scope: administration UI, per-field (column-level) authorization, an
  aggregator package that re-exports every adapter.

## License

[MIT](LICENSE). Third-party notices: see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES).
