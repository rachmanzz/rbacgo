# Third-Party Libraries & External Dependencies — rbacgo

- **Status:** Draft
- **Purpose:** Document every third-party library used by rbacgo, with its purpose, the
  pinned version, and its license — and to enforce that all dependencies stay on the
  **latest** version and are **MIT-compatible**.
- **Versions verified online:** 2026-08-02
- **Policy owner:** maintainers; re-verify before each release.

---

## 1. Policy

1. **Latest only** — all dependencies must be kept on their latest stable release. Bump
   them regularly (see §4) and before tagging a release.
2. **MIT-compatible only** — every direct dependency must carry a permissive license
   compatible with MIT (MIT, BSD-2/3-Clause, ISC, Apache-2.0). Weak-copyleft licenses
   (e.g. MPL-2.0) are **not** accepted as direct dependencies without explicit approval
   (see §5).
3. **Zero-dep core logic** — the core engine *logic* (enforcer, model, stores interface,
   in-house LRU) is **stdlib-only**. The module ships optional backends — embedded SQLite
   (`go-sqlite3`) and Redis cache (`go-redis`) — which are the module's only third-party
   dependencies; `miniredis` is test-only (PRD §7, ADR-006). Only adapters pull further deps.
4. Re-verify versions + licenses online before every release and update this file.

---

## 2. Dependency Inventory (direct)

### Core engine module (`github.com/rachmanzz/rbacgo`)

> The engine logic is **stdlib-only** (zero third-party deps). The module's only third-party
> dependencies are the optional backends below.

| Library | Module | Purpose | Version | License | MIT-compatible |
| --- | --- | --- | --- | --- | --- |
| go-sqlite3 | `github.com/mattn/go-sqlite3` | SQLite driver — **default embedded store** (`:memory:` / file) | v1.14.49 | MIT | ✅ |
| go-redis | `github.com/redis/go-redis/v9` | Redis client (LRU cache backend) | v9.21.0 | BSD-2-Clause | ✅ |
| miniredis | `github.com/alicebob/miniredis/v2` | In-process Redis for tests (test-only) | v2.38.0 | MIT | ✅ |

### Storage (`rbacgo/store`)

> **Pluggable design:** the SQL store accepts a user-supplied `*sql.DB`. The drivers below
> are the recommended ones, but users may bring their own `database/sql` driver/pool
> (e.g. `pgxpool` via the pgx `stdlib` adapter). See ADR-005.

| Library | Module | Purpose | Version | License | MIT-compatible |
| --- | --- | --- | --- | --- | --- |
| pgx | `github.com/jackc/pgx/v5` | PostgreSQL driver + toolkit (recommended for SQL store; incl. `pgxpool` + `stdlib` adapter) | v5.10.0 | MIT | ✅ |
| go-sqlite3 | `github.com/mattn/go-sqlite3` | SQLite driver — **default embedded store** (`:memory:` / file) | v1.14.49 | MIT | ✅ |
| go-redis | `github.com/redis/go-redis/v9` | Redis client (LRU cache backend) | v9.21.0 | BSD-2-Clause | ✅ |
| *(in-house)* | — | LRU cache implementation (cache layer) — implemented internally, **zero deps** (see §5) | — | MIT | ✅ |

### Adapters (each is its own module)

| Library | Module | Purpose | Version | License | MIT-compatible |
| --- | --- | --- | --- | --- | --- |
| Fiber | `github.com/gofiber/fiber/v3` | Fiber v3 adapter | v3.4.0 | MIT | ✅ |
| Echo | `github.com/labstack/echo/v5` | Echo v5 adapter | v5.3.1 | MIT | ✅ |
| Gin | `github.com/gin-gonic/gin` | Gin v1 adapter | v1.12.0 | MIT | ✅ |
| fasthttp (transitive, via Fiber) | `github.com/valyala/fasthttp` | Fiber's HTTP engine | v1.72.0 | MIT | ✅ |

The `http` adapter depends on **stdlib only** — zero third-party dependencies.

---

## 3. License compatibility summary

| License | Compatible with MIT? | Notes |
| --- | --- | --- |
| MIT | ✅ Yes | Same license family |
| BSD-2-Clause / BSD-3-Clause | ✅ Yes | Permissive; attribution notice required |
| ISC | ✅ Yes | Permissive |
| Apache-2.0 | ✅ Yes | Permissive; patent grant + attribution notice required |
| MPL-2.0 | ⚠️ Weak copyleft | File-level copyleft; OK to *depend on* without modifying the MPL files, but not preferred for an MIT-licensed library |

---

## 4. Keeping dependencies up to date

- Run `go get -u ./...` per module and re-run tests before committing.
- Recommended: enable **Dependabot** (GitHub) or **Renovate** with weekly cadence and
  `group:all` for each Go module in the monorepo.
- Add a CI step that fails when `go.mod` has known-outdated or vulnerable deps
  (`govulncheck` + `go list -m -u`).
- Before every release: re-verify versions in this file against live sources and update.

---

## 5. Exceptions & decisions (MPL-2.0)

No MPL-2.0 dependencies remain in the project. Historical decisions:

- **go-sql-driver/mysql (MPL-2.0)** — **removed (2026-08-02).** MySQL support is
  **not** part of the SQL store; only PostgreSQL and SQLite (both MIT) are supported.
- **hashicorp/golang-lru (MPL-2.0)** — **rejected as a dependency.** The LRU cache is
  implemented **in-house** (small, fixed-capacity, TTL-aware), keeping the cache layer
  MIT-only and the core engine dependency-free.

---

## 6. License obligations for redistribution

Because rbacgo is MIT-licensed and its direct deps are MIT/BSD, the following applies
when redistributing binaries:

- Keep MIT copyright notices for all MIT deps in a `NOTICE`/`THIRD_PARTY_NOTICES` file
  (fiber, echo, gin, pgx, go-sqlite3, fasthttp).
- Keep the BSD-2-Clause notice for go-redis.

---

## 7. Known follow-ups

- [x] Decide MySQL driver status — **removed; PostgreSQL + SQLite only** (2026-08-02).
- [x] Decide LRU implementation: **in-house LRU** (MIT, zero-dep) chosen.
- [x] Add `THIRD_PARTY_NOTICES` generation step to CI/release. — **Done (2026-08-02):** `THIRD_PARTY_NOTICES` added at repo root with the required MIT/BSD notices; a CI generation/re-verify step is still to be wired up before release.
