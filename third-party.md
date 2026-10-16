# Third-Party Libraries & External Dependencies — rbacgo

- **Status:** Draft
- **Purpose:** Document every third-party library used by rbacgo, with its purpose, the
  pinned version, and its license — and to enforce that all dependencies stay on the
  **latest** version and are **MIT-compatible**.
- **Last recorded online verification:** 2026-08-02 (historical, not a current freshness guarantee)
- **Inventory synchronized with module manifests:** 2026-10-16
- **Dependency update licenses checked:** 2026-10-16, downloaded module LICENSE files for miniredis 2.40.0, go-redis 9.23.0, Fiber 3.6.0, Echo 5.4.0, and go-brrr 1.2.0
- **New driver license checked:** go-mysql-org/go-mysql v1.16.0, MIT plus bundled BSD-3-Clause notice; official repository and downloaded module LICENSE
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
| go-sqlite3 | `github.com/mattn/go-sqlite3` | SQLite driver — **default embedded store** (`:memory:` / file) | v1.14.52 | MIT | ✅ |
| go-redis | `github.com/redis/go-redis/v9` | Redis client (LRU cache backend) | v9.23.0 | BSD-2-Clause | ✅ |
| miniredis | `github.com/alicebob/miniredis/v2` | In-process Redis for tests (test-only) | v2.40.0 | MIT | ✅ |
| pgx | `github.com/jackc/pgx/v5` | PostgreSQL driver for the **integration test** (`//go:build integration`, test-only) | v5.11.0 | MIT | ✅ |

### Storage (recommended drivers, in the root module)

> **Pluggable design:** the SQL store accepts a user-supplied `*sql.DB`. The drivers below
> target the supported PostgreSQL and SQLite dialects. Other drivers for
> these dialects require application verification; other dialects are not
> supported. A pgxpool can be adapted through pgx stdlib. See ADR-005.

| Library | Module | Purpose | Version | License | MIT-compatible |
| --- | --- | --- | --- | --- | --- |
| pgx | `github.com/jackc/pgx/v5` | PostgreSQL driver + toolkit (recommended for SQL store; incl. `pgxpool` + `stdlib` adapter) | v5.11.0 | MIT | ✅ |
| go-sqlite3 | `github.com/mattn/go-sqlite3` | SQLite driver — **default embedded store** (`:memory:` / file) | v1.14.52 | MIT | ✅ |
| go-redis | `github.com/redis/go-redis/v9` | Redis client (LRU cache backend) | v9.23.0 | BSD-2-Clause | ✅ |
| *(in-house)* | — | LRU cache implementation (cache layer) — implemented internally, **zero deps** (see §5) | — | MIT | ✅ |

### Adapters (each is its own module)

| Library | Module | Purpose | Version | License | MIT-compatible |
| --- | --- | --- | --- | --- | --- |
| Fiber | `github.com/gofiber/fiber/v3` | Fiber v3 adapter | v3.6.0 | MIT | ✅ |
| Echo | `github.com/labstack/echo/v5` | Echo v5 adapter | v5.4.0 | MIT | ✅ |
| Gin | `github.com/gin-gonic/gin` | Gin v1 adapter | v1.12.0 | MIT | ✅ |
| go-brrr (transitive, via Fiber/fasthttp) | `github.com/molecule-man/go-brrr` | Compression support | v1.2.0 | MIT | ✅ |
| fasthttp (transitive, via Fiber) | `github.com/valyala/fasthttp` | Fiber's HTTP engine | v1.75.0 | MIT | ✅ |

The `http` adapter adds no framework dependency beyond the core module. The
core module still brings its SQLite and Redis backend dependencies.

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
  one wildcard dependency group spanning all seven Go module directories.
  Their local replace directives require coordinated updates. See
  [Dependabot configuration options](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#groups).
- Add a CI step that fails when `go.mod` has known-outdated or vulnerable deps
  (`govulncheck` + `go list -m -u`).
- Before every release: re-verify versions in this file against live sources and update.

---

## 5. Exceptions & decisions (MPL-2.0)

No MPL-2.0 dependencies remain in the project. Historical decisions:

- **go-sql-driver/mysql (MPL-2.0)** remains excluded. MySQL syntax is now
  supported through an explicit dialect option. The isolated integration/mysql
  module uses go-mysql-org/go-mysql v1.16.0 (MIT, with its bundled BSD notice);
  the core module adds no MySQL driver dependency.
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

- [x] MySQL integration driver — isolated permissively licensed module;
  go-sql-driver/mysql remains excluded (updated 2026-10-16).
- [x] Decide LRU implementation: **in-house LRU** (MIT, zero-dep) chosen.
- [x] Add `THIRD_PARTY_NOTICES` generation step to CI/release. — **Done (2026-08-02):**
  `THIRD_PARTY_NOTICES` added at repo root with the required MIT/BSD notices; `.github/workflows/ci.yml`
  verifies `LICENSE` + `THIRD_PARTY_NOTICES` presence and the required notices on every push/PR.
- [x] Postgres dialect validated against a real server. — **Done (2026-08-02):** `sqlstore_postgres_test.go`
  (`//go:build integration`) runs against PostgreSQL 17 and is part of CI via a service container.

## Feature completion dependency/security notes (2026-10-16)

- The core adds no runtime dependency for policies, metadata, batches, metrics,
  file audit, or bounded registries; these use standard-library facilities.
- integration/mysql directly requires github.com/go-mysql-org/go-mysql v1.16.0.
  Its MIT LICENSE and bundled Vitess BSD-3-Clause notice are included in
  THIRD_PARTY_NOTICES. See https://github.com/go-mysql-org/go-mysql/tree/v1.16.0.
- The user approved minimum Go 1.26.0 across all seven modules, including
  core/http/echo/integration/mysql after the Redis dependency update.
  Recommended/CI toolchain remains go1.27.2.
- An up-to-date inventory is not proof of global dependency freshness or absence
  of vulnerabilities. See audit v3 for dated symbol-level scan results.
