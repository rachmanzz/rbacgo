# Dependabot Remediation v1

**Date:** 2026-10-16

**Scope:** Coordinated local remediation of the dependency changes proposed in
Dependabot PRs [#8](https://github.com/rachmanzz/rbacgo/pull/8),
[#11](https://github.com/rachmanzz/rbacgo/pull/11),
[#12](https://github.com/rachmanzz/rbacgo/pull/12), and
[#13](https://github.com/rachmanzz/rbacgo/pull/13).

**Status:** Implemented and locally verified. No commit, push, PR branch update,
or merge was performed in this remediation. Remote PR check results are not
changed by local verification.

## Root cause

Adapters and examples use local replace directives. Updating a framework only
in its adapter changes the effective dependency graph of examples without
updating the examples manifest. Updating core also changes required versions
and minimum Go versions in every consumer module. CI correctly rejected these
states with go mod tidy -diff or a package-loading error during govulncheck.
The inspected security job failures were manifest-loading failures, rather than
reports of newly called vulnerable symbols.

## Changes

- All seven modules now declare minimum **go 1.26.0** and recommended toolchain
  **go1.27.2**, as explicitly requested by the user.
- Update **miniredis 2.39.0 → 2.40.0**, **go-redis 9.22.0 → 9.23.0**,
  **Fiber 3.5.0 → 3.6.0**, and **Echo 5.3.1 → 5.4.0**.
- Regenerate all affected go.mod/go.sum files, including transitive requirements
  in adapters, examples, and integration/mysql. Keep the strict CI tidy check.
- Replace the seven independent Go Dependabot update entries with one entry
  listing all seven directories and one wildcard version-update group. Retain
  the weekly schedule and the separate GitHub Actions update group. The
  [official configuration reference](https://docs.github.com/en/code-security/reference/supply-chain-security/dependabot-options-reference#groups)
  documents groups and multiple directories. Grouping reduces isolated manifest
  updates; it does not guarantee every future update will pass CI.
- Update current compatibility guidance and dependency notices. Check downloaded
  LICENSE files for the four updated direct dependencies and the new MIT
  go-brrr 1.2.0 transitive dependency; include its notice. Preserve audit v3 as
  historical evidence for the earlier dependency baseline.

## Verification

| Check | Result |
| --- | --- |
| All seven modules: go mod tidy -diff | Passed without differences |
| All seven modules using Go 1.27.2: go test -race -count=1 ./... | Passed; examples compile and have no tests |
| All seven modules: go vet ./... | Passed |
| All seven modules with GOTOOLCHAIN=go1.26.0: go test -count=1 ./... | Passed, confirming the declared minimum toolchain |
| Redis/cache/invalidation integration tests with go-redis 9.23.0, race enabled | Passed against an isolated Redis 7.4.11 cluster with three primaries and all 16,384 slots |
| govulncheck ./... across all seven modules; MySQL uses -test | Passed with exit status zero; no called vulnerable symbols reported |
| Go directives, Dependabot YAML, diff whitespace | Passed |

The live Redis test command was:

~~~sh
RBAC_TEST_REDIS_CLUSTER_ADDRS='127.0.0.1:17100,127.0.0.1:17101,127.0.0.1:17102' \
  go test -race -count=1 -tags integration -run 'Redis|Invalidat' ./...
~~~

The three temporary cluster containers were removed after verification. Live
PostgreSQL/MySQL tests were not rerun for this dependency-only change. The
MySQL module compiled under both toolchains; its live test skips without a DSN.
The earlier live SQL results remain recorded in feature-audit_v3.md.

Security scans used the recommended Go 1.27.2 toolchain. Fiber, Gin, and examples
still report one advisory in required modules whose vulnerable code is not
called. The other scans report no vulnerabilities. Passing symbol-level scans
are dated evidence, not a guarantee about every possible integration or the
security of the older minimum standard library. See the
[raw scan results](verification_dependabot_v1/).
