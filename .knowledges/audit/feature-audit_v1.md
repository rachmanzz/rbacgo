# Feature Audit v1

> Historical audit. See [feature-audit_v3.md](feature-audit_v3.md) for the current completion status.

**Project:** rbacgo

**Audit scope:** Application features, feature maturity, documentation quality, and potentially overstated claims

**Assessment:** The project has a solid RBAC foundation for Go applications that need roles, inheritance, tenant scoping, middleware, and configurable storage. It is not yet accurate to describe every operational or enterprise use case as mature: some administrative authorization remains the consuming application's responsibility, tenant-registry lifecycle behavior needs clarification, and several documents claim broader completion or compatibility than the available evidence supports.

## 1. Feature maturity

- **Core RBAC — reasonably mature.** The library provides roles, permissions, role hierarchy, cycle detection, enforcement, caching, and several role-management operations.
- **HTTP middleware — broad framework coverage.** Adapters exist for `net/http`, Fiber, Echo, and Gin. Applications can supply identity extraction and resource/action mapping.
- **Multi-tenancy — good isolation foundation, incomplete lifecycle story.** Enforcers are scoped to tenants and the adapters provide per-tenant registries. However, `TenantRegistry.Clear()` only replaces the registry map. It does not call `Enforcer.Close()`, which stops the invalidation subscriber and releases a Redis client owned by the enforcer. The documentation should not imply that `Clear()` releases these resources until the behavior is changed. See `http/tenant.go` and `enforcer.go`.
- **Administrative controls — boundaries need to be explicit.** The `("roles", "manage")` capability check protects `UpdateRole`, `DeleteRole`, and `UnassignRole`. `RegisterRole`, `RegisterRoles`, `AssignRole`, and `ListRoles` do not request a caller identity or check that capability. This can be appropriate for trusted control-plane code, but applications must protect any routes that expose these operations. See `enforcer.go`.
- **Release maturity matters.** The README identifies `v0.1.0-1` as a pre-release. That is consistent with an early release and should not be presented as a stable maturity guarantee for every deployment pattern.

## 2. Is the feature set appropriate?

The feature direction is appropriate for a lightweight, framework-agnostic RBAC library: role inheritance, exact permissions, ownership/group scopes, thin middleware, and configurable storage provide a practical foundation without imposing a framework or user model.

The product is not a complete policy-management system. It does not provide ABAC, wildcard permissions, an administration UI, or per-field authorization. Also, its internal management capability does not protect every mutation operation. Documentation should clearly state that the consuming application remains responsible for authenticating and authorizing operations that are not guarded by the library.

## 3. Potential not yet realized

1. **Complete tenant lifecycle management.** Add a way to remove a tenant or clear a registry while closing its enforcer, with defined behavior for in-flight requests.
2. **Clarify and standardize administrative authorization.** Document which operations check `roles/manage` and which must be protected by the application. Consider a consistent administrative API if the library intends to own those checks.
3. **Add observability.** The PRD mentions custom logger hooks, but no logger hook was found in the implementation. Metrics for cache hits/misses, invalidation failures, and enforcement latency would also help production operators.
4. **Extend the policy model only when user needs justify it.** ABAC, wildcard/deny rules, or richer contextual checks could be roadmap items, but their semantics and compatibility guarantees should be designed first.
5. **Strengthen storage compatibility evidence.** State which database dialects are tested and supported. Add a driver/dialect matrix and integration tests before claiming support for additional databases.

## 4. Documentation gaps and corrections

User-facing feature documentation should be written in English and should describe the implemented behavior precisely.

- **Administrative authorization:** Explain that only selected operations enforce `roles/manage`. Document that applications must protect `RegisterRole`, `RegisterRoles`, `AssignRole`, and `ListRoles` when exposing them through endpoints.
- **Tenant registry lifecycle:** Clarify that `Clear()` currently forgets registry entries without closing the enforcers, or change the implementation to close them. The README currently describes `Clear()` as the way to reprovision a tenant.
- **Owned permissions:** `limitation.md` says decisions rely only on exact resource/action matching, while the README documents `self`, `grp`, and `any` scopes. Update the limitation text so it does not contradict the owned-permission feature.
- **SQL driver support:** Distinguish accepting a `*sql.DB` from verified dialect support. The README says any `database/sql` driver; the dependency notes identify PostgreSQL and SQLite as supported. State PostgreSQL and SQLite as tested/supported, and label other drivers as unverified until tested.
- **Project status:** `gap.md` says all gaps are complete and documentation is done, but its status and milestones do not reflect the current feature set and the issues identified in this audit. Update it to match the current repository. Use wording such as “test suites pass” where that is intended; avoid “100%” if it could be read as 100% test coverage.
- **Language and maintenance:** Keep user-facing documentation in English. `phases.md` contains Indonesian historical notes; move them to clearly marked internal notes or translate them. The README also duplicates the Redis Cluster warning.

Relevant locations include `README.md`, `limitation.md`, `gap.md`, `phases.md`, and `third-party.md`.

## 5. Potentially overstated claims

- **“Any `database/sql` driver.”** The store accepts `*sql.DB`, but that alone does not establish compatibility with every SQL dialect. Claim PostgreSQL and SQLite as tested/supported; describe other drivers as unverified unless integration-tested.
- **“Every decision is an O(1) cache hit on average.”** This describes neither cold misses nor evictions, disabled caching, or network-backed Redis behavior. Limit the performance claim to warm in-memory cache hits and provide the benchmark conditions.
- **Tenant admin/owner language.** Tenant namespacing enforces data separation between tenants; it does not establish that the caller is that tenant's administrator. Make the difference between tenant isolation and caller authorization explicit.
- **Cross-process invalidation “immediately.”** The README also notes best-effort behavior, but immediate invalidation depends on a shared invalidator and healthy connectivity. State consistently that failures or disconnections may return coherence to TTL-bounded behavior.
- **“All gaps complete” / “no code changes expected.”** These are too final for a pre-release project whose documentation and lifecycle behavior still have open issues. Reconcile the completion statements in `gap.md` with the current repository state.

## Overall assessment

The core is a useful and reasonably mature RBAC engine for applications that understand and implement their own authentication and administrative boundaries. Before presenting it as broadly production-ready, clarify those boundaries, fix or document tenant cleanup behavior, align the feature and limitation documents, and narrow compatibility/performance claims to what is actually tested.
