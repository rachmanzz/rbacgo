package rbacgo

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// permissionSet maps resource -> action -> allowed. It is JSON-serializable so
// it can be stored in Redis-backed caches.
type permissionSet map[string]map[string]bool

// Enforcer is the framework-agnostic RBAC engine. It answers whether a user is
// allowed to perform an action on a resource based on their assigned roles and
// the role hierarchy.
type Enforcer struct {
	store Store
	env   *envConfig
	cache CacheBackend
	// tenant scopes every role, user, and cache entry (see WithTenant).
	// Required: New returns ErrTenantRequired without it.
	tenant string
	// manageRes/manageAct is the capability required for role-management
	// operations (DeleteRole / UnassignRole). Default: ("roles", "manage").
	manageRes string
	manageAct string
	// policyVersion falls back to this local counter when no shared version
	// source is available (plain in-memory deployments).
	policyVersion atomic.Uint64
	// policySource overrides the shared policy-version source (e.g. a
	// RedisPolicyVersion). Defaults to the store when it implements
	// PolicyVersioner (SQL meta table).
	policySource PolicyVersioner
	// invalidator broadcasts/consumes cache-invalidation events across
	// enforcer instances (see WithCacheInvalidator).
	invalidator CacheInvalidator
	// invalidationMsgs is the event stream the subscriber consumes; it is
	// attached synchronously in New so no event window exists between
	// construction and subscription.
	invalidationMsgs <-chan InvalidationEvent
	// stopInvalidation closes the subscriber loop (see Close).
	stopInvalidation chan struct{}
	closeOnce        sync.Once
	// ownedClient is the Redis client created by WithConfigFromEnv; Close
	// releases it. Clients passed by the caller are never closed.
	ownedClient *redis.Client
}

// Option configures an Enforcer. Options are applied in order; environment
// configuration only fills values not already set explicitly.
type Option func(*Enforcer) error

// New creates an Enforcer. With no options it uses an embedded SQLite store
// in memory (":memory:") and a default in-memory LRU lookup cache (1024
// entries, 5m TTL) so every decision is an O(1) cache hit on average. Supply
// WithSQLStore / WithSQLite / WithStore / WithConfigFromEnv to customise
// persistence and WithLRU to replace the cache backend; WithConfigFromEnv
// with RBAC_CACHE=none disables the cache entirely. An Enforcer must be
// scoped to a tenant: WithTenant is required and New returns
// ErrTenantRequired without it.
func New(opts ...Option) (*Enforcer, error) {
	e := &Enforcer{manageRes: "roles", manageAct: "manage"}
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return nil, err
		}
	}
	if e.store == nil {
		if err := WithSQLite(":memory:")(e); err != nil {
			return nil, err
		}
	}
	// Default lookup cache: turns each Enforce/PermissionView into a bounded,
	// O(1) map read instead of rebuilding the effective permission set on
	// every call. Skipped when env config (WithConfigFromEnv) took charge of
	// the cache — it may legitimately choose "none" or a Redis backend.
	if e.cache == nil && e.env == nil {
		e.cache = NewMemoryLRU(1024, 5*time.Minute)
	}
	if e.tenant == "" {
		return nil, ErrTenantRequired
	}
	if e.invalidator != nil && e.cache != nil {
		// Subscribe synchronously before New returns: the subscriber must
		// be attached before the cache becomes usable, otherwise mutations
		// in the goroutine-startup window would be lost forever (pub/sub
		// does not replay events).
		e.invalidationMsgs = e.invalidator.Messages()
		e.stopInvalidation = make(chan struct{})
		go e.invalidationLoop()
	}
	return e, nil
}

// Store returns the underlying Store.
func (e *Enforcer) Store() Store { return e.store }

// TenantID returns the tenant this Enforcer is scoped to.
func (e *Enforcer) TenantID() string { return e.tenant }

// tenantSep separates tenant from role/user names inside the backing store.
// Never exposed through the API: RegisterRole/AssignRole/Enforce all accept
// and return unscoped names.
const tenantSep = "::"

func (e *Enforcer) roleKey(name string) string { return e.tenant + tenantSep + name }

func (e *Enforcer) userKey(userID string) string { return e.tenant + tenantSep + userID }

// cacheKey is the store key of a user's cached effective-permission
// snapshot. Invalidation events carry exactly this key, so any subscriber
// can drop it directly regardless of tenant.
func (e *Enforcer) cacheKey(userID string) string { return e.userKey("user:" + userID) }

func (e *Enforcer) scopeRole(role Role) Role {
	role.Name = e.roleKey(role.Name)
	if len(role.Parents) > 0 {
		parents := make([]string, len(role.Parents))
		for i, p := range role.Parents {
			parents[i] = e.roleKey(p)
		}
		role.Parents = parents
	}
	return role
}

func (e *Enforcer) unscopeRoles(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = strings.TrimPrefix(n, e.tenant+tenantSep)
	}
	return out
}

// RegisterRole registers a single role. Duplicate names and cycles are
// rejected (ErrRoleExists, ErrParentNotFound, ErrCycleDetected). The role
// belongs to this Enforcer's tenant: the tenant's admin/owner assigns and
// manages it through this Enforcer only.
func (e *Enforcer) RegisterRole(ctx context.Context, role Role) error {
	if !validRole(role) {
		return ErrInvalidRole
	}
	if err := e.store.AddRole(ctx, e.scopeRole(role)); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	e.flushCache()
	e.invalidateAll(ctx)
	return nil
}

// RegisterRoles registers several roles in order. Registration stops at the
// first error.
func (e *Enforcer) RegisterRoles(ctx context.Context, roles ...Role) error {
	for _, r := range roles {
		if err := e.RegisterRole(ctx, r); err != nil {
			return err
		}
	}
	return nil
}

// AssignRole assigns a role to a user. Both belong to this Enforcer's
// tenant; assignment is performed by the tenant's admin/owner through this
// Enforcer.
func (e *Enforcer) AssignRole(ctx context.Context, userID, roleName string) error {
	if err := e.store.AssignRole(ctx, e.userKey(userID), e.roleKey(roleName)); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	e.dropCache(userID)
	e.invalidateUser(ctx, userID)
	return nil
}

// DeleteRole removes a role. Only callers holding the role-management
// capability (default ("roles", "manage"), see WithRoleManagementPermission)
// may delete roles; anyone else gets ErrPermissionDenied. Stores that do not
// implement role deletion report ErrUnsupported. Roles still assigned to a
// user cannot be deleted (ErrRoleInUse); unassign them first via UnassignRole.
func (e *Enforcer) DeleteRole(ctx context.Context, userID, roleName string) error {
	if err := e.requireManagement(ctx, userID); err != nil {
		return err
	}
	d, ok := e.store.(RoleDeleter)
	if !ok {
		return ErrUnsupported
	}
	if err := d.DeleteRole(ctx, e.roleKey(roleName)); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	e.flushCache()
	e.invalidateAll(ctx)
	return nil
}

// UnassignRole removes a role from targetUserID. Only callers holding the
// role-management capability may unassign roles; anyone else gets
// ErrPermissionDenied. Stores that do not implement role unassignment report
// ErrUnsupported.
func (e *Enforcer) UnassignRole(ctx context.Context, userID, targetUserID, roleName string) error {
	if err := e.requireManagement(ctx, userID); err != nil {
		return err
	}
	u, ok := e.store.(RoleUnassigner)
	if !ok {
		return ErrUnsupported
	}
	if err := u.UnassignRole(ctx, e.userKey(targetUserID), e.roleKey(roleName)); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	e.dropCache(targetUserID)
	e.invalidateUser(ctx, targetUserID)
	return nil
}

// UpdateRole replaces the permissions and parents of an existing role in
// place. Only callers holding the role-management capability may update
// roles; anyone else gets ErrPermissionDenied. Stores that do not implement
// role updates report ErrUnsupported. Role names cannot be changed — the
// name identifies the role; renaming is delete-and-recreate.
func (e *Enforcer) UpdateRole(ctx context.Context, userID string, role Role) error {
	if err := e.requireManagement(ctx, userID); err != nil {
		return err
	}
	if !validRole(role) {
		return ErrInvalidRole
	}
	u, ok := e.store.(RoleUpdater)
	if !ok {
		return ErrUnsupported
	}
	if err := u.UpdateRole(ctx, e.scopeRole(role)); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	e.flushCache()
	e.invalidateAll(ctx)
	return nil
}

// ListRoles returns all roles of this Enforcer's tenant, alphabetically
// sorted, with names stripped of the tenant prefix. Stores that do not
// implement role enumeration report ErrUnsupported. Stores implementing
// RoleListerByPrefix are asked for the tenant's prefix directly, so shared
// stores do not load every tenant's roles.
func (e *Enforcer) ListRoles(ctx context.Context) ([]Role, error) {
	prefix := e.tenant + tenantSep
	var (
		roles []Role
		err   error
	)
	if lp, ok := e.store.(RoleListerByPrefix); ok {
		roles, err = lp.ListRolesByPrefix(ctx, prefix)
	} else {
		l, ok := e.store.(RoleLister)
		if !ok {
			return nil, ErrUnsupported
		}
		var all []Role
		all, err = l.ListRoles(ctx)
		if err != nil {
			return nil, err
		}
		// Cap the initial capacity: in the shared-store multi-tenant pattern
		// the store returns every tenant's roles, so preallocating len(all)
		// would reserve memory for roles this tenant discards.
		out := make([]Role, 0, min(len(all), 32))
		for _, r := range all {
			if strings.HasPrefix(r.Name, prefix) {
				out = append(out, r)
			}
		}
		roles = out
	}
	if err != nil {
		return nil, err
	}
	for i := range roles {
		roles[i].Name = strings.TrimPrefix(roles[i].Name, prefix)
		for j, p := range roles[i].Parents {
			roles[i].Parents[j] = strings.TrimPrefix(p, prefix)
		}
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	return roles, nil
}

// requireManagement enforces the role-management capability on userID.
func (e *Enforcer) requireManagement(ctx context.Context, userID string) error {
	ok, err := e.EnforceCtx(ctx, userID, e.manageRes, e.manageAct)
	if err != nil {
		return err
	}
	if !ok {
		return ErrPermissionDenied
	}
	return nil
}

// versionSource returns the shared policy-version source for this enforcer:
// an explicitly configured one, else the store's when it persists a version.
// It returns nil for stores without a version (fall back to the local
// counter, correct for single-instance deployments).
func (e *Enforcer) versionSource() PolicyVersioner {
	if e.policySource != nil {
		return e.policySource
	}
	if vs, ok := e.store.(PolicyVersioner); ok {
		return vs
	}
	return nil
}

// bumpPolicyVersion advances the policy version after a successful mutation.
// The shared source (store meta table or RedisPolicyVersion) is the source of
// truth; the local counter mirrors the latest value and is the fallback when
// no source is available. The bump is best-effort and never fails an
// already-committed mutation.
func (e *Enforcer) bumpPolicyVersion(ctx context.Context) {
	n := e.policyVersion.Add(1)
	if vs := e.versionSource(); vs != nil {
		if v, err := vs.NextPolicyVersion(ctx); err == nil {
			n = v
			e.policyVersion.Store(n)
		}
	}
}

// currentPolicyVersion returns the version to report for a permission
// snapshot: from the shared source when available, else the local counter.
func (e *Enforcer) currentPolicyVersion(ctx context.Context) uint64 {
	if vs := e.versionSource(); vs != nil {
		if v, err := vs.PolicyVersion(ctx); err == nil {
			e.policyVersion.Store(v)
			return v
		}
	}
	return e.policyVersion.Load()
}

// Enforce reports whether userID may perform action on resource, considering
// the role hierarchy. Errors are treated as deny.
func (e *Enforcer) Enforce(ctx context.Context, userID, resource, action string) bool {
	ok, err := e.EnforceCtx(ctx, userID, resource, action)
	return err == nil && ok
}

// EnforceCtx is like Enforce but also reports the underlying error.
func (e *Enforcer) EnforceCtx(ctx context.Context, userID, resource, action string) (bool, error) {
	perms, err := e.permissionsFor(ctx, userID)
	if err != nil {
		return false, err
	}
	return perms[resource][action], nil
}

// EnforceOwned reports whether userID may perform action on the resource
// owned by owner and belonging to group. Permissions may carry scopes:
//
//   - a plain permission (e.g. "article:delete") is "any": it allows the
//     operation regardless of owner or group;
//   - an explicitly scoped "article:delete:any" behaves like the plain
//     permission;
//   - "article:delete:self" allows the operation only when owner is userID;
//   - "article:delete:grp:hr" allows the operation only on resources of
//     group "hr" (department, team, project, ...);
//   - "create:self" behaves like "create" — creation has no owner yet.
//
// Any matching scope grants the operation ("any" first, then the scoped
// ones). An empty owner never satisfies ":self" (unless userID is also
// empty) and an empty group never satisfies ":grp:". Querying a literal
// ":self"/":grp:" action through Enforce is exact matching and ignores
// owner/group. Errors are treated as deny.
func (e *Enforcer) EnforceOwned(ctx context.Context, userID, owner, group, resource, action string) bool {
	ok, err := e.EnforceOwnedCtx(ctx, userID, owner, group, resource, action)
	return err == nil && ok
}

// EnforceOwnedCtx is like EnforceOwned but also reports the underlying error.
func (e *Enforcer) EnforceOwnedCtx(ctx context.Context, userID, owner, group, resource, action string) (bool, error) {
	perms, err := e.permissionsFor(ctx, userID)
	if err != nil {
		return false, err
	}
	if perms[resource][action] || perms[resource][action+":any"] {
		return true, nil
	}
	if perms[resource][action+":self"] && (owner == userID || action == "create") {
		return true, nil
	}
	if group != "" && perms[resource][action+":grp:"+group] {
		return true, nil
	}
	return false, nil
}

// PermissionView returns a user's access-rights snapshot for a
// "my permissions" endpoint: the directly assigned roles and the effective
// permission set (own + inherited, deduplicated, alphabetically sorted).
// Permissions reflect the cache when one is enabled.
func (e *Enforcer) PermissionView(ctx context.Context, userID string) (PermissionView, error) {
	roles, err := e.store.GetRoles(ctx, e.userKey(userID))
	if err != nil {
		return PermissionView{}, err
	}
	roles = e.unscopeRoles(roles)
	ps, err := e.permissionsFor(ctx, userID)
	if err != nil {
		return PermissionView{}, err
	}
	perms := make(map[string][]string, len(ps))
	for resource, actions := range ps {
		list := make([]string, 0, len(actions))
		for action, allowed := range actions {
			if allowed {
				list = append(list, action)
			}
		}
		sort.Strings(list)
		perms[resource] = list
	}
	roles = append([]string(nil), roles...)
	sort.Strings(roles)
	if roles == nil {
		roles = []string{}
	}
	return PermissionView{
		UserID:        userID,
		Roles:         roles,
		Permissions:   perms,
		PolicyVersion: e.currentPolicyVersion(ctx),
	}, nil
}

// HasRole reports whether userID holds the given role (including inheritance).
func (e *Enforcer) HasRole(ctx context.Context, userID, roleName string) (bool, error) {
	roles, err := e.store.GetRoles(ctx, e.userKey(userID))
	if err != nil {
		return false, err
	}
	seen := map[string]bool{}
	for _, name := range roles {
		if err := e.collectRoleNames(ctx, name, seen); err != nil {
			return false, err
		}
	}
	return seen[e.roleKey(roleName)], nil
}

// permissionsFor returns the effective permission set for a user, consulting
// the cache when enabled.
func (e *Enforcer) permissionsFor(ctx context.Context, userID string) (permissionSet, error) {
	if e.cache != nil {
		if v, ok := e.cache.Get(e.cacheKey(userID)); ok {
			if ps, ok := v.(permissionSet); ok {
				return ps, nil
			}
		}
	}
	ps := make(permissionSet)
	roles, err := e.store.GetRoles(ctx, e.userKey(userID))
	if err != nil {
		return nil, err
	}
	for _, name := range roles {
		if err := e.collectEffective(ctx, name, ps, map[string]bool{}); err != nil {
			return nil, err
		}
	}
	if e.cache != nil {
		e.cache.Set(e.cacheKey(userID), ps)
	}
	return ps, nil
}

func (e *Enforcer) flushCache() {
	if e.cache != nil {
		e.cache.Flush()
	}
}

func (e *Enforcer) dropCache(userID string) {
	if e.cache != nil {
		e.cache.Delete(e.cacheKey(userID))
	}
}

// invalidateAll broadcasts a flush event after a role-level mutation. The
// event is best-effort: a lost event only falls back to TTL expiry.
func (e *Enforcer) invalidateAll(ctx context.Context) {
	if e.invalidator == nil {
		return
	}
	_ = e.invalidator.Publish(ctx, InvalidationEvent{Kind: InvalidateFlush})
}

// invalidateUser broadcasts a drop event after one user's assignments
// changed. The event carries the exact cache key (tenant-scoped), so any
// subscriber — in any tenant — drops precisely that user's snapshot; drops
// for foreign tenants are no-ops on their caches.
func (e *Enforcer) invalidateUser(ctx context.Context, userID string) {
	if e.invalidator == nil {
		return
	}
	_ = e.invalidator.Publish(ctx, InvalidationEvent{Kind: InvalidateDrop, User: e.cacheKey(userID)})
}

// invalidationLoop consumes events from the shared invalidator and applies
// them to this Enforcer's cache. It exits on Close or when the invalidator
// shuts down.
func (e *Enforcer) invalidationLoop() {
	for {
		select {
		case <-e.stopInvalidation:
			return
		case ev, ok := <-e.invalidationMsgs:
			if !ok {
				return
			}
			e.applyInvalidation(ev)
		}
	}
}

func (e *Enforcer) applyInvalidation(ev InvalidationEvent) {
	// A subscriber loop exists only when a cache does (see New), so the
	// cache is never nil here.
	switch ev.Kind {
	case InvalidateFlush:
		e.cache.Flush()
	case InvalidateDrop:
		if ev.User != "" {
			e.cache.Delete(ev.User)
		}
	}
}

// Close stops the cross-instance cache-invalidation subscriber and releases
// the Redis client created by WithConfigFromEnv, if any. Safe to call more
// than once. After Close the Enforcer remains usable, but its cache no
// longer receives invalidation events (or, with an env-owned Redis client,
// serves misses) — decisions stay correct, bounded by TTL like before.
func (e *Enforcer) Close() error {
	e.closeOnce.Do(func() {
		if e.stopInvalidation != nil {
			close(e.stopInvalidation)
		}
		if e.ownedClient != nil {
			_ = e.ownedClient.Close()
		}
	})
	return nil
}

// collectEffective unions the effective permission set of role and all its
// ancestors into perm. The visiting set prevents infinite recursion.
func (e *Enforcer) collectEffective(ctx context.Context, roleName string, perm permissionSet, visiting map[string]bool) error {
	if visiting[roleName] {
		return ErrCycleDetected
	}
	role, ok, err := e.store.GetRole(ctx, roleName)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	visiting[roleName] = true
	defer delete(visiting, roleName)
	for _, p := range role.Permissions {
		if perm[p.Resource] == nil {
			perm[p.Resource] = make(map[string]bool)
		}
		perm[p.Resource][p.Action] = true
	}
	for _, parent := range role.Parents {
		if err := e.collectEffective(ctx, parent, perm, visiting); err != nil {
			return err
		}
	}
	return nil
}

// collectRoleNames records roleName and all inherited role names into seen.
func (e *Enforcer) collectRoleNames(ctx context.Context, roleName string, seen map[string]bool) error {
	if seen[roleName] {
		return nil
	}
	role, ok, err := e.store.GetRole(ctx, roleName)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	seen[roleName] = true
	for _, parent := range role.Parents {
		if err := e.collectRoleNames(ctx, parent, seen); err != nil {
			return err
		}
	}
	return nil
}
