package rbacgo

import (
	"context"
	"sort"
	"sync/atomic"
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
}

// Option configures an Enforcer. Options are applied in order; environment
// configuration only fills values not already set explicitly.
type Option func(*Enforcer) error

// New creates an Enforcer. With no options it uses an embedded SQLite store
// in memory (":memory:"). Supply WithSQLStore / WithSQLite / WithStore /
// WithConfigFromEnv to customise persistence and WithLRU to enable caching.
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
	return e, nil
}

// Store returns the underlying Store.
func (e *Enforcer) Store() Store { return e.store }

// RegisterRole registers a single role. Duplicate names and cycles are
// rejected (ErrRoleExists, ErrParentNotFound, ErrCycleDetected).
func (e *Enforcer) RegisterRole(ctx context.Context, role Role) error {
	if err := e.store.AddRole(ctx, role); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	e.flushCache()
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

// AssignRole assigns a role to a user.
func (e *Enforcer) AssignRole(ctx context.Context, userID, roleName string) error {
	if err := e.store.AssignRole(ctx, userID, roleName); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	e.dropCache(userID)
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
	if err := d.DeleteRole(ctx, roleName); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	e.flushCache()
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
	if err := u.UnassignRole(ctx, targetUserID, roleName); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	e.dropCache(targetUserID)
	return nil
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

// PermissionView returns a user's access-rights snapshot for a
// "my permissions" endpoint: the directly assigned roles and the effective
// permission set (own + inherited, deduplicated, alphabetically sorted).
// Permissions reflect the cache when one is enabled.
func (e *Enforcer) PermissionView(ctx context.Context, userID string) (PermissionView, error) {
	roles, err := e.store.GetRoles(ctx, userID)
	if err != nil {
		return PermissionView{}, err
	}
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
	roles, err := e.store.GetRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	seen := map[string]bool{}
	for _, name := range roles {
		if err := e.collectRoleNames(ctx, name, seen); err != nil {
			return false, err
		}
	}
	return seen[roleName], nil
}

// permissionsFor returns the effective permission set for a user, consulting
// the cache when enabled.
func (e *Enforcer) permissionsFor(ctx context.Context, userID string) (permissionSet, error) {
	if e.cache != nil {
		if v, ok := e.cache.Get("user:" + userID); ok {
			if ps, ok := v.(permissionSet); ok {
				return ps, nil
			}
		}
	}
	ps := make(permissionSet)
	roles, err := e.store.GetRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, name := range roles {
		if err := e.collectEffective(ctx, name, ps, map[string]bool{}); err != nil {
			return nil, err
		}
	}
	if e.cache != nil {
		e.cache.Set("user:"+userID, ps)
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
		e.cache.Delete("user:" + userID)
	}
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
