package rbacgo

import (
	"context"
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
}

// Option configures an Enforcer. Options are applied in order; environment
// configuration only fills values not already set explicitly.
type Option func(*Enforcer) error

// New creates an Enforcer. With no options it uses an embedded SQLite store
// in memory (":memory:"). Supply WithSQLStore / WithSQLite / WithStore /
// WithConfigFromEnv to customise persistence and WithLRU to enable caching.
func New(opts ...Option) (*Enforcer, error) {
	e := &Enforcer{}
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
	e.dropCache(userID)
	return nil
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
