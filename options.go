package rbacgo

import (
	"database/sql"
	"fmt"
	"strings"
)

// WithStore sets the persistence backend explicitly.
func WithStore(s Store) Option {
	return func(e *Enforcer) error {
		if s == nil {
			return fmt.Errorf("rbacgo: nil store")
		}
		e.store = s
		return nil
	}
}

// WithSQLStore wraps an existing *sql.DB (any database/sql driver, e.g. pgx /
// pgxpool via the pgx stdlib adapter) in a SQL store. See NewSQLStore.
func WithSQLStore(db *sql.DB, opts ...SQLStoreOption) Option {
	return func(e *Enforcer) error {
		s, err := NewSQLStore(db, opts...)
		if err != nil {
			return err
		}
		e.store = s
		return nil
	}
}

// WithMemoryStore uses the pure-Go in-memory store.
func WithMemoryStore() Option {
	return WithStore(NewMemoryStore())
}

// WithLRU enables the lookup cache with the given backend (see NewMemoryLRU,
// NewRedisLRU). The cache stores each user's effective permission set and is
// invalidated on role registration, update, deletion, and assignment changes.
func WithLRU(backend CacheBackend) Option {
	return func(e *Enforcer) error {
		if backend == nil {
			return fmt.Errorf("rbacgo: nil cache backend")
		}
		e.cache = backend
		return nil
	}
}

// WithRoleManagementPermission overrides the capability required to manage
// roles (RegisterRole / UpdateRole / DeleteRole / UnassignRole). The default
// is the ("roles", "manage") permission.
func WithRoleManagementPermission(resource, action string) Option {
	return func(e *Enforcer) error {
		if strings.TrimSpace(resource) == "" || strings.TrimSpace(action) == "" {
			return fmt.Errorf("rbacgo: invalid role management permission")
		}
		e.manageRes = resource
		e.manageAct = action
		return nil
	}
}

// WithPolicyVersionStore sets the shared policy-version source explicitly
// (e.g. NewRedisPolicyVersion for multi-instance deployments that want the
// version in Redis). Defaults to the store itself when it implements
// PolicyVersioner — the SQL store's meta table — and to a per-instance
// counter otherwise.
func WithPolicyVersionStore(vs PolicyVersioner) Option {
	return func(e *Enforcer) error {
		if vs == nil {
			return fmt.Errorf("rbacgo: nil policy version store")
		}
		e.policySource = vs
		return nil
	}
}

// WithTenant sets the tenant (organization, workspace, app, …) this Enforcer
// is scoped to. Required: New returns ErrTenantRequired without it. Roles,
// users, and cache entries are namespaced by the tenant, so one shared store
// can serve many tenants without cross-tenant access. The tenant owning a
// role is the tenant of the Enforcer that registered it; assignments are
// made by that tenant's admin/owner through this Enforcer.
//
// The tenant ID must not contain the internal separator "::" — role and user
// names are prefixed with it, so a tenant like "a::b" would share store keys
// with tenant "a" role "b::x" and break isolation. Role and user names may
// contain "::" safely: within one tenant they are full suffixes of their
// keys.
func WithTenant(tenant string) Option {
	return func(e *Enforcer) error {
		if strings.TrimSpace(tenant) == "" {
			return fmt.Errorf("rbacgo: empty tenant")
		}
		t := strings.TrimSpace(tenant)
		if strings.Contains(t, tenantSep) {
			return fmt.Errorf("rbacgo: tenant %q contains the reserved separator %q", t, tenantSep)
		}
		e.tenant = t
		return nil
	}
}
