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
// invalidated on role registration and role assignment.
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
// roles (DeleteRole / UnassignRole). The default is the ("roles", "manage")
// permission.
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
