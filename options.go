package rbacgo

import (
	"database/sql"
	"fmt"
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
func WithSQLStore(db *sql.DB) Option {
	return func(e *Enforcer) error {
		s, err := NewSQLStore(db)
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
