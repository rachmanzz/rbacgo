package rbacgo

import (
	"database/sql"
	"fmt"

	_ "github.com/mattn/go-sqlite3" // SQLite driver for the default embedded store
)

// WithSQLite configures the embedded SQLite store. path may be ":memory:" for
// an ephemeral database or a file path for persistence. For ":memory:" the
// store is serialized onto a single connection so concurrent access shares one
// database.
func WithSQLite(path string) Option {
	return func(e *Enforcer) error {
		s, err := newSQLiteStore(path)
		if err != nil {
			return err
		}
		e.store = s
		return nil
	}
}

func newSQLiteStore(path string) (Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("rbacgo: open sqlite: %w", err)
	}
	if path == ":memory:" {
		// Each :memory: connection opens a brand-new, empty database, so the
		// pool must be capped at one connection to keep concurrent access
		// consistent.
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("rbacgo: ping sqlite: %w", err)
	}
	s, err := NewSQLStore(db)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}
