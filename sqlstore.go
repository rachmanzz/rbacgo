package rbacgo

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// sqlStore is a Store backed by any *sql.DB from database/sql. It is fully
// pluggable at the driver/pool level: pass a pool created with pgx/pgxpool
// (via the pgx stdlib adapter), go-sqlite3, or any other driver. Only SQLite
// and PostgreSQL dialects are officially supported.
type sqlStore struct {
	db  *sql.DB
	ph  func(n int) string // placeholder generator for the active dialect
	sql sqlQueries
}

// dbStats exposes database/sql pool statistics for tests.
func (s *sqlStore) dbStats() sql.DBStats {
	return s.db.Stats()
}

// sqlQueries holds the parametrized statements for one dialect.
type sqlQueries struct {
	createTables string
	insertRole   string
	insertPerm   string
	insertParent string
	insertUser   string
	assignRole   string
	userRoles    string
	rolePerms    string
	roleParents  string
	roleExists   string
}

type dialect int

const (
	dialectSQLite dialect = iota
	dialectPostgres
)

// detectDialect probes the connected database to tell SQLite apart from other
// drivers (e.g. pgx/PostgreSQL).
func detectDialect(db *sql.DB) dialect {
	var v string
	if err := db.QueryRow(`SELECT sqlite_version()`).Scan(&v); err == nil {
		return dialectSQLite
	}
	return dialectPostgres
}

func (d dialect) param(i int) string {
	if d == dialectSQLite {
		return "?"
	}
	return fmt.Sprintf("$%d", i)
}

// NewSQLStore builds a Store on top of an existing *sql.DB. It runs the schema
// migration immediately and detects the SQL dialect (SQLite vs PostgreSQL)
// automatically.
func NewSQLStore(db *sql.DB) (Store, error) {
	if db == nil {
		return nil, fmt.Errorf("rbacgo: nil *sql.DB")
	}
	d := detectDialect(db)
	s := &sqlStore{db: db, ph: d.param, sql: buildQueries(d)}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *sqlStore) migrate() error {
	_, err := s.db.Exec(s.sql.createTables)
	return err
}

func buildQueries(d dialect) sqlQueries {
	p := d.param
	noConflict := "ON CONFLICT DO NOTHING"
	return sqlQueries{
		createTables: strings.Join([]string{
			`CREATE TABLE IF NOT EXISTS roles (name TEXT PRIMARY KEY)`,
			`CREATE TABLE IF NOT EXISTS role_permissions (` +
				`role_name TEXT NOT NULL, resource TEXT NOT NULL, action TEXT NOT NULL,` +
				`PRIMARY KEY (role_name, resource, action))`,
			`CREATE TABLE IF NOT EXISTS role_parents (` +
				`role_name TEXT NOT NULL, parent_name TEXT NOT NULL,` +
				`PRIMARY KEY (role_name, parent_name))`,
			`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY)`,
			`CREATE TABLE IF NOT EXISTS user_roles (` +
				`user_id TEXT NOT NULL, role_name TEXT NOT NULL,` +
				`PRIMARY KEY (user_id, role_name))`,
		}, ";"),
		insertRole: fmt.Sprintf(`INSERT INTO roles (name) VALUES (%s)`, p(1)),
		insertPerm: fmt.Sprintf(
			`INSERT INTO role_permissions (role_name, resource, action) VALUES (%s, %s, %s) %s`,
			p(1), p(2), p(3), noConflict),
		insertParent: fmt.Sprintf(
			`INSERT INTO role_parents (role_name, parent_name) VALUES (%s, %s) %s`,
			p(1), p(2), noConflict),
		insertUser: fmt.Sprintf(
			`INSERT INTO users (id) VALUES (%s) %s`, p(1), noConflict),
		assignRole: fmt.Sprintf(
			`INSERT INTO user_roles (user_id, role_name) VALUES (%s, %s) %s`,
			p(1), p(2), noConflict),
		userRoles: fmt.Sprintf(
			`SELECT role_name FROM user_roles WHERE user_id = %s`, p(1)),
		rolePerms: fmt.Sprintf(
			`SELECT resource, action FROM role_permissions WHERE role_name = %s`, p(1)),
		roleParents: fmt.Sprintf(
			`SELECT parent_name FROM role_parents WHERE role_name = %s`, p(1)),
		roleExists: fmt.Sprintf(
			`SELECT COUNT(*) FROM roles WHERE name = %s`, p(1)),
	}
}

func (s *sqlStore) AddRole(ctx context.Context, role Role) error {
	if !validRole(role) {
		return ErrInvalidRole
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	exists, err := s.roleExists(ctx, tx, role.Name)
	if err != nil {
		return err
	}
	if exists {
		return ErrRoleExists
	}

	if _, err := tx.ExecContext(ctx, s.sql.insertRole, role.Name); err != nil {
		return err
	}
	for _, perm := range role.Permissions {
		if _, err := tx.ExecContext(ctx, s.sql.insertPerm, role.Name, perm.Resource, perm.Action); err != nil {
			return err
		}
	}
	for _, parent := range role.Parents {
		ok, err := s.roleExists(ctx, tx, parent)
		if err != nil {
			return err
		}
		if !ok {
			return ErrParentNotFound
		}
		if _, err := tx.ExecContext(ctx, s.sql.insertParent, role.Name, parent); err != nil {
			return err
		}
	}

	// Defensive cycle check across the graph after inserting the role.
	if err := s.checkCycles(ctx, tx, role.Name); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *sqlStore) GetRole(ctx context.Context, name string) (Role, bool, error) {
	exists, err := s.roleExists(ctx, s.db, name)
	if err != nil {
		return Role{}, false, err
	}
	if !exists {
		return Role{}, false, nil
	}

	role := Role{Name: name}

	rows, err := s.db.QueryContext(ctx, s.sql.rolePerms, name)
	if err != nil {
		return Role{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.Resource, &p.Action); err != nil {
			return Role{}, false, err
		}
		role.Permissions = append(role.Permissions, p)
	}
	if err := rows.Err(); err != nil {
		return Role{}, false, err
	}

	rows, err = s.db.QueryContext(ctx, s.sql.roleParents, name)
	if err != nil {
		return Role{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var parent string
		if err := rows.Scan(&parent); err != nil {
			return Role{}, false, err
		}
		role.Parents = append(role.Parents, parent)
	}
	return role, true, rows.Err()
}

func (s *sqlStore) AssignRole(ctx context.Context, userID, roleName string) error {
	ok, err := s.roleExists(ctx, s.db, roleName)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRoleNotFound
	}
	if _, err := s.db.ExecContext(ctx, s.sql.insertUser, userID); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, s.sql.assignRole, userID, roleName); err != nil {
		return err
	}
	return nil
}

func (s *sqlStore) GetRoles(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, s.sql.userRoles, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		roles = append(roles, name)
	}
	return roles, rows.Err()
}

// checkCycles verifies that roleName is not reachable from itself via parents.
func (s *sqlStore) checkCycles(ctx context.Context, q querrer, roleName string) error {
	visiting := map[string]bool{}
	var visit func(name string) error
	visit = func(name string) error {
		if visiting[name] {
			return ErrCycleDetected
		}
		visiting[name] = true
		defer delete(visiting, name)

		rows, err := q.QueryContext(ctx, s.sql.roleParents, name)
		if err != nil {
			return err
		}
		// Collect parents and close rows before recursing: issuing further
		// queries on the same transaction while rows are still open fails on
		// PostgreSQL ("conn busy").
		var parents []string
		for rows.Next() {
			var parent string
			if err := rows.Scan(&parent); err != nil {
				rows.Close()
				return err
			}
			parents = append(parents, parent)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()

		for _, parent := range parents {
			if err := visit(parent); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(roleName)
}

type querrer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *sqlStore) roleExists(ctx context.Context, q querrer, name string) (bool, error) {
	var count int
	if err := q.QueryRowContext(ctx, s.sql.roleExists, name).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
