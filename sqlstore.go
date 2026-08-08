package rbacgo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// sqlStore is a Store backed by any *sql.DB from database/sql. It is fully
// pluggable at the driver/pool level: pass a pool created with pgx/pgxpool
// (via the pgx stdlib adapter), go-sqlite3, or any other driver. Only SQLite
// and PostgreSQL dialects are officially supported.
type sqlStore struct {
	db          *sql.DB
	ph          func(n int) string // placeholder generator for the active dialect
	sql         sqlQueries
	tablePrefix string
}

// dbStats exposes database/sql pool statistics for tests.
func (s *sqlStore) dbStats() sql.DBStats {
	return s.db.Stats()
}

// sqlQueries holds the parametrized statements for one dialect.
type sqlQueries struct {
	createTables        string
	insertRole          string
	insertPerm          string
	insertParent        string
	assignRole          string
	userRoles           string
	rolePerms           string
	roleParents         string
	roleExists          string
	roleInUse           string
	deleteRole          string
	deleteRolePerms     string
	deleteRoleParents   string
	deleteParentLinks   string
	unassignRole        string
	listRoles           string
	listRolesByPrefix   string
	listPerms           string
	listPermsByPrefix   string
	listParents         string
	listParentsByPrefix string
	policyVersion       string
	nextPolicyVersion   string
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
// automatically. SQLStoreOptions (e.g. WithTablePrefix) may customize the
// store.
func NewSQLStore(db *sql.DB, opts ...SQLStoreOption) (Store, error) {
	if db == nil {
		return nil, fmt.Errorf("rbacgo: nil *sql.DB")
	}
	d := detectDialect(db)
	s := &sqlStore{db: db, ph: d.param}
	for _, opt := range opts {
		if err := opt(s); err != nil {
			return nil, err
		}
	}
	s.sql = buildQueries(d, s.tablePrefix)
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

// SQLStoreOption configures a SQL store built by NewSQLStore.
type SQLStoreOption func(*sqlStore) error

// WithTablePrefix namespaces every SQL table behind prefix (e.g. "myapp_").
// Use it when multiple applications or tenants share one database, so their
// tables do not collide. An empty prefix is allowed and keeps the default
// table names.
func WithTablePrefix(prefix string) SQLStoreOption {
	return func(s *sqlStore) error {
		if !validTablePrefix(prefix) {
			return fmt.Errorf("rbacgo: invalid table prefix %q (letters, digits and underscore only; must not start with a digit)", prefix)
		}
		s.tablePrefix = prefix
		return nil
	}
}

// validTablePrefix reports whether prefix is empty or a safe SQL identifier
// fragment: it must not start with a digit (unquoted identifiers cannot).
func validTablePrefix(prefix string) bool {
	if prefix == "" {
		return true
	}
	if prefix[0] >= '0' && prefix[0] <= '9' {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func (s *sqlStore) migrate() error {
	_, err := s.db.Exec(s.sql.createTables)
	return err
}

func buildQueries(d dialect, tablePrefix string) sqlQueries {
	p := d.param
	noConflict := "ON CONFLICT DO NOTHING"
	roles := tablePrefix + "roles"
	rolePerms := tablePrefix + "role_permissions"
	roleParents := tablePrefix + "role_parents"
	userRoles := tablePrefix + "role_assignments"
	meta := tablePrefix + "meta"
	return sqlQueries{
		createTables: strings.Join([]string{
			`CREATE TABLE IF NOT EXISTS ` + roles + ` (name TEXT PRIMARY KEY)`,
			`CREATE TABLE IF NOT EXISTS ` + rolePerms + ` (` +
				`role_name TEXT NOT NULL, resource TEXT NOT NULL, action TEXT NOT NULL,` +
				`PRIMARY KEY (role_name, resource, action))`,
			`CREATE TABLE IF NOT EXISTS ` + roleParents + ` (` +
				`role_name TEXT NOT NULL, parent_name TEXT NOT NULL,` +
				`PRIMARY KEY (role_name, parent_name))`,
			`CREATE TABLE IF NOT EXISTS ` + userRoles + ` (` +
				`user_id TEXT NOT NULL, role_name TEXT NOT NULL,` +
				`PRIMARY KEY (user_id, role_name))`,
			`CREATE TABLE IF NOT EXISTS ` + meta + ` (key TEXT PRIMARY KEY, value INTEGER NOT NULL)`,
		}, ";"),
		insertRole: fmt.Sprintf(`INSERT INTO %s (name) VALUES (%s)`, roles, p(1)),
		insertPerm: fmt.Sprintf(
			`INSERT INTO %s (role_name, resource, action) VALUES (%s, %s, %s) %s`,
			rolePerms, p(1), p(2), p(3), noConflict),
		insertParent: fmt.Sprintf(
			`INSERT INTO %s (role_name, parent_name) VALUES (%s, %s) %s`,
			roleParents, p(1), p(2), noConflict),
		assignRole: fmt.Sprintf(
			`INSERT INTO %s (user_id, role_name) VALUES (%s, %s) %s`,
			userRoles, p(1), p(2), noConflict),
		userRoles: fmt.Sprintf(
			`SELECT role_name FROM %s WHERE user_id = %s`, userRoles, p(1)),
		rolePerms: fmt.Sprintf(
			`SELECT resource, action FROM %s WHERE role_name = %s`, rolePerms, p(1)),
		roleParents: fmt.Sprintf(
			`SELECT parent_name FROM %s WHERE role_name = %s`, roleParents, p(1)),
		roleExists: fmt.Sprintf(
			`SELECT COUNT(*) FROM %s WHERE name = %s`, roles, p(1)),
		roleInUse: fmt.Sprintf(
			`SELECT COUNT(*) FROM %s WHERE role_name = %s`, userRoles, p(1)),
		deleteRole: fmt.Sprintf(
			`DELETE FROM %s WHERE name = %s`, roles, p(1)),
		deleteRolePerms: fmt.Sprintf(
			`DELETE FROM %s WHERE role_name = %s`, rolePerms, p(1)),
		deleteRoleParents: fmt.Sprintf(
			`DELETE FROM %s WHERE role_name = %s`, roleParents, p(1)),
		deleteParentLinks: fmt.Sprintf(
			`DELETE FROM %s WHERE parent_name = %s`, roleParents, p(1)),
		unassignRole: fmt.Sprintf(
			`DELETE FROM %s WHERE user_id = %s AND role_name = %s`,
			userRoles, p(1), p(2)),
		listRoles: fmt.Sprintf(
			`SELECT name FROM %s ORDER BY name`, roles),
		listRolesByPrefix: fmt.Sprintf(
			`SELECT name FROM %s WHERE name LIKE %s ESCAPE '\' ORDER BY name`, roles, p(1)),
		listPerms: fmt.Sprintf(
			`SELECT role_name, resource, action FROM %s ORDER BY role_name`, rolePerms),
		listPermsByPrefix: fmt.Sprintf(
			`SELECT role_name, resource, action FROM %s WHERE role_name LIKE %s ESCAPE '\' ORDER BY role_name`, rolePerms, p(1)),
		listParents: fmt.Sprintf(
			`SELECT role_name, parent_name FROM %s ORDER BY role_name`, roleParents),
		listParentsByPrefix: fmt.Sprintf(
			`SELECT role_name, parent_name FROM %s WHERE role_name LIKE %s ESCAPE '\' ORDER BY role_name`, roleParents, p(1)),
		policyVersion: fmt.Sprintf(
			`SELECT value FROM %s WHERE key = 'policy'`, meta),
		nextPolicyVersion: fmt.Sprintf(
			`INSERT INTO %s (key, value) VALUES ('policy', 1) ON CONFLICT(key) DO UPDATE SET value = %s.value + 1 RETURNING %s.value`,
			meta, meta, meta),
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

// ListRoles returns every role in the store, alphabetically sorted. It uses
// three bulk queries (names, permissions, parents) instead of fetching each
// role separately, so the cost is proportional to the data, not to the number
// of roles times queries per role.
func (s *sqlStore) ListRoles(ctx context.Context) ([]Role, error) {
	return s.listRolesPattern(ctx, s.sql.listRoles, s.sql.listPerms, s.sql.listParents, "")
}

// ListRolesByPrefix returns the roles whose names begin with prefix,
// alphabetically sorted. Enforcers on shared stores use it so a single
// tenant's listing loads only that tenant's rows.
func (s *sqlStore) ListRolesByPrefix(ctx context.Context, prefix string) ([]Role, error) {
	pattern := escapeLike(prefix) + "%"
	return s.listRolesPattern(ctx, s.sql.listRolesByPrefix, s.sql.listPermsByPrefix, s.sql.listParentsByPrefix, pattern)
}

func (s *sqlStore) listRolesPattern(ctx context.Context, namesQ, permsQ, parentsQ, pattern string) ([]Role, error) {
	names, err := s.roleNames(ctx, namesQ, pattern)
	if err != nil {
		return nil, err
	}
	out := make([]Role, 0, len(names))
	index := make(map[string]int, len(names))
	for i, name := range names {
		out = append(out, Role{Name: name})
		index[name] = i
	}
	if err := s.loadRolePerms(ctx, permsQ, pattern, out, index); err != nil {
		return nil, err
	}
	if err := s.loadRoleParents(ctx, parentsQ, pattern, out, index); err != nil {
		return nil, err
	}
	return out, nil
}

// roleNames returns the alphabetically sorted role names (optionally limited
// to a LIKE pattern). The result set is closed before any other query runs,
// keeping single-connection databases (e.g. SQLite :memory:) usable.
func (s *sqlStore) roleNames(ctx context.Context, q, pattern string) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if pattern == "" {
		rows, err = s.db.QueryContext(ctx, q)
	} else {
		rows, err = s.db.QueryContext(ctx, q, pattern)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

// loadRolePerms fills roles with their permissions in one grouped query.
func (s *sqlStore) loadRolePerms(ctx context.Context, q, pattern string, roles []Role, index map[string]int) error {
	var (
		rows *sql.Rows
		err  error
	)
	if pattern == "" {
		rows, err = s.db.QueryContext(ctx, q)
	} else {
		rows, err = s.db.QueryContext(ctx, q, pattern)
	}
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var roleName, resource, action string
		if err := rows.Scan(&roleName, &resource, &action); err != nil {
			return err
		}
		if i, ok := index[roleName]; ok {
			roles[i].Permissions = append(roles[i].Permissions, Permission{Resource: resource, Action: action})
		}
	}
	return rows.Err()
}

// loadRoleParents fills roles with their parent links in one grouped query.
func (s *sqlStore) loadRoleParents(ctx context.Context, q, pattern string, roles []Role, index map[string]int) error {
	var (
		rows *sql.Rows
		err  error
	)
	if pattern == "" {
		rows, err = s.db.QueryContext(ctx, q)
	} else {
		rows, err = s.db.QueryContext(ctx, q, pattern)
	}
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var roleName, parent string
		if err := rows.Scan(&roleName, &parent); err != nil {
			return err
		}
		if i, ok := index[roleName]; ok {
			roles[i].Parents = append(roles[i].Parents, parent)
		}
	}
	return rows.Err()
}

// escapeLike escapes the LIKE metacharacters of s so it can be used as a
// literal prefix in a LIKE pattern (with ESCAPE '\').
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

// UpdateRole replaces a role's permissions and parent links atomically.
func (s *sqlStore) UpdateRole(ctx context.Context, role Role) error {
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
	if !exists {
		return ErrRoleNotFound
	}

	// Replace permissions and parent links wholesale.
	for _, q := range []string{s.sql.deleteRolePerms, s.sql.deleteRoleParents} {
		if _, err := tx.ExecContext(ctx, q, role.Name); err != nil {
			return err
		}
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

	if err := s.checkCycles(ctx, tx, role.Name); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *sqlStore) AssignRole(ctx context.Context, userID, roleName string) error {
	ok, err := s.roleExists(ctx, s.db, roleName)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRoleNotFound
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

// DeleteRole removes a role atomically: its permissions, parent links, and
// child parent links are removed together with the role itself. Deleting a
// role that is still assigned to a user fails with ErrRoleInUse.
func (s *sqlStore) DeleteRole(ctx context.Context, name string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // rollback after commit is a no-op

	exists, err := s.roleExists(ctx, tx, name)
	if err != nil {
		return err
	}
	if !exists {
		return ErrRoleNotFound
	}
	inUse, err := s.roleInUse(ctx, tx, name)
	if err != nil {
		return err
	}
	if inUse {
		return ErrRoleInUse
	}
	// Cascade: remove child links first so child roles never keep a dangling
	// parent reference.
	for _, q := range []string{s.sql.deleteParentLinks, s.sql.deleteRoleParents, s.sql.deleteRolePerms, s.sql.deleteRole} {
		if _, err := tx.ExecContext(ctx, q, name); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// UnassignRole removes a role from a user's assignments. Unassigning a role
// the user does not hold is a no-op.
func (s *sqlStore) UnassignRole(ctx context.Context, userID, roleName string) error {
	ok, err := s.roleExists(ctx, s.db, roleName)
	if err != nil {
		return err
	}
	if !ok {
		return ErrRoleNotFound
	}
	if _, err := s.db.ExecContext(ctx, s.sql.unassignRole, userID, roleName); err != nil {
		return err
	}
	return nil
}

// roleInUse reports whether any user is currently assigned the role.
func (s *sqlStore) roleInUse(ctx context.Context, q querrer, name string) (bool, error) {
	var count int
	if err := q.QueryRowContext(ctx, s.sql.roleInUse, name).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

// policyVersion reports the currently committed policy version (0 before any
// mutation is ever recorded through an Enforcer).
func (s *sqlStore) PolicyVersion(ctx context.Context) (uint64, error) {
	var v uint64
	err := s.db.QueryRowContext(ctx, s.sql.policyVersion).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

// NextPolicyVersion atomically advances the policy version in the shared meta
// table and returns the new value. Every Enforcer instance that performs a
// mutation agrees on the next value, so multi-instance deployments share one
// version.
func (s *sqlStore) NextPolicyVersion(ctx context.Context) (uint64, error) {
	var v uint64
	err := s.db.QueryRowContext(ctx, s.sql.nextPolicyVersion).Scan(&v)
	return v, err
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
