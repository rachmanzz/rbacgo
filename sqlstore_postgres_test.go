//go:build integration

package rbacgo

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// TestSQLStorePostgres runs the full RBAC flow against a real PostgreSQL to
// verify the Postgres dialect (parametrized $N placeholders, ON CONFLICT,
// transactions, cycle detection).
//
// Run with:
//
//	go test -tags integration -run TestSQLStorePostgres ./...
//
// It requires a reachable PostgreSQL server. Set RBAC_TEST_POSTGRES_DSN to
// override the default local test DSN. The test skips (not fails) when no
// server is reachable.
func TestSQLStorePostgres(t *testing.T) {
	dsn := os.Getenv("RBAC_TEST_POSTGRES_DSN")
	if dsn == "" {
		dsn = "postgres://rbac:test@localhost:5433/rbac?sslmode=disable"
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open pgx: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		t.Skipf("postgres not reachable at %q: %v", dsn, err)
	}

	cleanup := []string{
		"DROP TABLE IF EXISTS user_roles",
		"DROP TABLE IF EXISTS users",
		"DROP TABLE IF EXISTS role_parents",
		"DROP TABLE IF EXISTS role_permissions",
		"DROP TABLE IF EXISTS roles",
	}
	for _, q := range cleanup {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("cleanup %q: %v", q, err)
		}
	}

	store, err := NewSQLStore(db)
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	ctx := context.Background()

	viewer := Role{Name: "viewer", Permissions: []Permission{{Resource: "/articles", Action: "GET"}}}
	editor := Role{
		Name:        "editor",
		Parents:     []string{"viewer"},
		Permissions: []Permission{{Resource: "/articles", Action: "POST"}},
	}
	if err := store.AddRole(ctx, viewer); err != nil {
		t.Fatalf("AddRole viewer: %v", err)
	}
	if err := store.AddRole(ctx, editor); err != nil {
		t.Fatalf("AddRole editor: %v", err)
	}
	if err := store.AddRole(ctx, viewer); err != ErrRoleExists {
		t.Fatalf("duplicate AddRole error = %v, want ErrRoleExists", err)
	}
	if err := store.AddRole(ctx, Role{Name: "orphan", Parents: []string{"missing"}}); err != ErrParentNotFound {
		t.Fatalf("missing parent error = %v, want ErrParentNotFound", err)
	}

	if err := store.AssignRole(ctx, "pg-user", "editor"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := store.AssignRole(ctx, "pg-user", "nope"); err != ErrRoleNotFound {
		t.Fatalf("assign missing role error = %v, want ErrRoleNotFound", err)
	}

	roles, err := store.GetRoles(ctx, "pg-user")
	if err != nil {
		t.Fatalf("GetRoles: %v", err)
	}
	if len(roles) != 1 || roles[0] != "editor" {
		t.Fatalf("roles = %v, want [editor]", roles)
	}

	role, ok, err := store.GetRole(ctx, "editor")
	if err != nil || !ok {
		t.Fatalf("GetRole editor: ok=%v err=%v", ok, err)
	}
	if len(role.Permissions) != 1 || role.Permissions[0].Action != "POST" {
		t.Fatalf("editor permissions = %v", role.Permissions)
	}
	hasParent := false
	for _, p := range role.Parents {
		if p == "viewer" {
			hasParent = true
		}
	}
	if !hasParent {
		t.Fatalf("editor parents = %v, want to include viewer", role.Parents)
	}

	// Deep hierarchy exercises recursive parent traversal on PostgreSQL
	// (cycle-check recursion must close rows before issuing the next query).
	if err := store.AddRole(ctx, Role{Name: "pg-a"}); err != nil {
		t.Fatalf("AddRole pg-a: %v", err)
	}
	if err := store.AddRole(ctx, Role{Name: "pg-b", Parents: []string{"pg-a"}}); err != nil {
		t.Fatalf("AddRole pg-b: %v", err)
	}
	if err := store.AddRole(ctx, Role{Name: "pg-c", Parents: []string{"pg-b"}}); err != nil {
		t.Fatalf("AddRole pg-c: %v", err)
	}
	// Cycles are structurally impossible with the "parents must exist" rule;
	// this asserts the defensive rollback path for a bad parent instead.
	if err := store.AddRole(ctx, Role{Name: "pg-orphan", Parents: []string{"pg-missing"}}); err != ErrParentNotFound {
		t.Fatalf("orphan parent error = %v, want ErrParentNotFound", err)
	}

	// End-to-end enforcement via the Enforcer on top of the SQL store.
	enforcer, err := New(WithStore(store))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !enforcer.Enforce(ctx, "pg-user", "/articles", "GET") {
		t.Fatal("expected inherited GET via hierarchy, got deny")
	}
	if !enforcer.Enforce(ctx, "pg-user", "/articles", "POST") {
		t.Fatal("expected own POST, got deny")
	}
	if enforcer.Enforce(ctx, "pg-user", "/articles", "DELETE") {
		t.Fatal("expected deny for DELETE, got allow")
	}
}
