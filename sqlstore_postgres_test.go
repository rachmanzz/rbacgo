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
		"DROP TABLE IF EXISTS pg2_meta",
		"DROP TABLE IF EXISTS pg2_role_assignments",
		"DROP TABLE IF EXISTS pg2_rbac_roles",
		"DROP TABLE IF EXISTS pg2_user_roles",
		"DROP TABLE IF EXISTS pg2_users",
		"DROP TABLE IF EXISTS pg2_role_parents",
		"DROP TABLE IF EXISTS pg2_role_permissions",
		"DROP TABLE IF EXISTS pg2_roles",
		"DROP TABLE IF EXISTS meta",
		"DROP TABLE IF EXISTS role_assignments",
		"DROP TABLE IF EXISTS rbac_roles",
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

	del := store.(RoleDeleter)
	unassign := store.(RoleUnassigner)

	viewer := Role{Name: "pg::viewer", Permissions: []Permission{{Resource: "/articles", Action: "GET"}}}
	editor := Role{
		Name:        "pg::editor",
		Parents:     []string{"pg::viewer"},
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

	if err := store.AssignRole(ctx, "pg::pg-user", "pg::editor"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := store.AssignRole(ctx, "pg-user", "nope"); err != ErrRoleNotFound {
		t.Fatalf("assign missing role error = %v, want ErrRoleNotFound", err)
	}

	roles, err := store.GetRoles(ctx, "pg::pg-user")
	if err != nil {
		t.Fatalf("GetRoles: %v", err)
	}
	if len(roles) != 1 || roles[0] != "pg::editor" {
		t.Fatalf("roles = %v, want [editor]", roles)
	}

	role, ok, err := store.GetRole(ctx, "pg::editor")
	if err != nil || !ok {
		t.Fatalf("GetRole editor: ok=%v err=%v", ok, err)
	}
	if len(role.Permissions) != 1 || role.Permissions[0].Action != "POST" {
		t.Fatalf("editor permissions = %v", role.Permissions)
	}
	hasParent := false
	for _, p := range role.Parents {
		if p == "pg::viewer" {
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
	enforcer, err := New(WithTenant("pg"), WithStore(store))
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

	// --- Role management flow: UnassignRole / DeleteRole ---

	if err := unassign.UnassignRole(ctx, "pg::pg-user", "pg::editor"); err != nil {
		t.Fatalf("UnassignRole: %v", err)
	}
	roles, err = store.GetRoles(ctx, "pg::pg-user")
	if err != nil || len(roles) != 0 {
		t.Fatalf("roles after unassign = %v, %v; want empty", roles, err)
	}
	if err := unassign.UnassignRole(ctx, "pg::pg-user", "pg::editor"); err != nil {
		t.Fatalf("no-op UnassignRole: %v", err)
	}
	if err := unassign.UnassignRole(ctx, "pg-user", "missing"); err != ErrRoleNotFound {
		t.Fatalf("unassign missing role error = %v, want ErrRoleNotFound", err)
	}

	if err := del.DeleteRole(ctx, "pg::editor"); err != nil {
		t.Fatalf("DeleteRole editor: %v", err)
	}
	if _, ok, err := store.GetRole(ctx, "pg::editor"); err != nil || ok {
		t.Fatalf("GetRole deleted editor: ok=%v err=%v, want not found", ok, err)
	}
	if err := del.DeleteRole(ctx, "pg::editor"); err != ErrRoleNotFound {
		t.Fatalf("double DeleteRole error = %v, want ErrRoleNotFound", err)
	}

	// Assigned roles are protected.
	if err := store.AssignRole(ctx, "pg-user", "pg-a"); err != nil {
		t.Fatalf("AssignRole pg-a: %v", err)
	}
	if err := del.DeleteRole(ctx, "pg-a"); err != ErrRoleInUse {
		t.Fatalf("DeleteRole in-use error = %v, want ErrRoleInUse", err)
	}
	if err := unassign.UnassignRole(ctx, "pg-user", "pg-a"); err != nil {
		t.Fatalf("UnassignRole pg-a: %v", err)
	}
	if err := del.DeleteRole(ctx, "pg-a"); err != nil {
		t.Fatalf("DeleteRole pg-a after unassign: %v", err)
	}

	// Deleting a parent role cascades the parent link out of its children.
	if err := del.DeleteRole(ctx, "pg-b"); err != nil {
		t.Fatalf("DeleteRole pg-b: %v", err)
	}
	pgc, ok, err := store.GetRole(ctx, "pg-c")
	if err != nil || !ok {
		t.Fatalf("GetRole pg-c: ok=%v err=%v", ok, err)
	}
	if len(pgc.Parents) != 0 {
		t.Fatalf("pg-c parents = %v, want empty after pg-b deleted", pgc.Parents)
	}

	// Capability-gated management via the enforcer.
	manager := Role{Name: "pg::pg-manager", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}
	if err := store.AddRole(ctx, manager); err != nil {
		t.Fatalf("AddRole pg-manager: %v", err)
	}
	if err := store.AssignRole(ctx, "pg::pg-admin", "pg::pg-manager"); err != nil {
		t.Fatalf("AssignRole pg-admin: %v", err)
	}
	if err := enforcer.DeleteRole(ctx, "pg-admin", "viewer"); err != nil {
		t.Fatalf("DeleteRole viewer: %v", err)
	}
	if enforcer.Enforce(ctx, "pg-user", "/articles", "GET") {
		t.Fatal("expected deny after viewer deleted, got allow")
	}
	if err := enforcer.DeleteRole(ctx, "pg-user", "pg-c"); err != ErrPermissionDenied {
		t.Fatalf("DeleteRole by non-manager error = %v, want ErrPermissionDenied", err)
	}
	if err := enforcer.UnassignRole(ctx, "pg-admin", "pg-admin", "pg-manager"); err != nil {
		t.Fatalf("UnassignRole pg-manager: %v", err)
	}
	if err := enforcer.DeleteRole(ctx, "pg-admin", "pg-manager"); err != ErrPermissionDenied {
		t.Fatalf("DeleteRole after losing capability error = %v, want ErrPermissionDenied", err)
	}

	// Table prefix: a second store namespaced on the same database.
	pref, err := NewSQLStore(db, WithTablePrefix("pg2_"))
	if err != nil {
		t.Fatalf("NewSQLStore prefixed: %v", err)
	}
	// Same visible role name as the deleted main-table editor: must not leak
	// between table prefixes.
	if err := pref.AddRole(ctx, Role{Name: "pg::editor", Permissions: []Permission{{Resource: "/p", Action: "GET"}}}); err != nil {
		t.Fatalf("AddRole prefixed: %v", err)
	}
	if _, ok, err := store.GetRole(ctx, "pg::editor"); err != nil || ok {
		t.Fatalf("unprefixed store sees prefixed role: ok=%v err=%v", ok, err)
	}
	if err := pref.AssignRole(ctx, "pg::pg2-user", "pg::editor"); err != nil {
		t.Fatalf("AssignRole prefixed: %v", err)
	}
	prefEnforcer, err := New(WithTenant("pg"), WithStore(pref))
	if err != nil {
		t.Fatalf("New prefixed: %v", err)
	}
	if !prefEnforcer.Enforce(ctx, "pg2-user", "/p", "GET") {
		t.Fatal("expected allow via prefixed tables on Postgres")
	}

	// The policy version is stored in the shared meta table: both the main
	// store and a freshly opened second instance agree on it after the
	// enforcer-level mutations above.
	vs := store.(PolicyVersioner)
	v, err := vs.PolicyVersion(ctx)
	if err != nil || v == 0 {
		t.Fatalf("store policy version = %d, %v; want > 0 after mutations", v, err)
	}
	second, err := NewSQLStore(db)
	if err != nil {
		t.Fatalf("NewSQLStore second: %v", err)
	}
	if v2, err := second.(PolicyVersioner).PolicyVersion(ctx); err != nil || v2 != v {
		t.Fatalf("second instance version = %d, %v; want %d", v2, err, v)
	}
}
