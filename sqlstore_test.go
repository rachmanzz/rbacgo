package rbacgo

import (
	"context"
	"errors"
	"testing"
)

func sqliteStore(t *testing.T, path string) Store {
	t.Helper()
	s, err := newSQLiteStore(path)
	if err != nil {
		t.Fatalf("newSQLiteStore(%q): %v", path, err)
	}
	return s
}

func TestSQLStoreCRUD(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t, ":memory:")

	if err := s.AddRole(ctx, Role{Name: "viewer", Permissions: []Permission{{Resource: "a", Action: "read"}}}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	role, ok, err := s.GetRole(ctx, "viewer")
	if err != nil || !ok {
		t.Fatalf("GetRole = %v, %v; err %v", role, ok, err)
	}
	if len(role.Permissions) != 1 || role.Permissions[0] != (Permission{Resource: "a", Action: "read"}) {
		t.Errorf("unexpected permissions: %+v", role.Permissions)
	}

	if err := s.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	roles, err := s.GetRoles(ctx, "u1")
	if err != nil || len(roles) != 1 || roles[0] != "viewer" {
		t.Errorf("GetRoles = %v, %v", roles, err)
	}

	if err := s.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Errorf("idempotent AssignRole should not error: %v", err)
	}
	if _, ok, _ := s.GetRole(ctx, "missing"); ok {
		t.Error("GetRole(missing) reported found")
	}
}

func TestSQLStoreHierarchyAndCycles(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t, ":memory:")
	if err := s.AddRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRole(ctx, Role{Name: "editor", Parents: []string{"viewer"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRole(ctx, Role{Name: "editor", Parents: []string{"viewer"}}); !errors.Is(err, ErrRoleExists) {
		t.Fatalf("got %v, want ErrRoleExists", err)
	}
	if err := s.AddRole(ctx, Role{Name: "solo", Parents: []string{"ghost"}}); !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("got %v, want ErrParentNotFound", err)
	}
}

func TestSQLStorePersistenceAcrossReopen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping file-backed persistence test in short mode")
	}
	dir := t.TempDir()
	path := dir + "/rbac.db"

	ctx := context.Background()
	s1 := sqliteStore(t, path)
	if err := s1.AddRole(ctx, Role{Name: "admin", Permissions: []Permission{{Resource: "users", Action: "delete"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s1.AssignRole(ctx, "u1", "admin"); err != nil {
		t.Fatal(err)
	}

	s2 := sqliteStore(t, path)
	role, ok, err := s2.GetRole(ctx, "admin")
	if err != nil || !ok {
		t.Fatalf("reopen GetRole = ok %v, err %v", ok, err)
	}
	if len(role.Permissions) != 1 || role.Permissions[0].Action != "delete" {
		t.Errorf("reopen permissions mismatch: %+v", role.Permissions)
	}
	roles, err := s2.GetRoles(ctx, "u1")
	if err != nil || len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("reopen GetRoles = %v, %v", roles, err)
	}
}

func TestEnforcerWithSQLStore(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithSQLite(":memory:"))
	register(t, e,
		Role{Name: "viewer", Permissions: []Permission{{Resource: "articles", Action: "read"}}},
		Role{Name: "editor", Permissions: []Permission{{Resource: "articles", Action: "write"}}, Parents: []string{"viewer"}},
	)
	if err := e.AssignRole(ctx, "u1", "editor"); err != nil {
		t.Fatal(err)
	}
	if !e.Enforce(ctx, "u1", "articles", "write") {
		t.Error("expected allow write")
	}
	if !e.Enforce(ctx, "u1", "articles", "read") {
		t.Error("expected inherited read")
	}
	if e.Enforce(ctx, "u1", "articles", "delete") {
		t.Error("expected deny delete")
	}
}
