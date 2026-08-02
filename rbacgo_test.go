package rbacgo

import (
	"context"
	"errors"
	"testing"
)

func testCtx() context.Context { return context.Background() }

func mustEnforcer(t *testing.T, opts ...Option) *Enforcer {
	t.Helper()
	e, err := New(opts...)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	return e
}

func register(t *testing.T, e *Enforcer, roles ...Role) {
	t.Helper()
	if err := e.RegisterRoles(testCtx(), roles...); err != nil {
		t.Fatalf("RegisterRoles(%v) error: %v", roles, err)
	}
}

func TestDefaultStoreIsSQLite(t *testing.T) {
	e := mustEnforcer(t)
	if _, ok := e.store.(*sqlStore); !ok {
		t.Fatalf("default store is %T, want *sqlStore", e.store)
	}
}

func TestEnforceDirectPermission(t *testing.T) {
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{
		Name: "editor",
		Permissions: []Permission{
			{Resource: "articles", Action: "write"},
		},
	})
	if err := e.AssignRole(testCtx(), "u1", "editor"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if !e.Enforce(testCtx(), "u1", "articles", "write") {
		t.Error("expected allow for articles:write")
	}
	if e.Enforce(testCtx(), "u1", "articles", "delete") {
		t.Error("expected deny for articles:delete")
	}
	if e.Enforce(testCtx(), "nobody", "articles", "write") {
		t.Error("expected deny for unknown user")
	}
}

func TestRoleHierarchyInheritance(t *testing.T) {
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e,
		Role{Name: "viewer", Permissions: []Permission{{Resource: "articles", Action: "read"}}},
		Role{Name: "editor", Permissions: []Permission{{Resource: "articles", Action: "write"}}, Parents: []string{"viewer"}},
		Role{Name: "admin", Parents: []string{"editor"}},
	)
	if err := e.AssignRole(testCtx(), "u1", "admin"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	// Transitive inheritance: admin -> editor -> viewer.
	if !e.Enforce(testCtx(), "u1", "articles", "write") {
		t.Error("expected admin to inherit editor permission")
	}
	if !e.Enforce(testCtx(), "u1", "articles", "read") {
		t.Error("expected admin to inherit viewer permission")
	}
	if e.Enforce(testCtx(), "u1", "articles", "delete") {
		t.Error("expected deny for articles:delete")
	}
	has, err := e.HasRole(testCtx(), "u1", "viewer")
	if err != nil || !has {
		t.Errorf("HasRole(viewer) = %v, %v; want true, nil", has, err)
	}
}

func TestMissingParentRejected(t *testing.T) {
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{Name: "viewer"})
	err := e.RegisterRole(testCtx(), Role{Name: "editor", Parents: []string{"ghost"}})
	if !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("got %v, want ErrParentNotFound", err)
	}
}

func TestDuplicateRoleRejected(t *testing.T) {
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{Name: "viewer"})
	err := e.RegisterRole(testCtx(), Role{Name: "viewer"})
	if !errors.Is(err, ErrRoleExists) {
		t.Fatalf("got %v, want ErrRoleExists", err)
	}
}

func TestInvalidRoleRejected(t *testing.T) {
	e := mustEnforcer(t, WithMemoryStore())
	cases := []Role{
		{Name: ""},
		{Name: "x", Permissions: []Permission{{Resource: "", Action: "read"}}},
		{Name: "x", Permissions: []Permission{{Resource: "r", Action: ""}}},
	}
	for _, r := range cases {
		if err := e.RegisterRole(testCtx(), r); !errors.Is(err, ErrInvalidRole) {
			t.Errorf("RegisterRole(%+v) = %v, want ErrInvalidRole", r, err)
		}
	}
}

func TestAssignUnknownRoleRejected(t *testing.T) {
	e := mustEnforcer(t, WithMemoryStore())
	if err := e.AssignRole(testCtx(), "u1", "ghost"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("got %v, want ErrRoleNotFound", err)
	}
}

func TestEnforceUserWithMultipleRoles(t *testing.T) {
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e,
		Role{Name: "reader", Permissions: []Permission{{Resource: "docs", Action: "read"}}},
		Role{Name: "deleter", Permissions: []Permission{{Resource: "docs", Action: "delete"}}},
	)
	if err := e.AssignRole(testCtx(), "u1", "reader"); err != nil {
		t.Fatal(err)
	}
	if err := e.AssignRole(testCtx(), "u1", "deleter"); err != nil {
		t.Fatal(err)
	}
	if !e.Enforce(testCtx(), "u1", "docs", "read") {
		t.Error("expected allow via reader")
	}
	if !e.Enforce(testCtx(), "u1", "docs", "delete") {
		t.Error("expected allow via deleter")
	}
}

func TestHierarchyCycleDefensive(t *testing.T) {
	// Cycles are structurally impossible with the "parents must exist" rule,
	// but the defensive check must not panic and must deny cleanly.
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{Name: "a"}, Role{Name: "b", Parents: []string{"a"}})
	if err := e.AssignRole(testCtx(), "u1", "b"); err != nil {
		t.Fatal(err)
	}
	if e.Enforce(testCtx(), "u1", "x", "y") {
		t.Error("expected deny")
	}
}
