package rbacgo

import (
	"context"
	"errors"
	"testing"
	"time"
)

// roleMgmtStubStore implements Store but neither RoleDeleter nor
// RoleUnassigner. "admin" holds the default role-management capability,
// "broken" triggers a store error during the capability check.
type roleMgmtStubStore struct{}

func (roleMgmtStubStore) AddRole(context.Context, Role) error              { return nil }
func (roleMgmtStubStore) AssignRole(context.Context, string, string) error { return nil }
func (roleMgmtStubStore) GetRole(context.Context, string) (Role, bool, error) {
	return Role{Name: "manager", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}, true, nil
}
func (roleMgmtStubStore) GetRoles(_ context.Context, userID string) ([]string, error) {
	if userID == "t::broken" {
		return nil, errTest
	}
	if userID == "t::admin" {
		return []string{"manager"}, nil
	}
	return nil, nil
}

func TestDeleteRolePermissionDenied(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithTenant("t"), WithStore(roleMgmtStubStore{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.DeleteRole(ctx, "user", "viewer"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("DeleteRole = %v, want ErrPermissionDenied", err)
	}
}

func TestDeleteRoleUnsupportedStore(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithTenant("t"), WithStore(roleMgmtStubStore{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.DeleteRole(ctx, "admin", "viewer"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("DeleteRole = %v, want ErrUnsupported", err)
	}
}

func TestDeleteRoleEnforceError(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithTenant("t"), WithStore(roleMgmtStubStore{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.DeleteRole(ctx, "broken", "viewer"); !errors.Is(err, errTest) {
		t.Fatalf("DeleteRole = %v, want capability-check error", err)
	}
}

func TestUnassignRolePermissionDenied(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithTenant("t"), WithStore(roleMgmtStubStore{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.UnassignRole(ctx, "user", "someone", "viewer"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("UnassignRole = %v, want ErrPermissionDenied", err)
	}
}

func TestUnassignRoleUnsupportedStore(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithTenant("t"), WithStore(roleMgmtStubStore{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.UnassignRole(ctx, "admin", "someone", "viewer"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("UnassignRole = %v, want ErrUnsupported", err)
	}
}

func TestUnassignRoleEnforceError(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithTenant("t"), WithStore(roleMgmtStubStore{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.UnassignRole(ctx, "broken", "someone", "viewer"); !errors.Is(err, errTest) {
		t.Fatalf("UnassignRole = %v, want capability-check error", err)
	}
}

func TestMemoryStoreAddRoleInvalid(t *testing.T) {
	s := NewMemoryStore().(*memoryStore)
	if err := s.AddRole(testCtx(), Role{}); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("AddRole = %v, want ErrInvalidRole", err)
	}
	if err := s.UpdateRole(testCtx(), Role{}); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("UpdateRole = %v, want ErrInvalidRole", err)
	}
}

func TestMemoryStoreDeleteRoleNotFound(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore().(*memoryStore)
	if err := s.DeleteRole(ctx, "missing"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("DeleteRole = %v, want ErrRoleNotFound", err)
	}
}

func TestMemoryStoreDeleteRoleInUse(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore().(*memoryStore)
	if err := s.AddRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := s.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := s.DeleteRole(ctx, "viewer"); !errors.Is(err, ErrRoleInUse) {
		t.Fatalf("DeleteRole = %v, want ErrRoleInUse", err)
	}
}

func TestMemoryStoreRoleIndexConsistency(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore().(*memoryStore)
	if err := s.AddRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := s.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("AssignRole u1: %v", err)
	}
	if err := s.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("AssignRole u1 (dup): %v", err)
	}
	if err := s.AssignRole(ctx, "u2", "viewer"); err != nil {
		t.Fatalf("AssignRole u2: %v", err)
	}
	if got := len(s.roleUsers["viewer"]); got != 2 {
		t.Fatalf("index size = %d, want 2", got)
	}
	if got, _ := s.GetRoles(ctx, "u1"); len(got) != 1 {
		t.Fatalf("u1 roles = %v, want one entry (no duplicate)", got)
	}
	if err := s.UnassignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("UnassignRole: %v", err)
	}
	if _, ok := s.roleUsers["viewer"]["u1"]; ok {
		t.Fatal("index still holds u1 after unassign")
	}
	if err := s.UnassignRole(ctx, "u3", "viewer"); err != nil {
		t.Fatalf("UnassignRole unassigned user: %v", err)
	}
	if err := s.UnassignRole(ctx, "u2", "viewer"); err != nil {
		t.Fatalf("UnassignRole u2: %v", err)
	}
	if len(s.roleUsers["viewer"]) != 0 {
		t.Fatalf("index not empty after all unassigns: %v", s.roleUsers["viewer"])
	}
	if err := s.DeleteRole(ctx, "viewer"); err != nil {
		t.Fatalf("DeleteRole after full unassign: %v", err)
	}
	if _, ok := s.roleUsers["viewer"]; ok {
		t.Fatal("roleUsers entry not removed with role")
	}
}

func TestMemoryStoreDeleteRoleCascadesParents(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore().(*memoryStore)
	if err := s.AddRole(ctx, Role{Name: "base"}); err != nil {
		t.Fatalf("AddRole base: %v", err)
	}
	if err := s.AddRole(ctx, Role{Name: "removed"}); err != nil {
		t.Fatalf("AddRole removed: %v", err)
	}
	child := Role{Name: "child", Parents: []string{"base", "removed"}}
	if err := s.AddRole(ctx, child); err != nil {
		t.Fatalf("AddRole child: %v", err)
	}
	if err := s.DeleteRole(ctx, "removed"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	got, ok, err := s.GetRole(ctx, "child")
	if err != nil || !ok {
		t.Fatalf("GetRole child: ok=%v err=%v", ok, err)
	}
	if len(got.Parents) != 1 || got.Parents[0] != "base" {
		t.Fatalf("child parents = %v, want [base]", got.Parents)
	}
	if _, ok, _ := s.GetRole(ctx, "removed"); ok {
		t.Fatal("removed role still exists")
	}
}

func TestMemoryStoreUnassignRoleNotFound(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore().(*memoryStore)
	if err := s.UnassignRole(ctx, "u1", "missing"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("UnassignRole = %v, want ErrRoleNotFound", err)
	}
}

func TestMemoryStoreUnassignRoleFreesRole(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore().(*memoryStore)
	if err := s.AddRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := s.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := s.UnassignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("UnassignRole: %v", err)
	}
	roles, err := s.GetRoles(ctx, "u1")
	if err != nil || len(roles) != 0 {
		t.Fatalf("GetRoles = %v, %v; want empty", roles, err)
	}
	if err := s.DeleteRole(ctx, "viewer"); err != nil {
		t.Fatalf("DeleteRole after unassign: %v", err)
	}
}

func TestSQLStoreDeleteRoleMockPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("BeginTx error", func(t *testing.T) {
		sharedMock.beginErr = errTest
		defer func() { sharedMock.beginErr = nil }()
		s := newMockSQLStore()
		if err := s.DeleteRole(ctx, "r"); !errors.Is(err, errTest) {
			t.Fatalf("DeleteRole = %v, want BeginTx error", err)
		}
	})

	t.Run("roleExists error", func(t *testing.T) {
		s := newMockSQLStore(mockStep{queryErr: errTest})
		if err := s.DeleteRole(ctx, "r"); !errors.Is(err, errTest) {
			t.Fatalf("DeleteRole = %v, want roleExists error", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		s := newMockSQLStore(mockStep{cols: 1, rows: 1, val: int64(0)})
		if err := s.DeleteRole(ctx, "r"); !errors.Is(err, ErrRoleNotFound) {
			t.Fatalf("DeleteRole = %v, want ErrRoleNotFound", err)
		}
	})

	t.Run("in use", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{cols: 1, rows: 1, val: int64(1)},
		)
		if err := s.DeleteRole(ctx, "r"); !errors.Is(err, ErrRoleInUse) {
			t.Fatalf("DeleteRole = %v, want ErrRoleInUse", err)
		}
	})

	t.Run("roleInUse error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{queryErr: errTest},
		)
		if err := s.DeleteRole(ctx, "r"); !errors.Is(err, errTest) {
			t.Fatalf("DeleteRole = %v, want roleInUse error", err)
		}
	})

	t.Run("exec error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{cols: 1, rows: 1, val: int64(0)},
			mockStep{execErr: errTest},
		)
		if err := s.DeleteRole(ctx, "r"); !errors.Is(err, errTest) {
			t.Fatalf("DeleteRole = %v, want exec error", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{cols: 1, rows: 1, val: int64(0)},
			mockStep{},
			mockStep{},
			mockStep{},
			mockStep{},
		)
		if err := s.DeleteRole(ctx, "r"); err != nil {
			t.Fatalf("DeleteRole: %v", err)
		}
	})
}

func TestSQLStoreUnassignRoleMockPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("roleExists error", func(t *testing.T) {
		s := newMockSQLStore(mockStep{queryErr: errTest})
		if err := s.UnassignRole(ctx, "u", "r"); !errors.Is(err, errTest) {
			t.Fatalf("UnassignRole = %v, want roleExists error", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		s := newMockSQLStore(mockStep{cols: 1, rows: 1, val: int64(0)})
		if err := s.UnassignRole(ctx, "u", "r"); !errors.Is(err, ErrRoleNotFound) {
			t.Fatalf("UnassignRole = %v, want ErrRoleNotFound", err)
		}
	})

	t.Run("exec error", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{execErr: errTest},
		)
		if err := s.UnassignRole(ctx, "u", "r"); !errors.Is(err, errTest) {
			t.Fatalf("UnassignRole = %v, want exec error", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		s := newMockSQLStore(
			mockStep{cols: 1, rows: 1, val: int64(1)},
			mockStep{},
		)
		if err := s.UnassignRole(ctx, "u", "r"); err != nil {
			t.Fatalf("UnassignRole: %v", err)
		}
	})
}

func TestEnforcerRoleManagementFlow(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithTenant("t"), WithMemoryStore(), WithLRU(NewMemoryLRU(16, time.Hour)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	manager := Role{Name: "manager", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}
	backupManager := Role{Name: "backup-manager", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}
	viewer := Role{Name: "viewer", Permissions: []Permission{{Resource: "/articles", Action: "GET"}}}
	editor := Role{Name: "editor", Permissions: []Permission{{Resource: "/articles", Action: "POST"}}}
	if err := e.RegisterRoles(ctx, manager, backupManager, viewer, editor); err != nil {
		t.Fatalf("RegisterRoles: %v", err)
	}
	if err := e.AssignRole(ctx, "admin", "manager"); err != nil {
		t.Fatalf("AssignRole admin: %v", err)
	}
	if err := e.AssignRole(ctx, "admin", "editor"); err != nil {
		t.Fatalf("AssignRole admin editor: %v", err)
	}
	if err := e.AssignRole(ctx, "superuser", "backup-manager"); err != nil {
		t.Fatalf("AssignRole superuser: %v", err)
	}
	if err := e.AssignRole(ctx, "user", "viewer"); err != nil {
		t.Fatalf("AssignRole user: %v", err)
	}
	if !e.Enforce(ctx, "admin", "roles", "manage") {
		t.Fatal("admin should hold the role-management capability")
	}
	if !e.Enforce(ctx, "user", "/articles", "GET") {
		t.Fatal("user should be able to GET articles")
	}

	// UnassignRole drops the target user's cache immediately.
	if err := e.UnassignRole(ctx, "admin", "user", "viewer"); err != nil {
		t.Fatalf("UnassignRole: %v", err)
	}
	if e.Enforce(ctx, "user", "/articles", "GET") {
		t.Fatal("user should lose access right after unassign")
	}
	// Unassigning a role the user does not hold is a no-op.
	if err := e.UnassignRole(ctx, "admin", "user", "viewer"); err != nil {
		t.Fatalf("second UnassignRole: %v", err)
	}

	// DeleteRole works once the role is free, and flushes every cached user.
	if err := e.DeleteRole(ctx, "admin", "viewer"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	if err := e.DeleteRole(ctx, "admin", "viewer"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("second DeleteRole = %v, want ErrRoleNotFound", err)
	}
	if err := e.UnassignRole(ctx, "admin", "user", "viewer"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("UnassignRole of deleted role = %v, want ErrRoleNotFound", err)
	}

	// Still assigned roles cannot be deleted, even by their own holder.
	if err := e.DeleteRole(ctx, "admin", "editor"); !errors.Is(err, ErrRoleInUse) {
		t.Fatalf("DeleteRole editor = %v, want ErrRoleInUse", err)
	}
	if err := e.UnassignRole(ctx, "admin", "admin", "editor"); err != nil {
		t.Fatalf("UnassignRole admin: %v", err)
	}
	if err := e.DeleteRole(ctx, "admin", "editor"); err != nil {
		t.Fatalf("DeleteRole editor after unassign: %v", err)
	}
	if err := e.DeleteRole(ctx, "admin", "manager"); !errors.Is(err, ErrRoleInUse) {
		t.Fatalf("DeleteRole manager = %v, want ErrRoleInUse", err)
	}
	if err := e.UnassignRole(ctx, "admin", "admin", "manager"); err != nil {
		t.Fatalf("UnassignRole manager: %v", err)
	}
	// The backup manager still holds the capability and completes the delete.
	if err := e.DeleteRole(ctx, "superuser", "manager"); err != nil {
		t.Fatalf("DeleteRole manager after unassign: %v", err)
	}
	if e.Enforce(ctx, "admin", "roles", "manage") {
		t.Fatal("admin should lose the capability after manager is deleted")
	}
}

func TestCustomRoleManagementPermission(t *testing.T) {
	ctx := context.Background()
	e, err := New(
		WithTenant("t"),
		WithMemoryStore(),
		WithRoleManagementPermission("acl", "manage"),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	manager := Role{Name: "acl-manager", Permissions: []Permission{{Resource: "acl", Action: "manage"}}}
	viewer := Role{Name: "viewer", Permissions: []Permission{{Resource: "/articles", Action: "GET"}}}
	if err := e.RegisterRoles(ctx, manager, viewer); err != nil {
		t.Fatalf("RegisterRoles: %v", err)
	}
	if err := e.AssignRole(ctx, "admin", "acl-manager"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := e.AssignRole(ctx, "user", "viewer"); err != nil {
		t.Fatalf("AssignRole user: %v", err)
	}
	// The default ("roles", "manage") capability no longer grants access.
	if e.Enforce(ctx, "admin", "roles", "manage") {
		t.Fatal("admin must not hold the default capability")
	}
	if err := e.DeleteRole(ctx, "user", "viewer"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("DeleteRole = %v, want ErrPermissionDenied", err)
	}
	if err := e.UnassignRole(ctx, "admin", "user", "viewer"); err != nil {
		t.Fatalf("UnassignRole: %v", err)
	}
	if err := e.DeleteRole(ctx, "admin", "viewer"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
}

func TestWithRoleManagementPermissionInvalid(t *testing.T) {
	if _, err := New(WithRoleManagementPermission("", "manage")); err == nil {
		t.Fatal("empty resource must be rejected")
	}
	if _, err := New(WithRoleManagementPermission("roles", "  ")); err == nil {
		t.Fatal("blank action must be rejected")
	}
}

// failUpdateRoleStore implements RoleUpdater but always errors, so the
// Enforcer propagates store failures.
type failUpdateRoleStore struct {
	Store
}

func (failUpdateRoleStore) UpdateRole(context.Context, Role) error { return errTest }

// failListRolesStore implements RoleLister but always errors.
type failListRolesStore struct {
	Store
}

func (failListRolesStore) ListRoles(context.Context) ([]Role, error) { return nil, errTest }

func TestUpdateRole(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e,
		Role{Name: "manager", Permissions: []Permission{{Resource: "roles", Action: "manage"}}},
		Role{Name: "viewer", Permissions: []Permission{{Resource: "articles", Action: "read"}}},
		Role{Name: "editor", Permissions: []Permission{{Resource: "articles", Action: "write"}}, Parents: []string{"viewer"}},
	)
	if err := e.AssignRole(ctx, "admin", "manager"); err != nil {
		t.Fatal(err)
	}
	if err := e.AssignRole(ctx, "u1", "editor"); err != nil {
		t.Fatal(err)
	}
	if !e.Enforce(ctx, "u1", "articles", "write") {
		t.Fatal("u1 should hold editor perms")
	}
	if _, err := e.PermissionView(ctx, "u1"); err != nil {
		t.Fatalf("PermissionView: %v", err)
	}

	// Non-managers cannot update roles.
	if err := e.UpdateRole(ctx, "u1", Role{Name: "viewer", Permissions: []Permission{{Resource: "articles", Action: "delete"}}}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("UpdateRole by non-manager = %v, want ErrPermissionDenied", err)
	}
	// Invalid roles are rejected before touching the store.
	if err := e.UpdateRole(ctx, "admin", Role{}); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("UpdateRole invalid = %v, want ErrInvalidRole", err)
	}
	// Unknown roles cannot be updated.
	if err := e.UpdateRole(ctx, "admin", Role{Name: "ghost"}); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("UpdateRole missing = %v, want ErrRoleNotFound", err)
	}
	// Missing parents are rejected.
	if err := e.UpdateRole(ctx, "admin", Role{Name: "viewer", Parents: []string{"ghost"}}); !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("UpdateRole missing parent = %v, want ErrParentNotFound", err)
	}
	// Cycles are rejected: editor -> viewer exists, so viewer -> editor would cycle.
	if err := e.UpdateRole(ctx, "admin", Role{Name: "viewer", Parents: []string{"editor"}}); !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("UpdateRole cycle = %v, want ErrCycleDetected", err)
	}

	// A successful update replaces permissions and parents in place.
	if err := e.UpdateRole(ctx, "admin", Role{
		Name:        "viewer",
		Permissions: []Permission{{Resource: "articles", Action: "read"}, {Resource: "articles", Action: "delete"}},
	}); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	if !e.Enforce(ctx, "u1", "articles", "delete") {
		t.Fatal("u1 must see the updated permissions immediately (cache flushed)")
	}
	if !e.Enforce(ctx, "u1", "articles", "write") {
		t.Fatal("u1 must keep editor permissions")
	}
}

func TestUpdateRoleUnsupportedStore(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithTenant("t"), WithStore(roleMgmtStubStore{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.UpdateRole(ctx, "user", Role{Name: "viewer"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("UpdateRole = %v, want ErrPermissionDenied", err)
	}
	if err := e.UpdateRole(ctx, "admin", Role{Name: "viewer"}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("UpdateRole = %v, want ErrUnsupported", err)
	}
	if err := e.UpdateRole(ctx, "broken", Role{Name: "viewer"}); !errors.Is(err, errTest) {
		t.Fatalf("UpdateRole = %v, want capability-check error", err)
	}
}

func TestUpdateRoleStoreError(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	if err := ms.AddRole(ctx, Role{Name: "t::manager", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}); err != nil {
		t.Fatal(err)
	}
	if err := ms.AddRole(ctx, Role{Name: "t::viewer"}); err != nil {
		t.Fatal(err)
	}
	if err := ms.AssignRole(ctx, "t::admin", "t::manager"); err != nil {
		t.Fatal(err)
	}
	e := mustEnforcer(t, WithStore(failUpdateRoleStore{Store: ms}))
	if err := e.UpdateRole(ctx, "admin", Role{Name: "viewer"}); !errors.Is(err, errTest) {
		t.Fatalf("UpdateRole = %v, want store error", err)
	}
}

func TestUpdateRoleTenantIsolation(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	eA, err := New(WithTenant("a"), WithStore(ms))
	if err != nil {
		t.Fatal(err)
	}
	eB, err := New(WithTenant("b"), WithStore(ms))
	if err != nil {
		t.Fatal(err)
	}
	manager := Role{Name: "manager", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}
	for _, e := range []*Enforcer{eA, eB} {
		register(t, e, manager, Role{Name: "viewer", Permissions: []Permission{{Resource: "articles", Action: "read"}}})
		if err := e.AssignRole(ctx, "admin", "manager"); err != nil {
			t.Fatal(err)
		}
		if err := e.AssignRole(ctx, "alice", "viewer"); err != nil {
			t.Fatal(err)
		}
	}
	if err := eA.UpdateRole(ctx, "admin", Role{Name: "viewer", Permissions: []Permission{{Resource: "articles", Action: "delete"}}}); err != nil {
		t.Fatal(err)
	}
	if !eA.Enforce(ctx, "alice", "articles", "delete") {
		t.Fatal("tenant a must see its updated viewer")
	}
	if eA.Enforce(ctx, "alice", "articles", "read") {
		t.Fatal("tenant a's viewer must have its permissions replaced")
	}
	if eB.Enforce(ctx, "alice", "articles", "delete") {
		t.Fatal("tenant b's viewer must be unaffected by tenant a's update")
	}
	if !eB.Enforce(ctx, "alice", "articles", "read") {
		t.Fatal("tenant b's viewer must keep its own permissions")
	}
}

func TestListRoles(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e,
		Role{Name: "viewer", Permissions: []Permission{{Resource: "articles", Action: "read"}}},
		Role{Name: "editor", Permissions: []Permission{{Resource: "articles", Action: "write"}}, Parents: []string{"viewer"}},
		Role{Name: "admin", Permissions: []Permission{{Resource: "roles", Action: "manage"}}},
	)
	roles, err := e.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 3 {
		t.Fatalf("ListRoles = %d roles, want 3", len(roles))
	}
	// Alphabetical order, names unscoped.
	if roles[0].Name != "admin" || roles[1].Name != "editor" || roles[2].Name != "viewer" {
		t.Fatalf("ListRoles order/names = %+v", roles)
	}
	if len(roles[1].Parents) != 1 || roles[1].Parents[0] != "viewer" {
		t.Fatalf("ListRoles parents not unscoped: %+v", roles[1].Parents)
	}
	// Mutating the result must not corrupt the store.
	roles[0].Permissions = append(roles[0].Permissions, Permission{Resource: "HACKED", Action: "admin"})
	again, _ := e.ListRoles(ctx)
	if len(again[0].Permissions) != 1 {
		t.Fatal("ListRoles result must be a defensive copy")
	}
}

func TestListRolesUnsupportedStore(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithTenant("t"), WithStore(roleMgmtStubStore{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := e.ListRoles(ctx); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ListRoles = %v, want ErrUnsupported", err)
	}
}

func TestListRolesStoreError(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithStore(failListRolesStore{Store: NewMemoryStore()}))
	if _, err := e.ListRoles(ctx); !errors.Is(err, errTest) {
		t.Fatalf("ListRoles = %v, want store error", err)
	}
}

func TestListRolesPrefixStoreError(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithStore(failPrefixListStore{Store: NewMemoryStore()}))
	if _, err := e.ListRoles(ctx); !errors.Is(err, errTest) {
		t.Fatalf("ListRoles = %v, want prefix-store error", err)
	}
}

func TestListRolesTenantScoped(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	eA, err := New(WithTenant("a"), WithStore(ms))
	if err != nil {
		t.Fatal(err)
	}
	eB, err := New(WithTenant("b"), WithStore(ms))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*Enforcer{eA, eB} {
		register(t, e,
			Role{Name: "viewer", Permissions: []Permission{{Resource: "articles", Action: "read"}}},
			Role{Name: "editor", Parents: []string{"viewer"}},
		)
	}
	if err := eA.RegisterRole(ctx, Role{Name: "a-only"}); err != nil {
		t.Fatal(err)
	}
	rolesA, err := eA.ListRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rolesA) != 3 || rolesA[0].Name != "a-only" || rolesA[2].Name != "viewer" {
		t.Fatalf("ListRoles(a) = %+v, want exactly a's roles", rolesA)
	}
	rolesB, err := eB.ListRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rolesB) != 2 || rolesB[0].Name != "editor" || rolesB[1].Name != "viewer" {
		t.Fatalf("ListRoles(b) = %+v, want exactly b's roles", rolesB)
	}
	if rolesB[0].Parents[0] != "viewer" {
		t.Fatalf("ListRoles(b) parents = %+v, want unscoped [viewer]", rolesB[0].Parents)
	}
}

// listOnlyStore wraps a memory store but exposes only the plain RoleLister
// capability, forcing Enforcer.ListRoles onto its filter-and-unscope fallback.
type listOnlyStore struct{ Store }

func (s listOnlyStore) ListRoles(ctx context.Context) ([]Role, error) {
	l, ok := s.Store.(RoleLister)
	if !ok {
		return nil, ErrUnsupported
	}
	return l.ListRoles(ctx)
}

// failPrefixListStore implements RoleListerByPrefix but always errors.
type failPrefixListStore struct{ Store }

func (failPrefixListStore) ListRolesByPrefix(context.Context, string) ([]Role, error) {
	return nil, errTest
}

func TestListRolesPlainRoleListerFallback(t *testing.T) {
	ctx := context.Background()
	eA, err := New(WithTenant("a"), WithStore(listOnlyStore{Store: NewMemoryStore()}))
	if err != nil {
		t.Fatal(err)
	}
	eB, err := New(WithTenant("b"), WithStore(listOnlyStore{Store: eA.Store()}))
	if err != nil {
		t.Fatal(err)
	}
	register(t, eA,
		Role{Name: "viewer", Permissions: []Permission{{Resource: "articles", Action: "read"}}},
		Role{Name: "editor", Parents: []string{"viewer"}},
	)
	if err := eB.RegisterRole(ctx, Role{Name: "other"}); err != nil {
		t.Fatal(err)
	}
	rolesA, err := eA.ListRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rolesA) != 2 || rolesA[0].Name != "editor" || rolesA[1].Name != "viewer" {
		t.Fatalf("ListRoles(a) = %+v, want a's roles only", rolesA)
	}
	if rolesA[0].Parents[0] != "viewer" {
		t.Fatalf("ListRoles(a) parents = %+v, want unscoped [viewer]", rolesA[0].Parents)
	}
	rolesA[1].Permissions = append(rolesA[1].Permissions, Permission{Resource: "HACKED", Action: "admin"})
	if again, _ := eA.ListRoles(ctx); len(again[1].Permissions) != 1 {
		t.Fatal("fallback ListRoles result must be a defensive copy")
	}
}

func TestListRolesByPrefixEscapesLikeMeta(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t, ":memory:")
	eUnderscore, err := New(WithTenant("a_b"), WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	eWildcard, err := New(WithTenant("a%b"), WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	eNeighbour, err := New(WithTenant("axb"), WithStore(s))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*Enforcer{eUnderscore, eWildcard, eNeighbour} {
		if err := e.RegisterRole(ctx, Role{Name: "viewer"}); err != nil {
			t.Fatal(err)
		}
	}
	roles, err := eUnderscore.ListRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0].Name != "viewer" {
		t.Fatalf("ListRoles(a_b) = %+v, want exactly a_b's roles (LIKE metachar escaped)", roles)
	}
}
