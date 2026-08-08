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
