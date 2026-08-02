package rbacgo

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestPermissionViewBasic(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithMemoryStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	viewer := Role{Name: "viewer", Permissions: []Permission{{Resource: "/comments", Action: "GET"}}}
	editor := Role{
		Name:        "editor",
		Parents:     []string{"viewer"},
		Permissions: []Permission{{Resource: "/articles", Action: "POST"}, {Resource: "/articles", Action: "GET"}},
	}
	if err := e.RegisterRoles(ctx, viewer, editor); err != nil {
		t.Fatalf("RegisterRoles: %v", err)
	}
	if err := e.AssignRole(ctx, "user-123", "editor"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	view, err := e.PermissionView(ctx, "user-123")
	if err != nil {
		t.Fatalf("PermissionView: %v", err)
	}
	if view.UserID != "user-123" {
		t.Fatalf("UserID = %q, want user-123", view.UserID)
	}
	if len(view.Roles) != 1 || view.Roles[0] != "editor" {
		t.Fatalf("Roles = %v, want [editor]", view.Roles)
	}
	articles, ok := view.Permissions["/articles"]
	if !ok || len(articles) != 2 || articles[0] != "GET" || articles[1] != "POST" {
		t.Fatalf("/articles actions = %v, want sorted [GET POST]", articles)
	}
	comments, ok := view.Permissions["/comments"]
	if !ok || len(comments) != 1 || comments[0] != "GET" {
		t.Fatalf("/comments actions = %v, want [GET] (inherited)", comments)
	}
}

func TestPermissionViewJSONShape(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithMemoryStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	viewer := Role{Name: "viewer", Permissions: []Permission{{Resource: "/comments", Action: "GET"}}}
	editor := Role{
		Name:        "editor",
		Parents:     []string{"viewer"},
		Permissions: []Permission{{Resource: "/articles", Action: "GET"}, {Resource: "/articles", Action: "POST"}},
	}
	if err := e.RegisterRoles(ctx, viewer, editor); err != nil {
		t.Fatalf("RegisterRoles: %v", err)
	}
	if err := e.AssignRole(ctx, "user-123", "editor"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	view, err := e.PermissionView(ctx, "user-123")
	if err != nil {
		t.Fatalf("PermissionView: %v", err)
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"user_id":"user-123","roles":["editor"],"permissions":{"/articles":["GET","POST"],"/comments":["GET"]},"policy_version":3}`
	if string(raw) != want {
		t.Fatalf("JSON = %s, want %s", raw, want)
	}
}

func TestPermissionViewEmptyUser(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithMemoryStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	view, err := e.PermissionView(ctx, "unknown")
	if err != nil {
		t.Fatalf("PermissionView: %v", err)
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"user_id":"unknown","roles":[],"permissions":{},"policy_version":0}`
	if string(raw) != want {
		t.Fatalf("JSON = %s, want %s", raw, want)
	}
}

func TestPermissionViewUsesCache(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithMemoryStore(), WithLRU(NewMemoryLRU(16, 0)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.RegisterRoles(ctx, Role{Name: "viewer", Permissions: []Permission{{Resource: "/a", Action: "GET"}}}); err != nil {
		t.Fatalf("RegisterRoles: %v", err)
	}
	if err := e.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	for i := 0; i < 2; i++ {
		view, err := e.PermissionView(ctx, "u1")
		if err != nil {
			t.Fatalf("PermissionView: %v", err)
		}
		if view.Permissions["/a"][0] != "GET" {
			t.Fatalf("run %d: permissions = %v, want GET", i, view.Permissions)
		}
	}
}

func TestPolicyVersionIncrements(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithMemoryStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	version := func() uint64 {
		v, err := e.PermissionView(ctx, "u")
		if err != nil {
			t.Fatalf("PermissionView: %v", err)
		}
		return v.PolicyVersion
	}
	if got := version(); got != 0 {
		t.Fatalf("initial version = %d, want 0", got)
	}

	// Each successful mutation bumps the version by one.
	if err := e.RegisterRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatalf("RegisterRole: %v", err)
	}
	if err := e.RegisterRoles(ctx, Role{Name: "editor"}, Role{Name: "manager"}); err != nil {
		t.Fatalf("RegisterRoles: %v", err)
	}
	if err := e.AssignRole(ctx, "u", "viewer"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := e.UnassignRole(ctx, "admin-holder", "u", "viewer"); err != ErrPermissionDenied {
		t.Fatalf("UnassignRole = %v, want ErrPermissionDenied (no bump)", err)
	}
	if got := version(); got != 4 {
		t.Fatalf("version after 4 mutations = %d, want 4", got)
	}

	// Failed mutations must not bump the version.
	if err := e.RegisterRole(ctx, Role{Name: "viewer"}); err != ErrRoleExists {
		t.Fatalf("duplicate RegisterRole = %v, want ErrRoleExists", err)
	}
	if err := e.AssignRole(ctx, "u", "missing"); err != ErrRoleNotFound {
		t.Fatalf("AssignRole missing = %v, want ErrRoleNotFound", err)
	}
	if got := version(); got != 4 {
		t.Fatalf("version after failed mutations = %d, want 4", got)
	}

	// Role management mutations bump only on success.
	if err := e.RegisterRole(ctx, Role{Name: "admin", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}); err != nil {
		t.Fatalf("RegisterRole admin: %v", err)
	}
	if err := e.AssignRole(ctx, "admin", "admin"); err != nil {
		t.Fatalf("AssignRole admin: %v", err)
	}
	if err := e.UnassignRole(ctx, "admin", "u", "viewer"); err != nil {
		t.Fatalf("UnassignRole: %v", err)
	}
	if err := e.DeleteRole(ctx, "admin", "viewer"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	if err := e.DeleteRole(ctx, "admin", "viewer"); err != ErrRoleNotFound {
		t.Fatalf("second DeleteRole = %v, want ErrRoleNotFound", err)
	}
	if got := version(); got != 8 {
		t.Fatalf("version after management flow = %d, want 8", got)
	}
}

func TestPolicyVersionConcurrent(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithMemoryStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.RegisterRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatalf("RegisterRole: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			if _, err := e.PermissionView(ctx, "u"); err != nil {
				t.Errorf("PermissionView: %v", err)
				return
			}
		}
	}()
	for i := 0; i < 100; i++ {
		_ = e.AssignRole(ctx, "u", "viewer")
	}
	<-done
}

func TestPermissionViewErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("GetRoles error", func(t *testing.T) {
		e, err := New(WithStore(permissionViewErrStore{rolesErr: true}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := e.PermissionView(ctx, "u"); !errors.Is(err, errTest) {
			t.Fatalf("PermissionView = %v, want GetRoles error", err)
		}
	})

	t.Run("GetRole error", func(t *testing.T) {
		e, err := New(WithStore(permissionViewErrStore{roleErr: true}))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := e.PermissionView(ctx, "u"); !errors.Is(err, errTest) {
			t.Fatalf("PermissionView = %v, want GetRole error", err)
		}
	})
}

// permissionViewErrStore fails on the requested store call.
type permissionViewErrStore struct {
	rolesErr bool
	roleErr  bool
}

func (permissionViewErrStore) AddRole(context.Context, Role) error              { return nil }
func (permissionViewErrStore) AssignRole(context.Context, string, string) error { return nil }
func (s permissionViewErrStore) GetRole(context.Context, string) (Role, bool, error) {
	if s.roleErr {
		return Role{}, false, errTest
	}
	return Role{Name: "r"}, true, nil
}
func (s permissionViewErrStore) GetRoles(context.Context, string) ([]string, error) {
	if s.rolesErr {
		return nil, errTest
	}
	return []string{"r"}, nil
}
