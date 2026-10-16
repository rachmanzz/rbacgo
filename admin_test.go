package rbacgo

import (
	"context"
	"errors"
	"testing"
)

func TestManagementAsAuthorization(t *testing.T) {
	for _, capability := range []Permission{{Resource: "roles", Action: "manage"}, {Resource: "acl", Action: "admin"}} {
		t.Run(capability.Resource, func(t *testing.T) {
			ctx := context.Background()
			store := NewMemoryStore()
			e := mustEnforcer(t, WithStore(store), WithRoleManagementPermission(capability.Resource, capability.Action))
			if err := e.RegisterRole(ctx, Role{Name: "manager", Permissions: []Permission{capability}}); err != nil {
				t.Fatal(err)
			}
			if err := e.AssignRole(ctx, "admin", "manager"); err != nil {
				t.Fatal(err)
			}
			before, err := e.PermissionView(ctx, "user")
			if err != nil {
				t.Fatal(err)
			}
			for name, call := range map[string]func() error{
				"register": func() error { return e.RegisterRoleAs(ctx, "user", Role{Name: "blocked"}) },
				"batch":    func() error { return e.RegisterRolesAs(ctx, "user", Role{Name: "blocked-batch"}) },
				"assign":   func() error { return e.AssignRoleAs(ctx, "user", "user", "manager") },
				"list":     func() error { _, err := e.ListRolesAs(ctx, "user"); return err },
			} {
				if err := call(); !errors.Is(err, ErrPermissionDenied) {
					t.Fatalf("%s = %v, want denied", name, err)
				}
			}
			roles, err := e.ListRoles(ctx)
			if err != nil || len(roles) != 1 {
				t.Fatalf("denied operations changed roles: %v, %v", roles, err)
			}
			after, err := e.PermissionView(ctx, "user")
			if err != nil || after.PolicyVersion != before.PolicyVersion || len(after.Roles) != 0 {
				t.Fatalf("denied operations changed user/version: %+v, %v", after, err)
			}
			viewer := Role{Name: "viewer", Permissions: []Permission{{Resource: "articles", Action: "read"}}}
			if err := e.RegisterRoleAs(ctx, "admin", viewer); err != nil {
				t.Fatal(err)
			}
			if err := e.AssignRoleAs(ctx, "admin", "user", "viewer"); err != nil {
				t.Fatal(err)
			}
			if !e.Enforce(ctx, "user", "articles", "read") {
				t.Fatal("checked assignment did not invalidate warmed deny cache")
			}
			if err := e.RegisterRolesAs(ctx, "admin", Role{Name: "first"}, viewer, Role{Name: "never"}); !errors.Is(err, ErrRoleExists) {
				t.Fatalf("batch error = %v", err)
			}
			roles, err = e.ListRolesAs(ctx, "admin")
			if err != nil || len(roles) != 3 {
				t.Fatalf("batch must retain earlier success only: %v, %v", roles, err)
			}
			// Same actor ID in another tenant does not inherit admin authority.
			other, err := New(WithTenant("other"), WithStore(store), WithRoleManagementPermission(capability.Resource, capability.Action))
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if err := other.RegisterRoleAs(ctx, "admin", Role{Name: "cross-tenant"}); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("cross-tenant register = %v", err)
			}
			if _, err := other.ListRolesAs(ctx, "admin"); !errors.Is(err, ErrPermissionDenied) {
				t.Fatalf("cross-tenant list = %v", err)
			}
		})
	}
}
