package rbacgo

import (
	"context"
	"testing"
)

// TestTenantIsolation verifies that two enforcers sharing ONE store but with
// different tenants never see each other's roles, users, or decisions.
func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	shared := NewMemoryStore()

	a := mustEnforcer(t, WithTenant("org-a"), WithStore(shared))
	b := mustEnforcer(t, WithTenant("org-b"), WithStore(shared))
	if a.TenantID() != "org-a" || b.TenantID() != "org-b" {
		t.Fatalf("TenantID = %q/%q, want org-a/org-b", a.TenantID(), b.TenantID())
	}

	// Same role name registered independently in both tenants; the role
	// grants the role-management capability so the tenant admin can manage
	// its own assignments.
	admin := Role{Name: "admin", Permissions: []Permission{
		{Resource: "users", Action: "manage"},
		{Resource: "roles", Action: "manage"},
	}}
	if err := a.RegisterRole(ctx, admin); err != nil {
		t.Fatalf("A RegisterRole: %v", err)
	}
	if err := b.RegisterRole(ctx, admin); err != nil {
		t.Fatalf("B RegisterRole same name: %v", err)
	}

	// Same user id in both tenants, same role name — fully independent.
	if err := a.AssignRole(ctx, "alice", "admin"); err != nil {
		t.Fatalf("A AssignRole: %v", err)
	}
	if err := b.AssignRole(ctx, "alice", "admin"); err != nil {
		t.Fatalf("B AssignRole: %v", err)
	}
	if !a.Enforce(ctx, "alice", "users", "manage") {
		t.Fatal("A: alice should be allowed in org-a")
	}
	if !b.Enforce(ctx, "alice", "users", "manage") {
		t.Fatal("B: alice should be allowed in org-b")
	}

	// A role that exists only in org-a must never be visible in org-b.
	owner := Role{Name: "owner", Permissions: []Permission{
		{Resource: "billing", Action: "pay"},
		{Resource: "roles", Action: "manage"},
	}}
	if err := a.RegisterRole(ctx, owner); err != nil {
		t.Fatalf("A RegisterRole owner: %v", err)
	}
	if err := a.AssignRole(ctx, "alice", "owner"); err != nil {
		t.Fatalf("A AssignRole owner: %v", err)
	}
	if b.Enforce(ctx, "alice", "billing", "pay") {
		t.Fatal("B must not inherit org-a's roles")
	}
	if !a.Enforce(ctx, "alice", "billing", "pay") {
		t.Fatal("A: alice must hold org-a owner")
	}

	// Unassigning in org-a must not touch org-b's assignment…
	if err := a.UnassignRole(ctx, "alice", "alice", "admin"); err != nil {
		t.Fatalf("A UnassignRole: %v", err)
	}
	if !b.Enforce(ctx, "alice", "users", "manage") {
		t.Fatal("B: alice must keep org-b admin after org-a unassign")
	}
	if a.Enforce(ctx, "alice", "users", "manage") {
		t.Fatal("A: alice must lose org-a admin")
	}

	// …and deleting the role in org-a must not affect org-b.
	if err := a.DeleteRole(ctx, "alice", "admin"); err != nil {
		t.Fatalf("A DeleteRole: %v", err)
	}
	if !b.Enforce(ctx, "alice", "users", "manage") {
		t.Fatal("B: org-b admin must survive org-a role deletion")
	}
}

// TestTenantPermissionViewIsolation checks that PermissionView only reports
// the calling tenant's roles even when another tenant uses the same names,
// and that roles are returned without any tenant prefix.
func TestTenantPermissionViewIsolation(t *testing.T) {
	ctx := context.Background()
	shared := NewMemoryStore()
	a := mustEnforcer(t, WithTenant("org-a"), WithStore(shared))
	b := mustEnforcer(t, WithTenant("org-b"), WithStore(shared))

	role := Role{Name: "viewer", Permissions: []Permission{{Resource: "/x", Action: "GET"}}}
	if err := a.RegisterRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	if err := b.RegisterRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	if err := a.AssignRole(ctx, "u", "viewer"); err != nil {
		t.Fatal(err)
	}
	va, err := a.PermissionView(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	vb, err := b.PermissionView(ctx, "u")
	if err != nil {
		t.Fatal(err)
	}
	if len(va.Roles) != 1 || va.Roles[0] != "viewer" {
		t.Fatalf("A roles = %v, want [viewer] without tenant prefix", va.Roles)
	}
	if len(vb.Roles) != 0 {
		t.Fatalf("B roles = %v, want none", vb.Roles)
	}
	if va.PolicyVersion == 0 {
		t.Fatal("A policy version must be reported")
	}
}

// TestTenantSQLSharedStore runs the tenant flow over a shared SQL store
// (SQLite file) to prove isolation holds for persisted backends too.
func TestTenantSQLSharedStore(t *testing.T) {
	ctx := context.Background()
	db := sqliteStore(t, ":memory:")
	// Both enforcers share one SQL store instance.
	a := mustEnforcer(t, WithTenant("org-a"), WithStore(db))
	b := mustEnforcer(t, WithTenant("org-b"), WithStore(db))

	role := Role{Name: "admin", Permissions: []Permission{{Resource: "docs", Action: "write"}}}
	if err := a.RegisterRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	if err := b.RegisterRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	if err := a.AssignRole(ctx, "u1", "admin"); err != nil {
		t.Fatal(err)
	}
	if !a.Enforce(ctx, "u1", "docs", "write") {
		t.Fatal("A allow expected")
	}
	if b.Enforce(ctx, "u1", "docs", "write") {
		t.Fatal("B must deny without assignment")
	}
	if err := b.AssignRole(ctx, "u1", "admin"); err != nil {
		t.Fatal(err)
	}
	if !b.Enforce(ctx, "u1", "docs", "write") {
		t.Fatal("B allow expected after own assignment")
	}
}
