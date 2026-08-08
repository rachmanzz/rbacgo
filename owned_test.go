package rbacgo

import (
	"context"
	"errors"
	"testing"
)

// TestEnforceOwnedSelfOnly: ":self" grants the action on own resources only.
func TestEnforceOwnedSelfOnly(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	// "self" permission lives on an ancestor: it must be inherited.
	register(t, e, Role{
		Name: "base",
		Permissions: []Permission{
			{Resource: "article", Action: "delete:self"},
			{Resource: "article", Action: "read"},
		},
	})
	register(t, e, Role{
		Name:    "author",
		Parents: []string{"base"},
	})
	if err := e.AssignRole(ctx, "u0", "author"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		user, owner string
		act         string
		want        bool
	}{
		{"u0", "u0", "delete", true},  // own article
		{"u0", "u1", "delete", false}, // someone else's article
		{"u0", "", "delete", false},   // unknown owner
		{"u0", "u0", "read", true},    // plain permission ignores owner
		{"u0", "u1", "read", true},    // plain permission is "any"
		{"u0", "u0", "update", false}, // no matching permission at all
		{"u0", "u0", "DELETE", false}, // case-sensitive action match
		{"u0", "U0", "delete", false}, // case-sensitive owner compare
	} {
		got, err := e.EnforceOwnedCtx(ctx, tc.user, tc.owner, "", "article", tc.act)
		if err != nil || got != tc.want {
			t.Fatalf("EnforceOwned(%q,%q,article,%q) = %v, %v; want %v", tc.user, tc.owner, tc.act, got, err, tc.want)
		}
	}
}

// TestEnforceOwnedAnyWins: holding the plain (or ":any") action allows the
// operation on any resource, even when a ":self" permission is also held.
func TestEnforceOwnedAnyWins(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{
		Name: "moderator",
		Permissions: []Permission{
			{Resource: "article", Action: "delete"},
			{Resource: "article", Action: "delete:self"},
		},
	})
	if err := e.AssignRole(ctx, "u0", "moderator"); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"u0", "u1", ""} {
		got, err := e.EnforceOwnedCtx(ctx, "u0", owner, "", "article", "delete")
		if err != nil || !got {
			t.Fatalf("EnforceOwned(u0,%q,article,delete) = %v, %v; want true (any wins)", owner, got, err)
		}
	}
}

// TestEnforceOwnedAnyAlias: "update:any" behaves exactly like "update".
func TestEnforceOwnedAnyAlias(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{
		Name: "editor",
		Permissions: []Permission{
			{Resource: "article", Action: "update:any"},
		},
	})
	if err := e.AssignRole(ctx, "u0", "editor"); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"u0", "u1", ""} {
		got, err := e.EnforceOwnedCtx(ctx, "u0", owner, "", "article", "update")
		if err != nil || !got {
			t.Fatalf("EnforceOwned(u0,%q,article,update) = %v, %v; want true", owner, got, err)
		}
	}
	// The alias is also accepted when queried literally.
	if ok, _ := e.EnforceCtx(ctx, "u0", "article", "update:any"); !ok {
		t.Fatal("literal 'update:any' query must match")
	}
}

// TestEnforceOwnedCreateSelf: "create:self" behaves like plain "create" —
// creation has no owner yet.
func TestEnforceOwnedCreateSelf(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{
		Name: "writer",
		Permissions: []Permission{
			{Resource: "article", Action: "create:self"},
		},
	})
	if err := e.AssignRole(ctx, "u0", "writer"); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"", "u0", "u1"} {
		got, err := e.EnforceOwnedCtx(ctx, "u0", owner, "", "article", "create")
		if err != nil || !got {
			t.Fatalf("EnforceOwned(u0,%q,article,create) = %v, %v; want true", owner, got, err)
		}
	}
	// "create" must not be granted by an unrelated ":self" action.
	if got, _ := e.EnforceOwnedCtx(ctx, "u0", "u0", "", "article", "delete"); got {
		t.Fatal("'create:self' must not grant delete")
	}
}

// TestEnforceOwnedCachedFlips: the effective set is cached per user, but the
// owner comparison happens per call, so results flip correctly across calls.
func TestEnforceOwnedCachedFlips(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{
		Name: "owner",
		Permissions: []Permission{
			{Resource: "doc", Action: "update:self"},
		},
	})
	if err := e.AssignRole(ctx, "u0", "owner"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.EnforceOwnedCtx(ctx, "u0", "u0", "", "doc", "update"); !ok {
		t.Fatal("own doc must be updatable")
	}
	if ok, _ := e.EnforceOwnedCtx(ctx, "u0", "u1", "", "doc", "update"); ok {
		t.Fatal("someone else's doc must not be updatable via ':self'")
	}
}

// TestEnforceOwnedErrors: store failures propagate through the Ctx variant
// and are treated as deny by the bool variant.
func TestEnforceOwnedErrors(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithStore(failGetRolesStore{}))
	if ok, err := e.EnforceOwnedCtx(ctx, "u0", "u0", "", "a", "b"); !errors.Is(err, errTest) {
		t.Fatalf("EnforceOwnedCtx = %v, %v; want errTest", ok, err)
	}
	if ok := e.EnforceOwned(ctx, "u0", "u0", "", "a", "b"); ok {
		t.Fatal("bool variant must treat errors as deny")
	}
}

// TestEnforceOwnedGroup: ":grp:<id>" grants the action on resources of that
// group only (e.g. one department), regardless of the owner.
func TestEnforceOwnedGroup(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{
		Name: "hr-manager",
		Permissions: []Permission{
			{Resource: "article", Action: "update:grp:hr"},
		},
	})
	if err := e.AssignRole(ctx, "u0", "hr-manager"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		owner, group string
		want         bool
	}{
		{"u1", "hr", true},       // someone else's article, but in group hr
		{"u0", "hr", true},       // own article in group hr
		{"u0", "finance", false}, // article of another group
		{"u0", "", false},        // unknown group never satisfies ":grp:"
	} {
		got, err := e.EnforceOwnedCtx(ctx, "u0", tc.owner, tc.group, "article", "update")
		if err != nil || got != tc.want {
			t.Fatalf("EnforceOwned(u0,%q,%q,article,update) = %v, %v; want %v", tc.owner, tc.group, got, err, tc.want)
		}
	}
}

// TestEnforceOwnedGroupAndSelf: holding ":self" and ":grp:hr" together grants
// own resources anywhere and group-hr resources from anyone.
func TestEnforceOwnedGroupAndSelf(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{
		Name: "manager",
		Permissions: []Permission{
			{Resource: "article", Action: "update:self"},
			{Resource: "article", Action: "update:grp:hr"},
		},
	})
	if err := e.AssignRole(ctx, "u0", "manager"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		owner, group string
		want         bool
	}{
		{"u0", "finance", true},  // own article, any group
		{"u1", "hr", true},       // group-hr article from someone else
		{"u1", "finance", false}, // neither own nor group hr
	} {
		got, err := e.EnforceOwnedCtx(ctx, "u0", tc.owner, tc.group, "article", "update")
		if err != nil || got != tc.want {
			t.Fatalf("EnforceOwned(u0,%q,%q,article,update) = %v, %v; want %v", tc.owner, tc.group, got, err, tc.want)
		}
	}
}

// TestEnforceOwnedCreateGroup: ":create:grp:hr" scopes creation to the target
// group; unlike ":self" it is NOT treated as plain create.
func TestEnforceOwnedCreateGroup(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{
		Name: "hr-writer",
		Permissions: []Permission{
			{Resource: "article", Action: "create:grp:hr"},
		},
	})
	if err := e.AssignRole(ctx, "u0", "hr-writer"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.EnforceOwnedCtx(ctx, "u0", "", "hr", "article", "create"); !ok {
		t.Fatal("create into group hr must be allowed")
	}
	if ok, _ := e.EnforceOwnedCtx(ctx, "u0", "", "finance", "article", "create"); ok {
		t.Fatal("create into another group must be denied")
	}
	if ok, _ := e.EnforceOwnedCtx(ctx, "u0", "", "", "article", "create"); ok {
		t.Fatal("create without a group must be denied")
	}
}
