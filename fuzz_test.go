package rbacgo

import (
	"context"
	"errors"
	"hash/fnv"
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Fuzz targets use a deterministic PRNG seeded from the fuzzer's input bytes,
// so every input reproduces exactly the same scenario across runs.

func fuzzRNG(data []byte) *rand.Rand {
	h := fnv.New64a()
	_, _ = h.Write(data)
	return rand.New(rand.NewSource(int64(h.Sum64())))
}

var (
	fuzzNames     = []string{"", " ", "r0", "r1", "R0", "role-1", "role_1", " admin ", "ümlaut", "r0 ", " r0"}
	fuzzResources = []string{"", " ", "/r", "/r/p", "res", "/api/v1/items", "a", " a"}
	fuzzActions   = []string{"", " ", "GET", "POST", "READ", "a", "read"}
	fuzzUsers     = []string{"u0", "u1", "unknown"}
)

func pick(g *rand.Rand, pool []string) string { return pool[g.Intn(len(pool))] }

// oracleState mirrors the enforcer's memory store independently: only
// successful mutations are recorded, exactly as the library sees them.
type oracleState struct {
	roles   map[string]Role
	users   map[string][]string
	version uint64
}

func (st *oracleState) register(ctx context.Context, e *Enforcer, g *rand.Rand) {
	role := Role{
		Name:    pick(g, fuzzNames),
		Parents: make([]string, g.Intn(4)),
	}
	for i := range role.Parents {
		role.Parents[i] = pick(g, fuzzNames)
	}
	for i := g.Intn(3); i > 0; i-- {
		role.Permissions = append(role.Permissions, Permission{Resource: pick(g, fuzzResources), Action: pick(g, fuzzActions)})
	}
	if err := e.RegisterRole(ctx, role); err != nil {
		return
	}
	st.roles[role.Name] = role
	st.version++
}

func (st *oracleState) assign(ctx context.Context, e *Enforcer, g *rand.Rand) {
	user := pick(g, fuzzUsers)
	role := pick(g, fuzzNames)
	if err := e.AssignRole(ctx, user, role); err != nil {
		return
	}
	st.version++
	for _, existing := range st.users[user] {
		if existing == role {
			return
		}
	}
	st.users[user] = append(st.users[user], role)
}

// oracleEffective is an independent iterative traversal (BFS worklist) that
// must agree with the library's recursive collectEffective.
func oracleEffective(roles map[string]Role, assigned []string) map[string]bool {
	out := make(map[string]bool)
	seen := make(map[string]bool)
	stack := append([]string(nil), assigned...)
	for len(stack) > 0 {
		last := len(stack) - 1
		name := stack[last]
		stack = stack[:last]
		if seen[name] {
			continue
		}
		seen[name] = true
		role, ok := roles[name]
		if !ok {
			continue
		}
		for _, p := range role.Permissions {
			out[p.Resource+"\x00"+p.Action] = true
		}
		stack = append(stack, role.Parents...)
	}
	return out
}

func oracleReachable(roles map[string]Role, assigned []string, target string) bool {
	seen := make(map[string]bool)
	stack := append([]string(nil), assigned...)
	for len(stack) > 0 {
		last := len(stack) - 1
		name := stack[last]
		stack = stack[:last]
		if seen[name] {
			continue
		}
		seen[name] = true
		if name == target {
			return true
		}
		stack = append(stack, roles[name].Parents...)
	}
	return false
}

func wantPermissionLists(wantSet map[string]bool) map[string][]string {
	want := make(map[string][]string)
	for k := range wantSet {
		parts := strings.SplitN(k, "\x00", 2)
		want[parts[0]] = append(want[parts[0]], parts[1])
	}
	for _, l := range want {
		sort.Strings(l)
	}
	return want
}

func checkAgainstOracle(t *testing.T, e *Enforcer, st *oracleState, g *rand.Rand) {
	t.Helper()
	ctx := context.Background()
	for range 2 {
		user := pick(g, fuzzUsers)
		want := oracleEffective(st.roles, st.users[user])

		res, act := pick(g, fuzzResources), pick(g, fuzzActions)
		ok, err := e.EnforceCtx(ctx, user, res, act)
		if err != nil {
			t.Fatalf("EnforceCtx(%q): unexpected error: %v", user, err)
		}
		if ok != want[res+"\x00"+act] {
			t.Fatalf("Enforce(%q, %q, %q) = %v, oracle disagrees", user, res, act, ok)
		}

		view, err := e.PermissionView(ctx, user)
		if err != nil {
			t.Fatalf("PermissionView(%q): unexpected error: %v", user, err)
		}
		wantRoles := append([]string(nil), st.users[user]...)
		sort.Strings(wantRoles)
		if wantRoles == nil {
			wantRoles = []string{}
		}
		if !reflect.DeepEqual(view.Roles, wantRoles) {
			t.Fatalf("Roles = %v, want %v", view.Roles, wantRoles)
		}
		if !reflect.DeepEqual(view.Permissions, wantPermissionLists(want)) {
			t.Fatalf("Permissions = %v, want %v", view.Permissions, wantPermissionLists(want))
		}
		if view.PolicyVersion != st.version {
			t.Fatalf("PolicyVersion = %d, want %d", view.PolicyVersion, st.version)
		}

		name := pick(g, fuzzNames)
		gotHas, err := e.HasRole(ctx, user, name)
		if err != nil {
			t.Fatalf("HasRole(%q): unexpected error: %v", name, err)
		}
		if gotHas != oracleReachable(st.roles, st.users[user], name) {
			t.Fatalf("HasRole(%q) = %v, oracle disagrees", name, gotHas)
		}
	}
}

func fuzzScenario(data []byte) (*Enforcer, *oracleState) {
	g := fuzzRNG(data)
	e, err := New(WithMemoryStore())
	if err != nil {
		panic(err)
	}
	st := &oracleState{roles: make(map[string]Role), users: make(map[string][]string)}
	ctx := context.Background()
	for i := g.Intn(12); i > 0; i-- {
		if g.Intn(2) == 0 {
			st.register(ctx, e, g)
		} else {
			st.assign(ctx, e, g)
		}
	}
	return e, st
}

// FuzzHierarchyResolution checks that the library's effective permission
// resolution, role reachability, and permission snapshots always agree with an
// independent oracle, for arbitrary role graphs, names, and permissions.
func FuzzHierarchyResolution(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{0, 1, 2, 3, 4, 5})
	f.Add([]byte("role:admin,parent:viewer,perm:GET"))
	f.Fuzz(func(t *testing.T, data []byte) {
		e, st := fuzzScenario(data)
		checkAgainstOracle(t, e, st, fuzzRNG(data))
	})
}

var errSet = []error{ErrInvalidRole, ErrRoleExists, ErrParentNotFound, ErrCycleDetected, ErrRoleNotFound}

// FuzzGraphSafety checks that no input can panic, that every failure is one of
// the documented sentinel errors, and that any graph that registered
// successfully stays acyclic (PermissionView never reports a cycle).
func FuzzGraphSafety(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1})
	f.Fuzz(func(t *testing.T, data []byte) {
		e, st := fuzzScenario(data)
		ctx := context.Background()
		g := fuzzRNG(data)

		role := Role{Name: pick(g, fuzzNames), Parents: []string{pick(g, fuzzNames), pick(g, fuzzNames)}}
		role.Permissions = append(role.Permissions, Permission{Resource: pick(g, fuzzResources), Action: pick(g, fuzzActions)})
		err := e.RegisterRole(ctx, role)
		if err != nil && !containsErr(errSet, err) {
			t.Fatalf("RegisterRole returned undocumented error %v", err)
		}

		err = e.AssignRole(ctx, pick(g, fuzzUsers), pick(g, fuzzNames))
		if err != nil && !containsErr(errSet, err) {
			t.Fatalf("AssignRole returned undocumented error %v", err)
		}

		for name := range st.roles {
			if err := e.AssignRole(ctx, "cycle-probe", name); err != nil {
				t.Fatalf("assign registered role: %v", err)
			}
			if _, err := e.PermissionView(ctx, "cycle-probe"); err != nil {
				if errors.Is(err, ErrCycleDetected) {
					t.Fatalf("registered graph contains a cycle via %q", name)
				}
				t.Fatalf("PermissionView: %v", err)
			}
		}
	})
}

func containsErr(set []error, err error) bool {
	for _, s := range set {
		if errors.Is(err, s) {
			return true
		}
	}
	return false
}

// FuzzPolicyVersionMonotonic checks that the reported policy version always
// equals the count of successful mutations: every nil-returning mutation bumps
// by exactly one, failed mutations never bump.
func FuzzPolicyVersionMonotonic(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{9})
	f.Fuzz(func(t *testing.T, data []byte) {
		e, st := fuzzScenario(data)
		ctx := context.Background()
		g := fuzzRNG(data)
		for i := g.Intn(20); i > 0; i-- {
			role := Role{Name: pick(g, fuzzNames), Parents: []string{pick(g, fuzzNames)}}
			if err := e.RegisterRole(ctx, role); err == nil {
				st.version++
			}
			if err := e.AssignRole(ctx, pick(g, fuzzUsers), pick(g, fuzzNames)); err == nil {
				st.version++
			}
			view, err := e.PermissionView(ctx, pick(g, fuzzUsers))
			if err != nil {
				t.Fatalf("PermissionView: %v", err)
			}
			if view.PolicyVersion != st.version {
				t.Fatalf("PolicyVersion = %d, want %d", view.PolicyVersion, st.version)
			}
		}
	})
}
