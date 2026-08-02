package rbacgo

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestSQLStorePolicyVersionDefault(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "pv.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	s, err := NewSQLStore(db)
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	vs := s.(PolicyVersioner)
	if v, err := vs.PolicyVersion(ctx); err != nil || v != 0 {
		t.Fatalf("initial PolicyVersion = %d, %v; want 0", v, err)
	}

	e, err := New(WithStore(s))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.RegisterRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatalf("RegisterRole: %v", err)
	}
	if err := e.RegisterRoles(ctx, Role{Name: "editor"}, Role{Name: "manager"}); err != nil {
		t.Fatalf("RegisterRoles: %v", err)
	}
	if err := e.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if err := e.UnassignRole(ctx, "u1-holder", "x", "viewer"); err != ErrPermissionDenied {
		t.Fatalf("UnassignRole = %v, want ErrPermissionDenied (no bump)", err)
	}

	want := uint64(4)
	got, err := vs.PolicyVersion(ctx)
	if err != nil || got != want {
		t.Fatalf("store PolicyVersion = %d, %v; want %d", got, err, want)
	}
	view, err := e.PermissionView(ctx, "u1")
	if err != nil {
		t.Fatalf("PermissionView: %v", err)
	}
	if view.PolicyVersion != want {
		t.Fatalf("PermissionView policy_version = %d, want %d", view.PolicyVersion, want)
	}
}

func TestPolicyVersionSharedAcrossSQLiteInstances(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "shared.db")

	newStore := func(t *testing.T) (PolicyVersioner, *Enforcer) {
		t.Helper()
		db, err := sql.Open("sqlite3", path)
		if err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { db.Close() })
		s, err := NewSQLStore(db)
		if err != nil {
			t.Fatalf("NewSQLStore: %v", err)
		}
		e, err := New(WithStore(s))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return s.(PolicyVersioner), e
	}

	// Two independent Enforcer instances (separate DB pools) over one file.
	_, e1 := newStore(t)
	vs2, e2 := newStore(t)

	if err := e1.RegisterRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatalf("e1 RegisterRole: %v", err)
	}
	// e2 (a different process/pool) must report the version bumped by e1.
	v, err := vs2.PolicyVersion(ctx)
	if err != nil || v != 1 {
		t.Fatalf("e2 sees PolicyVersion = %d, %v; want 1", v, err)
	}
	view, err := e2.PermissionView(ctx, "u1")
	if err != nil {
		t.Fatalf("e2 PermissionView: %v", err)
	}
	if view.PolicyVersion != 1 {
		t.Fatalf("e2 policy_version = %d, want 1", view.PolicyVersion)
	}

	if err := e2.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("e2 AssignRole: %v", err)
	}
	view, err = e1.PermissionView(ctx, "u1")
	if err != nil {
		t.Fatalf("e1 PermissionView: %v", err)
	}
	if view.PolicyVersion != 2 {
		t.Fatalf("e1 policy_version after e2 mutation = %d, want 2", view.PolicyVersion)
	}
}

func TestPolicyVersionSharedViaRedis(t *testing.T) {
	ctx := context.Background()
	client := newTestRedisClient(t)

	// Two enforcer instances backed by separate memory stores but the SAME
	// Redis version key: they agree on one version.
	e1, err := New(WithMemoryStore(), WithPolicyVersionStore(NewRedisPolicyVersion(client, "rbac:policy_version")))
	if err != nil {
		t.Fatalf("New e1: %v", err)
	}
	e2, err := New(WithMemoryStore(), WithPolicyVersionStore(NewRedisPolicyVersion(client, "rbac:policy_version")))
	if err != nil {
		t.Fatalf("New e2: %v", err)
	}

	if err := e1.RegisterRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatalf("e1 RegisterRole: %v", err)
	}
	for _, e := range []*Enforcer{e1, e2} {
		view, err := e.PermissionView(ctx, "u1")
		if err != nil {
			t.Fatalf("PermissionView: %v", err)
		}
		if view.PolicyVersion != 1 {
			t.Fatalf("policy_version via Redis = %d, want 1", view.PolicyVersion)
		}
	}

	// Each instance owns a separate memory store, so the role must exist in
	// e2 as well; every mutation bumps the SAME shared Redis key.
	if err := e2.RegisterRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatalf("e2 RegisterRole: %v", err)
	}
	if err := e2.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("e2 AssignRole: %v", err)
	}
	for _, e := range []*Enforcer{e1, e2} {
		view, err := e.PermissionView(ctx, "u1")
		if err != nil {
			t.Fatalf("PermissionView: %v", err)
		}
		if view.PolicyVersion != 3 {
			t.Fatalf("policy_version via Redis = %d, want 3", view.PolicyVersion)
		}
	}
}

func TestRedisPolicyVersionDefaultsAndNil(t *testing.T) {
	ctx := context.Background()

	t.Run("nil client panics", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("NewRedisPolicyVersion(nil) did not panic")
			}
		}()
		_ = NewRedisPolicyVersion(nil, "x")
	})

	t.Run("default key and initial zero", func(t *testing.T) {
		client := newTestRedisClient(t)
		vs := NewRedisPolicyVersion(client, "")
		v, err := vs.PolicyVersion(ctx)
		if err != nil || v != 0 {
			t.Fatalf("PolicyVersion = %d, %v; want 0", v, err)
		}
	})
}

func TestWithPolicyVersionStoreNil(t *testing.T) {
	if _, err := New(WithPolicyVersionStore(nil)); err == nil {
		t.Fatal("WithPolicyVersionStore(nil) must error")
	}
}

// errCmdable is a redis.Cmdable whose Get/Incr always fail, forcing the
// RedisPolicyVersion error branches.
type errCmdable struct{ redis.Cmdable }

func (errCmdable) Get(context.Context, string) *redis.StringCmd {
	return redis.NewStringResult("", errors.New("boom"))
}
func (errCmdable) Incr(context.Context, string) *redis.IntCmd {
	return redis.NewIntResult(0, errors.New("boom"))
}

func TestRedisPolicyVersionErrors(t *testing.T) {
	ctx := context.Background()
	vs := NewRedisPolicyVersion(errCmdable{}, "k")
	if _, err := vs.PolicyVersion(ctx); err == nil {
		t.Fatal("PolicyVersion with failing redis must error")
	}
	if _, err := vs.NextPolicyVersion(ctx); err == nil {
		t.Fatal("NextPolicyVersion with failing redis must error")
	}
}

// errPolicyVersion fails every shared version call; the Enforcer must fall
// back to its local counter.
type errPolicyVersion struct{}

func (errPolicyVersion) PolicyVersion(context.Context) (uint64, error)     { return 0, errTest }
func (errPolicyVersion) NextPolicyVersion(context.Context) (uint64, error) { return 0, errTest }

func TestPolicyVersionSourceErrorFallback(t *testing.T) {
	ctx := context.Background()
	e, err := New(WithMemoryStore(), WithPolicyVersionStore(errPolicyVersion{}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.RegisterRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatalf("RegisterRole: %v", err)
	}
	view, err := e.PermissionView(ctx, "u")
	if err != nil {
		t.Fatalf("PermissionView: %v", err)
	}
	if view.PolicyVersion != 1 {
		t.Fatalf("policy_version with failing source = %d, want local fallback 1", view.PolicyVersion)
	}
}

func TestSQLStorePolicyVersionMockErrorPaths(t *testing.T) {
	ctx := context.Background()

	t.Run("PolicyVersion query error", func(t *testing.T) {
		s := newMockSQLStore(mockStep{queryErr: errTest})
		if _, err := s.PolicyVersion(ctx); !errors.Is(err, errTest) {
			t.Fatalf("PolicyVersion = %v, want query error", err)
		}
	})

	t.Run("NextPolicyVersion query error", func(t *testing.T) {
		s := newMockSQLStore(mockStep{queryErr: errTest})
		if _, err := s.NextPolicyVersion(ctx); !errors.Is(err, errTest) {
			t.Fatalf("NextPolicyVersion = %v, want query error", err)
		}
	})
}
