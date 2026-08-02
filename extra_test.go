package rbacgo

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestWithStoreAndGetter(t *testing.T) {
	ms := NewMemoryStore()
	e := mustEnforcer(t, WithStore(ms))
	if e.Store() != ms {
		t.Fatal("Store() did not return the configured store")
	}
}

func TestWithStoreNil(t *testing.T) {
	if _, err := New(WithStore(nil)); err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestWithMemoryStoreOption(t *testing.T) {
	e := mustEnforcer(t, WithMemoryStore())
	if _, ok := e.store.(*memoryStore); !ok {
		t.Fatalf("store is %T, want *memoryStore", e.store)
	}
}

func TestHasRoleFalseAndEmpty(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e, Role{Name: "a"})
	has, err := e.HasRole(ctx, "u1", "a")
	if err != nil || has {
		t.Errorf("HasRole(unknown user) = %v, %v; want false, nil", has, err)
	}
	if err := e.AssignRole(ctx, "u1", "a"); err != nil {
		t.Fatal(err)
	}
	has, err = e.HasRole(ctx, "u1", "b")
	if err != nil || has {
		t.Errorf("HasRole(unassigned) = %v, %v; want false, nil", has, err)
	}
}

func TestWithSQLStoreOption(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	e := mustEnforcer(t, WithSQLStore(db))
	if _, ok := e.store.(*sqlStore); !ok {
		t.Fatalf("store is %T, want *sqlStore", e.store)
	}
}

func TestEnforceCtxReportsErrors(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	ok, err := e.EnforceCtx(ctx, "u1", "r", "a")
	if err != nil {
		t.Fatalf("EnforceCtx error: %v", err)
	}
	if ok {
		t.Fatal("expected deny")
	}
	// Enforce must swallow errors into deny.
	if e.Enforce(ctx, "u1", "r", "a") {
		t.Fatal("Enforce should deny on error")
	}
}

func TestConfigFromEnvSQLWithURL(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/env.db"
	t.Setenv("RBAC_STORE", "sql")
	t.Setenv("RBAC_DATABASE_URL", path)
	e := mustEnforcer(t, WithConfigFromEnv())
	if _, ok := e.store.(*sqlStore); !ok {
		t.Fatalf("store is %T, want *sqlStore", e.store)
	}
}

func TestConfigFromEnvSQLMissingURL(t *testing.T) {
	t.Setenv("RBAC_STORE", "sql")
	if _, err := New(WithConfigFromEnv()); err == nil {
		t.Fatal("expected error when DATABASE_URL is missing")
	}
}

func TestStoreInterface(t *testing.T) {
	// Compile-time check that both stores satisfy Store.
	var _ Store = NewMemoryStore()
	s := sqliteStore(t, ":memory:")
	var _ Store = s
}

func TestSQLStoreAssignUnknownRole(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t, ":memory:")
	if err := s.AssignRole(ctx, "u1", "ghost"); err != ErrRoleNotFound {
		t.Fatalf("got %v, want ErrRoleNotFound", err)
	}
}

func TestWithSQLiteBadPath(t *testing.T) {
	if _, err := New(WithSQLite("/nonexistent/dir/that/does/not/exist/rbac.db")); err == nil {
		t.Fatal("expected error for invalid sqlite path")
	}
}

func TestRegisterRolesStopsOnError(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	roles := []Role{
		{Name: "ok"},
		{Name: "bad", Parents: []string{"ghost"}},
	}
	err := e.RegisterRoles(ctx, roles...)
	if err != ErrParentNotFound {
		t.Fatalf("got %v, want ErrParentNotFound", err)
	}
	// First role must have been registered before the failure.
	if _, ok, _ := e.store.GetRole(ctx, "ok"); !ok {
		t.Fatal("first role should be registered")
	}
}

func TestPostgresDialectQueries(t *testing.T) {
	q := buildQueries(dialectPostgres)
	if q.insertRole != "INSERT INTO roles (name) VALUES ($1)" {
		t.Errorf("unexpected insertRole: %q", q.insertRole)
	}
	if q.assignRole != "INSERT INTO user_roles (user_id, role_name) VALUES ($1, $2) ON CONFLICT DO NOTHING" {
		t.Errorf("unexpected assignRole: %q", q.assignRole)
	}
	if got := dialectPostgres.param(3); got != "$3" {
		t.Errorf("param(3) = %q, want $3", got)
	}
	if got := dialectSQLite.param(3); got != "?" {
		t.Errorf("param(3) = %q, want ?", got)
	}
}

func TestDialectDetection(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if d := detectDialect(db); d != dialectSQLite {
		t.Errorf("detectDialect(sqlite) = %v, want dialectSQLite", d)
	}
}
