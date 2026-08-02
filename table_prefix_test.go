package rbacgo

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestTablePrefixIsolation(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "shared.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	storeA, err := NewSQLStore(db, WithTablePrefix("app1_"))
	if err != nil {
		t.Fatalf("NewSQLStore app1_: %v", err)
	}
	storeB, err := NewSQLStore(db, WithTablePrefix("app2_"))
	if err != nil {
		t.Fatalf("NewSQLStore app2_: %v", err)
	}

	viewer := Role{Name: "viewer", Permissions: []Permission{{Resource: "/a", Action: "GET"}}}
	if err := storeA.AddRole(ctx, viewer); err != nil {
		t.Fatalf("AddRole A: %v", err)
	}
	// Same role name must not collide across prefixes.
	if err := storeB.AddRole(ctx, viewer); err != nil {
		t.Fatalf("AddRole B same name: %v", err)
	}
	if err := storeB.AddRole(ctx, Role{Name: "editor"}); err != nil {
		t.Fatalf("AddRole B editor: %v", err)
	}

	// A must not see B's editor; both must see their own viewer.
	if _, ok, err := storeA.GetRole(ctx, "editor"); err != nil || ok {
		t.Fatalf("GetRole A editor: ok=%v err=%v, want not found", ok, err)
	}
	if _, ok, err := storeB.GetRole(ctx, "editor"); err != nil || !ok {
		t.Fatalf("GetRole B editor: ok=%v err=%v, want found", ok, err)
	}
	if _, ok, err := storeA.GetRole(ctx, "viewer"); err != nil || !ok {
		t.Fatalf("GetRole A viewer: ok=%v err=%v, want found", ok, err)
	}

	// Full enforcement works on prefixed tables.
	if err := storeA.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("AssignRole A: %v", err)
	}
	enforcer, err := New(WithStore(storeA))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !enforcer.Enforce(ctx, "u1", "/a", "GET") {
		t.Fatal("expected allow via prefixed tables")
	}
}

func TestTablePrefixCreatesPrefixedTables(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "pref.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := NewSQLStore(db, WithTablePrefix("myapp_")); err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	rows, err := db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'myapp_%' ORDER BY name`)
	if err != nil {
		t.Fatalf("query sqlite_master: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		names = append(names, n)
	}
	want := []string{"myapp_role_parents", "myapp_role_permissions", "myapp_roles", "myapp_user_roles", "myapp_users"}
	if len(names) != len(want) {
		t.Fatalf("prefixed tables = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("prefixed tables = %v, want %v", names, want)
		}
	}
}

func TestWithTablePrefixInvalid(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	for _, prefix := range []string{"bad prefix!", "1leading-digit", "a/b", "a-b"} {
		if _, err := NewSQLStore(db, WithTablePrefix(prefix)); err == nil {
			t.Errorf("NewSQLStore(prefix %q) = nil error, want error", prefix)
		}
	}

	// Empty prefix keeps the default table names.
	if _, err := NewSQLStore(db, WithTablePrefix("")); err != nil {
		t.Fatalf("NewSQLStore(empty prefix): %v", err)
	}
	// Valid prefixes pass.
	if _, err := NewSQLStore(db, WithTablePrefix("_ok1_")); err != nil {
		t.Fatalf("NewSQLStore(valid prefix): %v", err)
	}
}

func TestEnvSQLTablePrefix(t *testing.T) {
	t.Setenv("RBAC_STORE", "sql")
	t.Setenv("RBAC_DATABASE_URL", filepath.Join(t.TempDir(), "env.db"))
	t.Setenv("RBAC_SQL_TABLE_PREFIX", "env_")
	t.Setenv("RBAC_CACHE", "none")

	ctx := context.Background()
	e, err := New(WithConfigFromEnv())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := e.RegisterRole(ctx, Role{Name: "viewer", Permissions: []Permission{{Resource: "/a", Action: "GET"}}}); err != nil {
		t.Fatalf("RegisterRole: %v", err)
	}
	if err := e.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	if !e.Enforce(ctx, "u1", "/a", "GET") {
		t.Fatal("expected allow via env-prefixed tables")
	}
}

func TestEnvSQLTablePrefixInvalid(t *testing.T) {
	t.Setenv("RBAC_STORE", "sql")
	t.Setenv("RBAC_DATABASE_URL", filepath.Join(t.TempDir(), "env.db"))
	t.Setenv("RBAC_SQL_TABLE_PREFIX", "bad prefix!")

	if _, err := New(WithConfigFromEnv()); err == nil {
		t.Fatal("New with invalid env table prefix = nil error, want error")
	}
}
