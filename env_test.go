package rbacgo

import (
	"context"
	"testing"
)

func TestConfigFromEnvSQLite(t *testing.T) {
	t.Setenv("RBAC_STORE", "sqlite")
	t.Setenv("RBAC_SQLITE_PATH", ":memory:")
	e := mustEnforcer(t, WithConfigFromEnv())
	if _, ok := e.store.(*sqlStore); !ok {
		t.Fatalf("store is %T, want *sqlStore", e.store)
	}
}

func TestConfigFromEnvMemory(t *testing.T) {
	t.Setenv("RBAC_STORE", "memory")
	e := mustEnforcer(t, WithConfigFromEnv())
	if _, ok := e.store.(*memoryStore); !ok {
		t.Fatalf("store is %T, want *memoryStore", e.store)
	}
}

func TestConfigFromEnvCustomPrefix(t *testing.T) {
	t.Setenv("APP_STORE", "memory")
	e := mustEnforcer(t, WithEnvPrefix("APP_"), WithConfigFromEnv())
	if _, ok := e.store.(*memoryStore); !ok {
		t.Fatalf("store is %T, want *memoryStore", e.store)
	}
}

func TestConfigFromEnvUnknownStore(t *testing.T) {
	t.Setenv("RBAC_STORE", "bogus")
	if _, err := New(WithTenant("t"), WithConfigFromEnv()); err == nil {
		t.Fatal("expected error for unknown store type")
	}
}

func TestExplicitOptionOverridesEnv(t *testing.T) {
	t.Setenv("RBAC_STORE", "memory")
	e := mustEnforcer(t, WithConfigFromEnv(), WithMemoryStore())
	if _, ok := e.store.(*memoryStore); !ok {
		t.Fatalf("store is %T, want *memoryStore", e.store)
	}
	// Env applied last must not clobber an explicit store.
	e2 := mustEnforcer(t, WithMemoryStore(), WithConfigFromEnv())
	if _, ok := e2.store.(*memoryStore); !ok {
		t.Fatalf("store is %T, want *memoryStore", e2.store)
	}
}

func TestEnvConfigStoreCRUD(t *testing.T) {
	ctx := context.Background()
	t.Setenv("RBAC_STORE", "sqlite")
	e := mustEnforcer(t, WithConfigFromEnv())
	if err := e.RegisterRole(ctx, Role{Name: "r", Permissions: []Permission{{Resource: "x", Action: "read"}}}); err != nil {
		t.Fatal(err)
	}
	if err := e.AssignRole(ctx, "u", "r"); err != nil {
		t.Fatal(err)
	}
	if !e.Enforce(ctx, "u", "x", "read") {
		t.Error("expected allow")
	}
}
