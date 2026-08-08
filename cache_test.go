package rbacgo

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemoryLRUBasic(t *testing.T) {
	c := NewMemoryLRU(2, time.Hour)
	c.Set("a", 1)
	if v, ok := c.Get("a"); !ok || v != 1 {
		t.Fatalf("Get(a) = %v, %v; want 1, true", v, ok)
	}
	if _, ok := c.Get("missing"); ok {
		t.Fatal("Get(missing) should miss")
	}
	c.Delete("a")
	if _, ok := c.Get("a"); ok {
		t.Fatal("Get(a) after delete should miss")
	}
}

func TestMemoryLRUEviction(t *testing.T) {
	c := NewMemoryLRU(2, time.Hour)
	c.Set("a", 1)
	c.Set("b", 2)
	c.Get("a") // a is now most-recent
	c.Set("c", 3)
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should have been evicted")
	}
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should still be present")
	}
}

func TestMemoryLRUTTL(t *testing.T) {
	c := NewMemoryLRU(4, 50*time.Millisecond)
	c.Set("a", 1)
	time.Sleep(80 * time.Millisecond)
	if _, ok := c.Get("a"); ok {
		t.Fatal("expired entry should miss")
	}
}

func TestMemoryLRUFlush(t *testing.T) {
	c := NewMemoryLRU(4, time.Hour)
	c.Set("a", 1)
	c.Set("b", 2)
	c.Flush()
	if _, ok := c.Get("a"); ok {
		t.Fatal("a should be gone after flush")
	}
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should be gone after flush")
	}
}

func TestMemoryLRUConcurrent(t *testing.T) {
	c := NewMemoryLRU(16, time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				key := string(rune('a' + n))
				c.Set(key, j)
				c.Get(key)
			}
		}(i)
	}
	wg.Wait()
}

func TestEnforcerCacheIntegration(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryLRU(16, time.Hour)
	e := mustEnforcer(t, WithMemoryStore(), WithLRU(c))
	register(t, e, Role{Name: "r", Permissions: []Permission{{Resource: "x", Action: "read"}}})
	if err := e.AssignRole(ctx, "u1", "r"); err != nil {
		t.Fatal(err)
	}
	if !e.Enforce(ctx, "u1", "x", "read") {
		t.Fatal("expected allow")
	}
	if _, ok := c.Get("t::user:u1"); !ok {
		t.Fatal("expected cached permission set for u1")
	}

	// Registering a new role must flush the cache.
	if err := e.RegisterRole(ctx, Role{Name: "other"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("t::user:u1"); ok {
		t.Fatal("cache should be flushed after role registration")
	}

	// Enforce again then assign another role; that user's entry is dropped.
	if !e.Enforce(ctx, "u1", "x", "read") {
		t.Fatal("expected allow after refill")
	}
	if err := e.AssignRole(ctx, "u1", "other"); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("t::user:u1"); ok {
		t.Fatal("cache entry should be dropped after role assignment")
	}
}

func TestCachePreservesCorrectness(t *testing.T) {
	ctx := context.Background()
	c := NewMemoryLRU(16, time.Hour)
	e := mustEnforcer(t, WithMemoryStore(), WithLRU(c))
	register(t, e,
		Role{Name: "viewer", Permissions: []Permission{{Resource: "a", Action: "read"}}},
		Role{Name: "admin", Parents: []string{"viewer"}},
	)
	if err := e.AssignRole(ctx, "u1", "admin"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if !e.Enforce(ctx, "u1", "a", "read") {
			t.Fatalf("iteration %d: expected inherited allow", i)
		}
		if e.Enforce(ctx, "u1", "a", "write") {
			t.Fatalf("iteration %d: expected deny", i)
		}
	}
}

func TestNewDefaultCache(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t)
	if e.cache == nil {
		t.Fatal("New() must enable the default in-memory LRU cache")
	}
	register(t, e, Role{Name: "r", Permissions: []Permission{{Resource: "x", Action: "read"}}})
	if err := e.AssignRole(ctx, "u1", "r"); err != nil {
		t.Fatal(err)
	}
	if !e.Enforce(ctx, "u1", "x", "read") {
		t.Fatal("expected allow")
	}
	if _, ok := e.cache.Get("t::user:u1"); !ok {
		t.Fatal("expected default cache to hold u1's permission set")
	}
	// Mutations must still invalidate the default cache.
	if err := e.RegisterRole(ctx, Role{Name: "other"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.cache.Get("t::user:u1"); ok {
		t.Fatal("default cache should be flushed after role registration")
	}
}

func TestEnvConfigRedisCacheConstruction(t *testing.T) {
	t.Setenv("RBAC_STORE", "memory")
	t.Setenv("RBAC_CACHE", "redis")
	t.Setenv("RBAC_REDIS_ADDR", "127.0.0.1:1")
	if _, err := New(WithTenant("t"), WithConfigFromEnv()); err != nil {
		// Construction must not fail even if Redis is unreachable; lookups
		// degrade to misses.
		t.Fatalf("New: %v", err)
	}
}
