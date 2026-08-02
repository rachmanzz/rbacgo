package rbacgo

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedisClient(t *testing.T) redis.Cmdable {
	t.Helper()
	mr := miniredis.RunT(t)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

func TestRedisLRUBasic(t *testing.T) {
	client := newTestRedisClient(t)
	c := NewRedisLRU(client, "test:", time.Minute)

	ps := permissionSet{"articles": {"read": true, "write": true}}
	c.Set("u1", ps)

	got, ok := c.Get("u1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	g, isPS := got.(permissionSet)
	if !isPS || !g["articles"]["write"] {
		t.Fatalf("unexpected cached value: %#v", got)
	}

	if _, ok := c.Get("missing"); ok {
		t.Fatal("expected miss for unknown key")
	}

	c.Delete("u1")
	if _, ok := c.Get("u1"); ok {
		t.Fatal("expected miss after delete")
	}
}

func TestRedisLRUFlush(t *testing.T) {
	client := newTestRedisClient(t)
	c := NewRedisLRU(client, "test:", time.Minute)
	c.Set("u1", permissionSet{"a": {"b": true}})
	c.Set("u2", permissionSet{"c": {"d": true}})
	c.Flush()
	if _, ok := c.Get("u1"); ok {
		t.Fatal("u1 should be gone after flush")
	}
	if _, ok := c.Get("u2"); ok {
		t.Fatal("u2 should be gone after flush")
	}
}

func TestRedisLRUDefaultPrefix(t *testing.T) {
	client := newTestRedisClient(t)
	c := NewRedisLRU(client, "", time.Minute)
	c.Set("k", permissionSet{"a": {"b": true}})
	if _, ok := c.Get("k"); !ok {
		t.Fatal("expected hit with default prefix")
	}
}

func TestEnvCacheRedisEndToEnd(t *testing.T) {
	mr := miniredis.RunT(t)
	t.Setenv("RBAC_STORE", "memory")
	t.Setenv("RBAC_CACHE", "redis")
	t.Setenv("RBAC_REDIS_ADDR", mr.Addr())
	t.Setenv("RBAC_CACHE_TTL", "1m")

	ctx := context.Background()
	e := mustEnforcer(t, WithConfigFromEnv())
	register(t, e, Role{Name: "r", Permissions: []Permission{{Resource: "x", Action: "read"}}})
	if err := e.AssignRole(ctx, "u1", "r"); err != nil {
		t.Fatal(err)
	}
	if !e.Enforce(ctx, "u1", "x", "read") {
		t.Fatal("expected allow")
	}
	// The cached key must exist in Redis.
	if _, ok := e.cache.Get("user:u1"); !ok {
		t.Fatal("expected cached user key in redis")
	}
}

func TestWithLRUNil(t *testing.T) {
	if _, err := New(WithLRU(nil)); err == nil {
		t.Fatal("expected error for nil cache backend")
	}
}

func TestEnvCacheNone(t *testing.T) {
	t.Setenv("RBAC_STORE", "memory")
	t.Setenv("RBAC_CACHE", "none")
	e := mustEnforcer(t, WithConfigFromEnv())
	if e.cache != nil {
		t.Fatal("cache should be disabled with RBAC_CACHE=none")
	}
}

func TestEnvCacheInvalid(t *testing.T) {
	t.Setenv("RBAC_STORE", "memory")
	t.Setenv("RBAC_CACHE", "bogus")
	if _, err := New(WithConfigFromEnv()); err == nil {
		t.Fatal("expected error for unknown cache type")
	}
}

func TestEnvHelpers(t *testing.T) {
	if got := envInt("RBAC_UNSET_INT", 7); got != 7 {
		t.Errorf("envInt fallback = %d, want 7", got)
	}
	t.Setenv("RBAC_TEST_INT", "42")
	if got := envInt("RBAC_TEST_INT", 7); got != 42 {
		t.Errorf("envInt = %d, want 42", got)
	}
	t.Setenv("RBAC_TEST_BAD_INT", "abc")
	if got := envInt("RBAC_TEST_BAD_INT", 7); got != 7 {
		t.Errorf("envInt bad value fallback = %d, want 7", got)
	}
	if got := envDuration("RBAC_UNSET_DUR", time.Minute); got != time.Minute {
		t.Errorf("envDuration fallback = %v, want 1m", got)
	}
	t.Setenv("RBAC_TEST_DUR", "30s")
	if got := envDuration("RBAC_TEST_DUR", time.Minute); got != 30*time.Second {
		t.Errorf("envDuration = %v, want 30s", got)
	}
}

func TestMemoryLRUDefaults(t *testing.T) {
	c := NewMemoryLRU(0, 0)
	c.Set("a", 1)
	if _, ok := c.Get("a"); !ok {
		t.Fatal("expected hit with defaulted cache")
	}
}

func TestRedisLRUEnvDefaultTTL(t *testing.T) {
	client := newTestRedisClient(t)
	c := NewRedisLRU(client, "x:", 0)
	c.Set("a", permissionSet{"r": {"a": true}})
	if _, ok := c.Get("a"); !ok {
		t.Fatal("expected hit")
	}
}
