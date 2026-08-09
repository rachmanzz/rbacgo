package rbacgo

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// BenchmarkCacheHit measures the hot path cost of an Enforce that hits the
// in-memory LRU cache. Target: under 1 ms per decision.
func BenchmarkCacheHit(b *testing.B) {
	ctx := context.Background()
	e, err := New(WithTenant("bench"), WithMemoryStore(), WithLRU(NewMemoryLRU(1024, time.Hour)))
	if err != nil {
		b.Fatal(err)
	}
	setupEnforceBench(b, ctx, e)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !e.Enforce(ctx, "u1", "articles", "write") {
			b.Fatal("unexpected deny on cache hit")
		}
	}
}

// BenchmarkDefaultCacheHit measures the hot path with the default on-by-default
// LRU cache — the configuration a plain New() produces.
func BenchmarkDefaultCacheHit(b *testing.B) {
	ctx := context.Background()
	e, err := New(WithTenant("bench"), WithMemoryStore())
	if err != nil {
		b.Fatal(err)
	}
	if e.cache == nil {
		b.Fatal("New() must enable the default cache")
	}
	setupEnforceBench(b, ctx, e)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !e.Enforce(ctx, "u1", "articles", "write") {
			b.Fatal("unexpected deny on default cache hit")
		}
	}
}

// BenchmarkNoCacheMiss measures the uncached path (RBAC_CACHE=none): every
// decision rebuilds the effective permission set.
func BenchmarkNoCacheMiss(b *testing.B) {
	ctx := context.Background()
	b.Setenv("RBAC_STORE", "memory")
	b.Setenv("RBAC_CACHE", "none")
	e, err := New(WithTenant("bench"), WithConfigFromEnv())
	if err != nil {
		b.Fatal(err)
	}
	if e.cache != nil {
		b.Fatal("expected no cache with RBAC_CACHE=none")
	}
	setupEnforceBench(b, ctx, e)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !e.Enforce(ctx, "u1", "articles", "write") {
			b.Fatal("unexpected deny on uncached decision")
		}
	}
}

func setupEnforceBench(b *testing.B, ctx context.Context, e *Enforcer) {
	b.Helper()
	if err := e.RegisterRole(ctx, Role{
		Name:        "editor",
		Permissions: []Permission{{Resource: "articles", Action: "write"}},
	}); err != nil {
		b.Fatal(err)
	}
	if err := e.AssignRole(ctx, "u1", "editor"); err != nil {
		b.Fatal(err)
	}
	if !e.Enforce(ctx, "u1", "articles", "write") {
		b.Fatal("warmup enforce failed")
	}
}

// BenchmarkOwnedCacheHit measures an EnforceOwned that hits the cache with a
// :self-scoped permission and a matching owner.
func BenchmarkOwnedCacheHit(b *testing.B) {
	ctx := context.Background()
	e, err := New(WithTenant("bench"), WithMemoryStore(), WithLRU(NewMemoryLRU(1024, time.Hour)))
	if err != nil {
		b.Fatal(err)
	}
	if err := e.RegisterRole(ctx, Role{
		Name:        "editor",
		Permissions: []Permission{{Resource: "articles", Action: "edit:self"}},
	}); err != nil {
		b.Fatal(err)
	}
	if err := e.AssignRole(ctx, "u1", "editor"); err != nil {
		b.Fatal(err)
	}
	if !e.EnforceOwned(ctx, "u1", "u1", "", "articles", "edit") {
		b.Fatal("warmup owned enforce failed")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !e.EnforceOwned(ctx, "u1", "u1", "", "articles", "edit") {
			b.Fatal("unexpected deny on owned cache hit")
		}
	}
}

// BenchmarkListRolesMultiTenant measures ListRoles on a shared memory store
// holding 100 tenants x 20 roles each (the documented shared-store pattern).
// The bulk path copies only the caller's tenant's roles.
func BenchmarkListRolesMultiTenant(b *testing.B) {
	ctx := context.Background()
	store := NewMemoryStore()
	for t := 0; t < 100; t++ {
		e, err := New(WithTenant(fmt.Sprintf("t%03d", t)), WithStore(store), WithLRU(NewMemoryLRU(1, time.Hour)))
		if err != nil {
			b.Fatal(err)
		}
		for r := 0; r < 20; r++ {
			if err := e.RegisterRole(ctx, Role{
				Name:        fmt.Sprintf("role%d", r),
				Permissions: []Permission{{Resource: "doc", Action: "read"}},
			}); err != nil {
				b.Fatal(err)
			}
		}
	}
	target, err := New(WithTenant("t050"), WithStore(store), WithLRU(NewMemoryLRU(1, time.Hour)))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := target.ListRoles(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkUncachedDeepHierarchy measures the uncached decision path on a
// 10-deep role hierarchy: every Enforce rebuilds the effective permission
// set by walking the chain.
func BenchmarkUncachedDeepHierarchy(b *testing.B) {
	ctx := context.Background()
	b.Setenv("RBAC_STORE", "memory")
	b.Setenv("RBAC_CACHE", "none")
	e, err := New(WithTenant("bench"), WithConfigFromEnv())
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		role := Role{Name: fmt.Sprintf("lvl%d", i)}
		if i > 0 {
			role.Parents = []string{fmt.Sprintf("lvl%d", i-1)}
		}
		if err := e.RegisterRole(ctx, role); err != nil {
			b.Fatal(err)
		}
	}
	if err := e.RegisterRole(ctx, Role{Name: "leaf", Parents: []string{"lvl9"}, Permissions: []Permission{{Resource: "articles", Action: "write"}}}); err != nil {
		b.Fatal(err)
	}
	if err := e.AssignRole(ctx, "u1", "leaf"); err != nil {
		b.Fatal(err)
	}
	if !e.Enforce(ctx, "u1", "articles", "write") {
		b.Fatal("warmup enforce failed")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !e.Enforce(ctx, "u1", "articles", "write") {
			b.Fatal("unexpected deny on uncached deep enforce")
		}
	}
}
