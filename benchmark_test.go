package rbacgo

import (
	"context"
	"testing"
	"time"
)

// BenchmarkCacheHit measures the hot path cost of an Enforce that hits the
// in-memory LRU cache. Target: under 1 ms per decision.
func BenchmarkCacheHit(b *testing.B) {
	ctx := context.Background()
	e, err := New(WithMemoryStore(), WithLRU(NewMemoryLRU(1024, time.Hour)))
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
