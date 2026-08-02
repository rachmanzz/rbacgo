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

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !e.Enforce(ctx, "u1", "articles", "write") {
			b.Fatal("unexpected deny on cache hit")
		}
	}
}
