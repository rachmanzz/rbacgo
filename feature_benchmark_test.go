package rbacgo

import (
	"context"
	"path/filepath"
	"testing"
)

func BenchmarkAttributeDecision(b *testing.B) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := store.AddRole(ctx, Role{Name: "bench::reader"}); err != nil {
		b.Fatal(err)
	}
	if err := store.AssignRole(ctx, "bench::alice", "bench::reader"); err != nil {
		b.Fatal(err)
	}
	if err := store.(RoleRuleStore).SetRoleRules(ctx, "bench::reader", []PolicyRule{{Effect: EffectAllow, Resource: "doc", Action: "read", Conditions: []Condition{{Attribute: "amount", Operator: "le", Value: 1000}}}}); err != nil {
		b.Fatal(err)
	}
	e, err := New(WithTenant("bench"), WithStore(store), WithPolicyRules())
	if err != nil {
		b.Fatal(err)
	}
	defer e.Shutdown(ctx)
	attrs := Attributes{"amount": 500}
	b.ResetTimer()
	for range b.N {
		if !e.EnforceAttributes(ctx, "alice", "doc", "read", attrs) {
			b.Fatal("unexpected deny")
		}
	}
}

func BenchmarkDurableAuditDecision(b *testing.B) {
	ctx := context.Background()
	sink, err := NewFileAuditSink(filepath.Join(b.TempDir(), "audit.jsonl"))
	if err != nil {
		b.Fatal(err)
	}
	defer sink.Close()
	e, err := New(WithTenant("bench"), WithMemoryStore(), WithAuditSink(sink))
	if err != nil {
		b.Fatal(err)
	}
	defer e.Shutdown(ctx)
	setupEnforceBench(b, ctx, e)
	b.ResetTimer()
	for range b.N {
		if !e.Enforce(ctx, "u1", "articles", "write") {
			b.Fatal("unexpected deny")
		}
	}
}

func BenchmarkEnforceParallel(b *testing.B) {
	ctx := context.Background()
	e, err := New(WithTenant("bench"), WithMemoryStore())
	if err != nil {
		b.Fatal(err)
	}
	defer e.Shutdown(ctx)
	setupEnforceBench(b, ctx, e)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !e.Enforce(ctx, "u1", "articles", "write") {
				b.Error("unexpected deny")
			}
		}
	})
}
