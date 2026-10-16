package rbacgo

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Pause after reading assignments so revocation can complete before cache fill.
type auditPausedStore struct {
	Store
	pause  atomic.Bool
	read   chan struct{}
	resume chan struct{}
}

func (s *auditPausedStore) GetRoles(ctx context.Context, user string) ([]string, error) {
	roles, err := s.Store.GetRoles(ctx, user)
	if user == "t::u" && s.pause.CompareAndSwap(true, false) {
		close(s.read)
		select {
		case <-s.resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return roles, err
}
func (s *auditPausedStore) UnassignRole(ctx context.Context, user, role string) error {
	return s.Store.(RoleUnassigner).UnassignRole(ctx, user, role)
}

func TestRevocationCannotBeOverwrittenByInFlightLookup(t *testing.T) {
	for _, remote := range []bool{false, true} {
		name := "local"
		if remote {
			name = "remote"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			s := &auditPausedStore{Store: NewMemoryStore(), read: make(chan struct{}), resume: make(chan struct{})}
			e := mustEnforcer(t, WithStore(s))
			register(t, e, Role{Name: "admin", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}, Role{Name: "reader", Permissions: []Permission{{Resource: "doc", Action: "read"}}})
			for user, role := range map[string]string{"root": "admin", "u": "reader"} {
				if err := e.AssignRole(ctx, user, role); err != nil {
					t.Fatal(err)
				}
			}
			s.pause.Store(true)
			done := make(chan struct{})
			go func() { defer close(done); e.Enforce(ctx, "u", "doc", "read") }()
			select {
			case <-s.read:
			case <-ctx.Done():
				t.Fatal("lookup did not reach pause")
			}
			if remote {
				if err := s.UnassignRole(ctx, "t::u", "t::reader"); err != nil {
					t.Fatal(err)
				}
				e.applyInvalidation(InvalidationEvent{Kind: InvalidateDrop, User: e.cacheKey("u")})
			} else if err := e.UnassignRole(ctx, "root", "u", "reader"); err != nil {
				t.Fatal(err)
			}
			close(s.resume)
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("lookup did not finish")
			}
			if e.Enforce(ctx, "u", "doc", "read") {
				t.Fatal("completed revocation was overwritten by stale cache fill")
			}
		})
	}
}

func TestMemoryRegistrationOwnsRoleSlices(t *testing.T) {
	s := NewMemoryStore()
	ctx := context.Background()
	for _, name := range []string{"parent", "other"} {
		if err := s.AddRole(ctx, Role{Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	role := Role{Name: "reader", Parents: []string{"parent"}, Permissions: []Permission{{Resource: "doc", Action: "read"}}}
	if err := s.AddRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	role.Parents[0] = "other"
	role.Permissions[0].Action = "delete"
	got, ok, err := s.GetRole(ctx, "reader")
	if err != nil || !ok {
		t.Fatalf("GetRole: %v, %v", ok, err)
	}
	if got.Parents[0] != "parent" || got.Permissions[0].Action != "read" {
		t.Fatalf("caller mutated stored policy: %+v", got)
	}
}

func TestSQLiteTenantPrefixIsCaseSensitiveAndLiteral(t *testing.T) {
	s := sqliteStore(t, ":memory:")
	t.Cleanup(func() { s.(*sqlStore).db.Close() })
	ctx := context.Background()
	for _, tenant := range []string{"Acme", "acme", "a_%[?]", "aXYZ"} {
		e := mustEnforcer(t, WithTenant(tenant), WithStore(s))
		register(t, e, Role{Name: "parent", Permissions: []Permission{{Resource: tenant, Action: "read"}}}, Role{Name: "child", Parents: []string{"parent"}})
	}
	for _, tenant := range []string{"Acme", "acme", "a_%[?]"} {
		e := mustEnforcer(t, WithTenant(tenant), WithStore(s))
		got, err := e.ListRoles(ctx)
		want := []Role{{Name: "child", Parents: []string{"parent"}}, {Name: "parent", Permissions: []Permission{{Resource: tenant, Action: "read"}}}}
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("tenant %q: got %+v, err %v; want %+v", tenant, got, err, want)
		}
	}
}

func TestRedisInvalidatorFansOutAndReleasesSubscribers(t *testing.T) {
	inv := NewRedisInvalidator(newTestRedisClient(t).(*redis.Client), "audit:fanout").(*redisInvalidator)
	defer inv.Close()
	a, b := inv.Messages(), inv.Messages()
	awaitInitialRedisFlush(t, a)
	awaitInitialRedisFlush(t, b)
	ev := InvalidationEvent{Kind: InvalidateDrop, User: "t::user:u"}
	if err := inv.Publish(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	for _, ch := range []<-chan InvalidationEvent{a, b} {
		select {
		case got := <-ch:
			if got != ev {
				t.Fatalf("event = %+v", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("event did not reach every subscriber")
		}
	}
	e := mustEnforcer(t, WithMemoryStore(), WithCacheInvalidator(inv))
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	inv.mu.Lock()
	count := len(inv.subs)
	inv.mu.Unlock()
	if count != 2 {
		t.Fatalf("closed enforcer retained subscription: %d", count)
	}
	inv.Close()
	for _, ch := range []<-chan InvalidationEvent{a, b, inv.Messages()} {
		select {
		case _, ok := <-ch:
			if ok {
				t.Fatal("subscriber not closed")
			}
		case <-time.After(time.Second):
			t.Fatal("Close did not close subscriber")
		}
	}
}

func TestSharedCacheCannotRestoreRevokedPermission(t *testing.T) {
	for _, backend := range []string{"memory", "redis"} {
		t.Run(backend, func(t *testing.T) {
			cacheA := NewMemoryLRU(100, time.Hour)
			cacheB := cacheA
			if backend == "redis" {
				client := newTestRedisClient(t)
				cacheA = NewRedisLRU(client, "audit:shared:", time.Hour)
				// Separate backend objects, as in different processes sharing Redis.
				cacheB = NewRedisLRU(client, "audit:shared:", time.Hour)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			store := NewMemoryStore()
			a := mustEnforcer(t, WithStore(store), WithLRU(cacheA))
			paused := &auditPausedStore{Store: store, read: make(chan struct{}), resume: make(chan struct{})}
			b := mustEnforcer(t, WithStore(paused), WithLRU(cacheB))
			register(t, a, Role{Name: "admin", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}, Role{Name: "reader", Permissions: []Permission{{Resource: "doc", Action: "read"}}})
			for user, role := range map[string]string{"root": "admin", "u": "reader"} {
				if err := a.AssignRole(ctx, user, role); err != nil {
					t.Fatal(err)
				}
			}
			paused.pause.Store(true)
			done := make(chan struct{})
			go func() { defer close(done); b.Enforce(ctx, "u", "doc", "read") }()
			select {
			case <-paused.read:
			case <-ctx.Done():
				t.Fatal("lookup did not pause")
			}
			if err := a.UnassignRole(ctx, "root", "u", "reader"); err != nil {
				t.Fatal(err)
			}
			close(paused.resume)
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("lookup did not finish")
			}
			for _, e := range []*Enforcer{a, b} {
				if e.Enforce(ctx, "u", "doc", "read") {
					t.Fatal("shared cache restored revoked permission")
				}
			}
		})
	}
}

func TestCacheGenerationRejectsInvalidatedFill(t *testing.T) {
	for _, backend := range []string{"memory", "redis"} {
		t.Run(backend, func(t *testing.T) {
			var cache CacheBackend = NewMemoryLRU(100, time.Hour)
			if backend == "redis" {
				cache = NewRedisLRU(newTestRedisClient(t), "audit:tokens:", time.Hour)
			}
			versioned := cache.(GenerationCacheBackend)
			for _, flush := range []bool{false, true} {
				old, ok := versioned.Generation("u")
				if !ok {
					t.Fatal("generation unavailable")
				}
				if flush {
					cache.Flush()
				} else {
					cache.Delete("u")
				}
				next, ok := versioned.Generation("u")
				if !ok || next == old {
					t.Fatal("generation reused after invalidation")
				}
				versioned.SetIfGeneration("u", permissionSet{"doc": {"read": true}}, old)
				if _, ok := cache.Get("u"); ok {
					t.Fatal("stale fill accepted")
				}
				versioned.SetIfGeneration("u", permissionSet{"doc": {"write": true}}, next)
				if _, ok := cache.Get("u"); !ok {
					t.Fatal("current fill rejected")
				}
			}
		})
	}
}
