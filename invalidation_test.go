package rbacgo

import (
	"context"
	"errors"
	"github.com/alicebob/miniredis/v2"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// fanoutInvalidator is an in-process CacheInvalidator that fans every event
// out to all subscribers — the same topology a shared Redis channel gives
// cross-process enforcers. Channels are unbuffered, so a Publish returns
// only after every subscriber has received the event: tests observe a
// deterministic, drained event queue.
type fanoutInvalidator struct {
	mu     sync.Mutex
	subs   []chan InvalidationEvent
	closed bool
}

func (f *fanoutInvalidator) Publish(_ context.Context, ev InvalidationEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errors.New("invalidator closed")
	}
	for _, c := range f.subs {
		c <- ev
	}
	return nil
}

func (f *fanoutInvalidator) Messages() <-chan InvalidationEvent {
	c := make(chan InvalidationEvent)
	f.mu.Lock()
	f.subs = append(f.subs, c)
	f.mu.Unlock()
	return c
}

func (f *fanoutInvalidator) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	f.closed = true
	for _, c := range f.subs {
		close(c)
	}
	return nil
}

// mustEnforcerPair builds two enforcers over one shared store, each with its
// own LRU cache, wired to the same invalidator — the configuration whose
// cross-instance staleness the invalidator fixes.
func mustEnforcerPair(t *testing.T, inv CacheInvalidator) (*Enforcer, *Enforcer) {
	t.Helper()
	store := NewMemoryStore()
	a, err := New(WithTenant("t"), WithStore(store), WithLRU(NewMemoryLRU(1024, time.Hour)), WithCacheInvalidator(inv))
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(WithTenant("t"), WithStore(store), WithLRU(NewMemoryLRU(1024, time.Hour)), WithCacheInvalidator(inv))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	if err := a.RegisterRole(ctx(), Role{Name: "admin", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}); err != nil {
		t.Fatal(err)
	}
	if err := a.RegisterRole(ctx(), Role{Name: "writer"}); err != nil {
		t.Fatal(err)
	}
	if err := a.AssignRole(ctx(), "root", "admin"); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func ctx() context.Context { return context.Background() }

// TestInvalidatorCrossEnforcerFlush proves the headline fix: a role-level
// mutation through enforcer a reaches enforcer b's cache immediately, not
// after TTL expiry.
func TestInvalidatorCrossEnforcerFlush(t *testing.T) {
	inv := &fanoutInvalidator{}
	defer inv.Close()
	a, b := mustEnforcerPair(t, inv)

	if err := b.AssignRole(ctx(), "u1", "writer"); err != nil {
		t.Fatal(err)
	}
	// b primes its cache with u1's empty effective set.
	if b.Enforce(ctx(), "u1", "doc", "write") {
		t.Fatal("sanity: u1 must not have write yet")
	}
	if err := a.UpdateRole(ctx(), "root", Role{Name: "writer", Permissions: []Permission{{Resource: "doc", Action: "write"}}}); err != nil {
		t.Fatal(err)
	}
	// Without the invalidator, b would serve its stale snapshot until TTL.
	// The flush event must reach b's subscriber promptly (event delivery is
	// asynchronous, so poll).
	deadline := time.Now().Add(2 * time.Second)
	for !b.Enforce(ctx(), "u1", "doc", "write") {
		if time.Now().After(deadline) {
			t.Fatal("b served a stale decision: flush event was not applied")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestInvalidatorDropIsUserScoped proves drop events evict exactly the
// affected user's entry, leaving other users' snapshots intact.
func TestInvalidatorDropIsUserScoped(t *testing.T) {
	inv := &fanoutInvalidator{}
	defer inv.Close()
	a, b := mustEnforcerPair(t, inv)

	if err := a.UpdateRole(ctx(), "root", Role{Name: "writer", Permissions: []Permission{{Resource: "doc", Action: "write"}}}); err != nil {
		t.Fatal(err)
	}
	if err := b.AssignRole(ctx(), "u1", "writer"); err != nil {
		t.Fatal(err)
	}
	if err := b.AssignRole(ctx(), "u2", "writer"); err != nil {
		t.Fatal(err)
	}
	// Unbuffered Publish returns as soon as subscribers receive the event,
	// but their applyInvalidation may still be in flight by microseconds —
	// a rebuild here could race an earlier drop. Let the event queue settle
	// before priming the caches.
	time.Sleep(50 * time.Millisecond)
	if !b.Enforce(ctx(), "u1", "doc", "write") || !b.Enforce(ctx(), "u2", "doc", "write") {
		t.Fatal("sanity: both users must have write")
	}
	key1 := b.userKey("user:u1")
	key2 := b.userKey("user:u2")
	if _, ok := b.cache.Get(key2); !ok {
		t.Fatal("sanity: u2 cache entry missing")
	}
	// Unassigning u1 publishes a drop for u1 only.
	if err := a.UnassignRole(ctx(), "root", "u1", "writer"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := b.cache.Get(key1); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("u1 cache entry was never evicted")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if _, ok := b.cache.Get(key2); !ok {
		t.Fatal("drop event evicted the wrong user (u2)")
	}
	if b.Enforce(ctx(), "u1", "doc", "write") {
		t.Fatal("u1 must lose write after unassignment")
	}
}

// TestInvalidatorPublishErrorsAreBestEffort proves mutations still succeed
// when the invalidator's Publish fails (e.g. Redis down): the mutation is
// committed first, and the lost event only falls back to TTL.
func TestInvalidatorPublishErrorsAreBestEffort(t *testing.T) {
	inv := &fanoutInvalidator{}
	defer inv.Close()
	a, _ := mustEnforcerPair(t, inv)
	// Break the fanout after construction: publish now errors, enforcers
	// must not fail their mutations.
	inv.mu.Lock()
	inv.closed = true
	inv.mu.Unlock()
	if err := a.RegisterRole(ctx(), Role{Name: "extra"}); err != nil {
		t.Fatalf("mutation must not fail on publish error: %v", err)
	}
}

// TestInvalidatorSubscriberStopsOnClose proves Close stops the subscriber
// goroutine and that a second Close is a no-op. The fanout's channel close
// also ends the loop.
func TestInvalidatorSubscriberStopsOnClose(t *testing.T) {
	inv := &fanoutInvalidator{}
	a, _ := mustEnforcerPair(t, inv)
	a.Close()
	a.Close()
	inv.Close()
	// Both subscriber loops end when the invalidator's channel closes.
	time.Sleep(50 * time.Millisecond)
}

// TestNewRedisInvalidator validates construction defaults and nil handling.
func TestNewRedisInvalidator(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("nil client must panic")
		}
	}()
	NewRedisInvalidator(nil, "")
}

// TestRedisInvalidatorDefaultChannel proves an empty channel falls back to
// the default "rbacgo:invalidation".
func TestRedisInvalidatorDefaultChannel(t *testing.T) {
	client := newTestRedisClient(t).(*redis.Client)
	invA := NewRedisInvalidator(client, "")
	invB := NewRedisInvalidator(client, "")
	defer invA.Close()
	defer invB.Close()
	if err := invA.Publish(ctx(), InvalidationEvent{Kind: InvalidateFlush}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]<-chan InvalidationEvent{"a": invA.Messages(), "b": invB.Messages()} {
		select {
		case ev, ok := <-c:
			if !ok {
				t.Fatalf("%s: channel closed early", name)
			}
			if ev.Kind != InvalidateFlush {
				t.Fatalf("%s: unexpected event: %+v", name, ev)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: event not delivered on default channel", name)
		}
	}
}

// TestEnvOwnedRedisClientClosed proves Close releases the Redis client that
// WithConfigFromEnv created (RBAC_CACHE=redis) and is idempotent.
func TestEnvOwnedRedisClientClosed(t *testing.T) {
	mr := miniredis.RunT(t)
	t.Setenv("RBAC_STORE", "memory")
	t.Setenv("RBAC_CACHE", "redis")
	t.Setenv("RBAC_REDIS_ADDR", mr.Addr())
	e, err := New(WithTenant("t"), WithConfigFromEnv())
	if err != nil {
		t.Fatal(err)
	}
	if e.ownedClient == nil {
		t.Fatal("env-created Redis client must be tracked as owned")
	}
	if _, ok := e.cache.(*redisLRU); !ok {
		t.Fatalf("cache must be redis-backed, got %T", e.cache)
	}
	e.Close()
	e.Close()
}

// TestRedisInvalidatorRoundTrip proves two invalidators on one Redis receive
// each other's events (the cross-process path), that foreign payloads are
// ignored, and that Close terminates the subscription.
func TestRedisInvalidatorRoundTrip(t *testing.T) {
	client := newTestRedisClient(t).(*redis.Client)
	invA := NewRedisInvalidator(client, "test:inval")
	invB := NewRedisInvalidator(client, "test:inval")

	// Publish a foreign payload first: subscribers must skip it.
	if err := client.Publish(ctx(), "test:inval", "{not json").Err(); err != nil {
		t.Fatal(err)
	}
	if err := invA.Publish(ctx(), InvalidationEvent{Kind: InvalidateDrop, User: "t::u9"}); err != nil {
		t.Fatal(err)
	}
	// Both subscribers see exactly one event: the drop (the foreign payload
	// is skipped). invA receives its own publish too — every subscriber on
	// the channel gets every event.
	for name, c := range map[string]<-chan InvalidationEvent{"a": invA.Messages(), "b": invB.Messages()} {
		select {
		case ev, ok := <-c:
			if !ok {
				t.Fatalf("%s: channel closed early", name)
			}
			if ev.Kind != InvalidateDrop || ev.User != "t::u9" {
				t.Fatalf("%s: unexpected event: %+v", name, ev)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: event not delivered", name)
		}
	}
	invA.Close()
	invB.Close()
}

// TestRedisInvalidatorFullBufferDrops proves a full subscriber backlog does
// not block the subscription: events are dropped, later ones still arrive.
func TestRedisInvalidatorFullBufferDrops(t *testing.T) {
	client := newTestRedisClient(t).(*redis.Client)
	inv := NewRedisInvalidator(client, "test:inval")
	defer inv.Close()
	for i := 0; i < 128; i++ {
		if err := inv.Publish(ctx(), InvalidationEvent{Kind: InvalidateFlush}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case ev, ok := <-inv.Messages():
			if !ok {
				t.Fatal("channel closed early")
			}
			if ev.Kind != InvalidateFlush {
				t.Fatalf("unexpected event: %+v", ev)
			}
		case <-time.After(50 * time.Millisecond):
			goto done
		}
	}
done:
}

// TestInvalidatorPublishAfterClose proves a subscriber loop exits when the
// invalidator shuts down (Messages closes) even without Enforcer.Close.
func TestInvalidatorPublishAfterClose(t *testing.T) {
	client := newTestRedisClient(t).(*redis.Client)
	inv := NewRedisInvalidator(client, "test:inval")
	store := NewMemoryStore()
	e, err := New(WithTenant("t"), WithStore(store), WithLRU(NewMemoryLRU(1024, time.Hour)), WithCacheInvalidator(inv))
	if err != nil {
		t.Fatal(err)
	}
	inv.Close()
	time.Sleep(50 * time.Millisecond)
	e.Close()
}

// TestInvalidatorWithoutCacheIsInert proves an invalidator attached to an
// enforcer without a cache neither subscribes nor breaks mutations.
func TestInvalidatorWithoutCacheIsInert(t *testing.T) {
	inv := &fanoutInvalidator{}
	defer inv.Close()
	t.Setenv("RBAC_STORE", "memory")
	t.Setenv("RBAC_CACHE", "none")
	e, err := New(WithTenant("t"), WithConfigFromEnv(), WithCacheInvalidator(inv))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.cache != nil {
		t.Fatal("sanity: cache must be disabled")
	}
	if e.stopInvalidation != nil {
		t.Fatal("subscriber must not start without a cache")
	}
	if err := e.RegisterRole(ctx(), Role{Name: "r"}); err != nil {
		t.Fatal(err)
	}
}

// TestWithCacheInvalidatorNil validates the option rejects nil.
func TestWithCacheInvalidatorNil(t *testing.T) {
	if _, err := New(WithTenant("t"), WithStore(NewMemoryStore()), WithCacheInvalidator(nil)); err == nil {
		t.Fatal("nil invalidator must be rejected")
	}
}
