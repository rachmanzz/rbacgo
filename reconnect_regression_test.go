package rbacgo

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisInvalidatorRecoversAndFlushesMissedMutations(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialTimeout: 100 * time.Millisecond})
	defer client.Close()
	inv := NewRedisInvalidator(client, "audit:reconnect")
	defer inv.Close()
	messages := inv.Messages()
	awaitInitialRedisFlush(t, messages)
	ctx := context.Background()
	store := NewMemoryStore()
	a := mustEnforcer(t, WithStore(store))
	b := mustEnforcer(t, WithStore(store), WithCacheInvalidator(inv))
	defer b.Close()
	// Wait for b's initial flush before priming its stale snapshot. Otherwise
	// that pending flush could mask a failure of the reconnect flush below.
	initialDeadline := time.Now().Add(2 * time.Second)
	for {
		b.cacheMu.Lock()
		flushed := b.cacheGeneration > 0
		b.cacheMu.Unlock()
		if flushed {
			break
		}
		if time.Now().After(initialDeadline) {
			t.Fatal("enforcer did not apply initial flush")
		}
		time.Sleep(time.Millisecond)
	}
	register(t, a, Role{Name: "reader", Permissions: []Permission{{Resource: "doc", Action: "read"}}})
	if err := a.AssignRole(ctx, "u", "reader"); err != nil {
		t.Fatal(err)
	}
	if !b.Enforce(ctx, "u", "doc", "read") {
		t.Fatal("initial permission missing")
	}
	// First event also proves the subscription is attached before the outage.
	if err := inv.Publish(ctx, InvalidationEvent{Kind: InvalidateDrop, User: "unrelated"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-messages:
	case <-time.After(2 * time.Second):
		t.Fatal("initial event missing")
	}
	mr.Close()
	// No event can be published during the outage. Recovery must flush this
	// stale snapshot rather than wait for its five-minute TTL.
	if err := store.(RoleUnassigner).UnassignRole(ctx, "t::u", "t::reader"); err != nil {
		t.Fatal(err)
	}
	if err := mr.Restart(); err != nil {
		t.Fatal(err)
	}
	select {
	case ev, ok := <-messages:
		if !ok || ev.Kind != InvalidateFlush {
			t.Fatalf("recovery event = %+v, open=%v", ev, ok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscription did not recover")
	}
	deadline := time.Now().Add(2 * time.Second)
	for b.Enforce(ctx, "u", "doc", "read") {
		if time.Now().After(deadline) {
			t.Fatal("recovery did not invalidate stale permission")
		}
		time.Sleep(time.Millisecond)
	}
	want := InvalidationEvent{Kind: InvalidateDrop, User: "t::user:after-recovery"}
	if err := inv.Publish(ctx, want); err != nil {
		t.Fatal(err)
	}
	select {
	case got, ok := <-messages:
		if !ok || got != want {
			t.Fatalf("post-recovery event = %+v, open=%v", got, ok)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("post-recovery event missing")
	}
	// Shutdown must also terminate a receiver that is currently retrying.
	mr.Close()
	inv.Close()
	select {
	case _, ok := <-messages:
		if ok {
			t.Fatal("subscriber remains open")
		}
	case <-time.After(time.Second):
		t.Fatal("Close blocked during outage")
	}
}

func TestRedisCacheExpiredGenerationCannotBeReused(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	cache := NewRedisLRU(client, "audit:expiry:", time.Minute).(GenerationCacheBackend)
	old, ok := cache.Generation("u")
	if !ok {
		t.Fatal("generation unavailable")
	}
	mr.FastForward(2 * time.Minute)
	current, ok := cache.Generation("u")
	if !ok || current == old {
		t.Fatal("expired generation reused")
	}
	cache.SetIfGeneration("u", permissionSet{"doc": {"read": true}}, old)
	if _, ok := cache.Get("u"); ok {
		t.Fatal("expired fill accepted")
	}
	cache.SetIfGeneration("u", permissionSet{"doc": {"write": true}}, current)
	if _, ok := cache.Get("u"); !ok {
		t.Fatal("current fill rejected")
	}
}

func awaitInitialRedisFlush(t *testing.T, messages <-chan InvalidationEvent) {
	t.Helper()
	select {
	case ev, ok := <-messages:
		if !ok || ev.Kind != InvalidateFlush {
			t.Fatalf("initial subscription event = %+v, open=%v", ev, ok)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("initial subscription did not invalidate cache")
	}
}

func TestRedisInitialAcknowledgementFlushesCachedPermissions(t *testing.T) {
	client := newTestRedisClient(t).(*redis.Client)
	// Hold back the receive loop until an old permission snapshot is cached.
	// This deterministically represents policy changes before the first
	// subscription acknowledgement is consumed.
	ctx, cancel := context.WithCancel(context.Background())
	inv := &redisInvalidator{
		ctx: ctx, cancel: cancel, client: client, channel: "audit:initial",
		sub:  client.Subscribe(ctx, "audit:initial"),
		subs: make(map[<-chan InvalidationEvent]chan InvalidationEvent),
	}
	defer inv.Close()
	messages := inv.Messages()
	store := NewMemoryStore()
	writer := mustEnforcer(t, WithStore(store))
	register(t, writer, Role{Name: "reader", Permissions: []Permission{{Resource: "doc", Action: "read"}}})
	if err := writer.AssignRole(ctx, "u", "reader"); err != nil {
		t.Fatal(err)
	}
	e := mustEnforcer(t, WithStore(store), WithCacheInvalidator(inv))
	defer e.Close()
	if !e.Enforce(ctx, "u", "doc", "read") {
		t.Fatal("initial permission missing")
	}
	// No mutation event is sent for this change: the initial flush must repair
	// the snapshot even when its corresponding event was missed.
	if err := store.(RoleUnassigner).UnassignRole(ctx, "t::u", "t::reader"); err != nil {
		t.Fatal(err)
	}
	go inv.run()
	awaitInitialRedisFlush(t, messages)
	deadline := time.Now().Add(2 * time.Second)
	for e.Enforce(ctx, "u", "doc", "read") {
		if time.Now().After(deadline) {
			t.Fatal("initial acknowledgement left stale permission cached")
		}
		time.Sleep(time.Millisecond)
	}
	// Joining after the acknowledgement must not miss the initial flush.
	awaitInitialRedisFlush(t, inv.Messages())
}

func TestRedisFlushReplacesFullSubscriberQueue(t *testing.T) {
	inv := &redisInvalidator{subs: make(map[<-chan InvalidationEvent]chan InvalidationEvent)}
	defer inv.closeSubscribers()
	slow, fast := inv.Messages(), inv.Messages()
	// Fill only the slow subscriber. Drain the fast one after each event.
	for i := 0; i < cap(slow); i++ {
		inv.broadcast(InvalidationEvent{Kind: InvalidateDrop, User: "t::user:other"})
		<-fast
	}
	done := make(chan struct{})
	go func() { inv.broadcast(InvalidationEvent{Kind: InvalidateFlush}); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("full subscriber blocked flush delivery")
	}
	for _, ch := range []<-chan InvalidationEvent{slow, fast} {
		select {
		case ev := <-ch:
			if ev.Kind != InvalidateFlush {
				t.Fatalf("pending invalidations not covered by flush: %+v", ev)
			}
		default:
			t.Fatal("flush dropped for subscriber")
		}
	}
	if len(slow) != 0 {
		t.Fatal("old invalidations remained after replacement flush")
	}
}
