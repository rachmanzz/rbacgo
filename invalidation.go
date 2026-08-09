package rbacgo

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/redis/go-redis/v9"
)

// InvalidationEvent describes a policy mutation that makes cached permission
// snapshots stale. Enforcers publish events after successful mutations and
// subscribe to them, so cross-instance cache invalidation no longer waits
// for TTL expiry. Events are best-effort: a lost event only falls back to
// the existing TTL semantics.
type InvalidationEvent struct {
	// Kind is InvalidateFlush or InvalidateDrop.
	Kind string
	// User is the scoped user key (tenant::userID) for InvalidateDrop,
	// ignored otherwise.
	User string
}

const (
	// InvalidateFlush marks every cached snapshot stale: a role-level
	// change (register/update/delete) may affect any user's effective set.
	InvalidateFlush = "flush"
	// InvalidateDrop marks one user's snapshot stale: only their
	// assignments changed (assign/unassign).
	InvalidateDrop = "drop"
)

// CacheInvalidator broadcasts and receives cache-invalidation events between
// Enforcer instances — within a process or across processes (e.g. via Redis
// pub/sub). Implementations must be safe for concurrent use.
type CacheInvalidator interface {
	// Publish broadcasts an invalidation event to every subscribed
	// instance. Callers treat errors as best-effort (TTL remains the
	// fallback), but implementations should still report them.
	Publish(ctx context.Context, ev InvalidationEvent) error
	// Messages delivers events published by other instances. The channel
	// is closed when the invalidator shuts down. One invalidator may feed
	// several Enforcers: every subscriber consumes the same stream and
	// invalidates only its own cache.
	Messages() <-chan InvalidationEvent
	// Close shuts the invalidator down and closes Messages().
	Close() error
}

// redisInvalidator is a CacheInvalidator backed by Redis pub/sub: one
// channel per deployment, JSON-encoded events. Invalidation latency is one
// PUBLISH hop instead of the cache TTL.
type redisInvalidator struct {
	ctx       context.Context
	client    redis.UniversalClient
	channel   string
	msgs      chan InvalidationEvent
	sub       *redis.PubSub
	closeOnce sync.Once
}

// NewRedisInvalidator returns a Redis pub/sub invalidator on channel
// (default "rbacgo:invalidation"). Use one instance per process and share it
// across Enforcers with WithCacheInvalidator, so a deployment holds a single
// subscription no matter how many tenants it serves. Close the invalidator
// when the process shuts down. Accepts any UniversalClient (*redis.Client,
// *redis.ClusterClient, *redis.Ring, ...).
func NewRedisInvalidator(client redis.UniversalClient, channel string) CacheInvalidator {
	if client == nil {
		panic("rbacgo: nil redis client")
	}
	if channel == "" {
		channel = "rbacgo:invalidation"
	}
	sub := client.Subscribe(context.Background(), channel)
	ri := &redisInvalidator{
		ctx:     context.Background(),
		client:  client,
		channel: channel,
		msgs:    make(chan InvalidationEvent, 64),
		sub:     sub,
	}
	go ri.run()
	return ri
}

// run forwards subscription messages to the msgs channel. It exits when the
// subscription is closed (Close or connection loss); the msgs channel is
// closed so subscribers stop cleanly.
func (r *redisInvalidator) run() {
	defer r.sub.Close()
	defer close(r.msgs)
	for {
		msg, err := r.sub.ReceiveMessage(r.ctx)
		if err != nil {
			return
		}
		var ev InvalidationEvent
		if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil {
			// Foreign payload on a shared channel: ignore.
			continue
		}
		select {
		case r.msgs <- ev:
		default: // subscriber backlog full: drop rather than block Redis
		}
	}
}

func (r *redisInvalidator) Publish(ctx context.Context, ev InvalidationEvent) error {
	// InvalidationEvent holds only strings, so marshaling cannot fail.
	payload, _ := json.Marshal(ev)
	return r.client.Publish(ctx, r.channel, payload).Err()
}

func (r *redisInvalidator) Messages() <-chan InvalidationEvent { return r.msgs }

func (r *redisInvalidator) Close() error {
	r.closeOnce.Do(func() { _ = r.sub.Close() })
	return nil
}

// WithCacheInvalidator enables cross-instance cache invalidation. After a
// successful mutation this Enforcer publishes an InvalidationEvent; every
// Enforcer sharing the invalidator then drops or flushes its lookup cache
// immediately instead of waiting for TTL expiry. Requires a lookup cache
// (WithLRU or the default) to receive events; without one the Enforcer
// still publishes its mutations. See NewRedisInvalidator for the Redis
// pub/sub backend, and Enforcer.Close to stop a subscriber cleanly.
func WithCacheInvalidator(inv CacheInvalidator) Option {
	return func(e *Enforcer) error {
		if inv == nil {
			return fmt.Errorf("rbacgo: nil cache invalidator")
		}
		e.invalidator = inv
		return nil
	}
}
