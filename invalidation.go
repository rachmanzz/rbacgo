package rbacgo

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

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
	// several Enforcers: each call creates a new subscription receiving
	// subsequent events, so every subscriber can invalidate its own cache.
	// The Redis backend also sends a flush on initial subscription and recovery.
	Messages() <-chan InvalidationEvent
	// Close shuts the invalidator down and closes Messages().
	Close() error
}

// redisInvalidator is a CacheInvalidator backed by Redis pub/sub: one
// channel per deployment, JSON-encoded events. Invalidation latency is one
// PUBLISH hop instead of the cache TTL.
type redisInvalidator struct {
	ctx       context.Context
	cancel    context.CancelFunc
	client    redis.UniversalClient
	channel   string
	mu        sync.Mutex
	subs      map[<-chan InvalidationEvent]chan InvalidationEvent
	closed    bool
	ready     bool
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
	ctx, cancel := context.WithCancel(context.Background())
	sub := client.Subscribe(ctx, channel)
	ri := &redisInvalidator{
		ctx:     ctx,
		cancel:  cancel,
		client:  client,
		channel: channel,
		subs:    make(map[<-chan InvalidationEvent]chan InvalidationEvent),
		sub:     sub,
	}
	go ri.run()
	return ri
}

// run keeps subscriber channels alive through transient connection failures.
// go-redis reconnects and resubscribes on the next Receive call. After the
// subscription acknowledgement, including the first, flush snapshots that
// may have missed events before Redis confirmed the subscription.
func (r *redisInvalidator) run() {
	defer r.sub.Close()
	defer r.closeSubscribers()
	delay := 50 * time.Millisecond
	for {
		msg, err := r.sub.Receive(r.ctx)
		if err != nil {
			if r.ctx.Err() != nil {
				return
			}
			r.mu.Lock()
			r.ready = false
			r.mu.Unlock()
			timer := time.NewTimer(delay)
			select {
			case <-r.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			delay = min(2*delay, time.Second)
			continue
		}
		delay = 50 * time.Millisecond
		switch msg := msg.(type) {
		case *redis.Subscription:
			if msg.Kind == "subscribe" && msg.Channel == r.channel {
				r.mu.Lock()
				r.ready = true
				r.broadcastLocked(InvalidationEvent{Kind: InvalidateFlush})
				r.mu.Unlock()
			}
		case *redis.Message:
			var ev InvalidationEvent
			if err := json.Unmarshal([]byte(msg.Payload), &ev); err == nil {
				r.broadcast(ev)
			}
		}
	}
}

func (r *redisInvalidator) broadcast(ev InvalidationEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.broadcastLocked(ev)
}

// All senders and channel closure hold mu. Receivers can only create room,
// so after draining a full queue the replacement flush cannot block.
func (r *redisInvalidator) broadcastLocked(ev InvalidationEvent) {
	for _, ch := range r.subs {
		select {
		case ch <- ev:
		default:
			if ev.Kind == InvalidateFlush {
				draining := true
				for draining {
					select {
					case <-ch:
					default:
						draining = false
					}
				}
				ch <- ev // One flush covers all discarded user invalidations.
			}
		}
	}
}

func (r *redisInvalidator) Publish(ctx context.Context, ev InvalidationEvent) error {
	// InvalidationEvent holds only strings, so marshaling cannot fail.
	payload, _ := json.Marshal(ev)
	return r.client.Publish(ctx, r.channel, payload).Err()
}

func (r *redisInvalidator) Messages() <-chan InvalidationEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch := make(chan InvalidationEvent, 64)
	if r.closed {
		close(ch)
	} else {
		r.subs[ch] = ch
		if r.ready {
			ch <- InvalidationEvent{Kind: InvalidateFlush}
		}
	}
	return ch
}

func (r *redisInvalidator) unsubscribe(ch <-chan InvalidationEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.subs[ch]; ok {
		delete(r.subs, ch)
		close(c)
	}
}

func (r *redisInvalidator) closeSubscribers() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for ch, c := range r.subs {
		delete(r.subs, ch)
		close(c)
	}
}

func (r *redisInvalidator) Close() error {
	r.closeOnce.Do(func() {
		r.cancel()
		_ = r.sub.Close()
		r.closeSubscribers()
	})
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
