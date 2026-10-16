package rbacgo

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrRegistryClosed = errors.New("rbacgo: tenant registry is shut down")
	ErrTenantCapacity = errors.New("rbacgo: tenant registry capacity exhausted by active entries")
	ErrTenantFactory  = errors.New("rbacgo: invalid tenant factory result")
)

// TenantRegistryOption configures bounded storage, idle eviction, and factories.
type TenantRegistryOption func(*tenantRegistryConfig) error

type tenantRegistryConfig struct {
	capacity       int
	idleTTL        time.Duration
	factoryTimeout time.Duration
}

func WithRegistryCapacity(capacity int) TenantRegistryOption {
	return func(c *tenantRegistryConfig) error {
		if capacity < 0 {
			return fmt.Errorf("rbacgo: negative registry capacity")
		}
		c.capacity = capacity
		return nil
	}
}

func WithRegistryIdleTTL(ttl time.Duration) TenantRegistryOption {
	return func(c *tenantRegistryConfig) error {
		if ttl < 0 {
			return fmt.Errorf("rbacgo: negative idle TTL")
		}
		c.idleTTL = ttl
		return nil
	}
}

func WithRegistryFactoryTimeout(timeout time.Duration) TenantRegistryOption {
	return func(c *tenantRegistryConfig) error {
		if timeout < 0 {
			return fmt.Errorf("rbacgo: negative factory timeout")
		}
		c.factoryTimeout = timeout
		return nil
	}
}

// TenantRegistry caches independently owned tenant Enforcers. Use Acquire for
// work that must be drained before eviction; Get does not retain a lease.
// Optional capacity uses LRU eviction of initialized, unleased entries.
// Idle eviction runs automatically when configured. Call Shutdown to stop it.
type TenantRegistry struct {
	mu       sync.Mutex
	factory  func(context.Context, string) (*Enforcer, error)
	config   tenantRegistryConfig
	cache    map[string]*registryEntry
	all      map[*registryEntry]struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	closed   bool
	stopped  chan struct{}
	stopOnce sync.Once
}

type registryEntry struct {
	ctx      context.Context
	ready    chan struct{}
	finished chan struct{}
	cancel   context.CancelFunc
	enf      *Enforcer
	err      error
	lastUsed time.Time
	refs     int
	retired  bool
	closing  bool
}

// NewTenantRegistry preserves the original context-free factory contract.
func NewTenantRegistry(factory func(string) (*Enforcer, error)) *TenantRegistry {
	return NewTenantRegistryWithOptions(factory)
}

func NewTenantRegistryWithOptions(factory func(string) (*Enforcer, error), opts ...TenantRegistryOption) *TenantRegistry {
	if factory == nil {
		panic("rbacgo: nil tenant enforcer factory")
	}
	return NewTenantRegistryContext(func(_ context.Context, tenant string) (*Enforcer, error) {
		return factory(tenant)
	}, opts...)
}

// NewTenantRegistryContext supports cooperative factory cancellation on eviction,
// shutdown, and the optional timeout. A factory ignoring context cannot be killed;
// bounded cleanup returns its context error and closes the result if it arrives.
// Invalid options panic, consistent with middleware construction.
func NewTenantRegistryContext(factory func(context.Context, string) (*Enforcer, error), opts ...TenantRegistryOption) *TenantRegistry {
	if factory == nil {
		panic("rbacgo: nil tenant enforcer factory")
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &TenantRegistry{factory: factory, cache: make(map[string]*registryEntry), all: make(map[*registryEntry]struct{}), ctx: ctx, cancel: cancel, stopped: make(chan struct{})}
	for _, opt := range opts {
		if err := opt(&r.config); err != nil {
			cancel()
			panic(err)
		}
	}
	if r.config.idleTTL > 0 {
		go r.reap()
	}
	return r
}

func (r *TenantRegistry) Get(tenant string) (*Enforcer, error) {
	return r.GetContext(context.Background(), tenant)
}

func (r *TenantRegistry) GetContext(ctx context.Context, tenant string) (*Enforcer, error) {
	e, release, err := r.Acquire(ctx, tenant)
	if err == nil {
		release()
	}
	return e, err
}

// Acquire returns an Enforcer and an idempotent release function. Middleware
// holds this lease until its downstream handler returns. Do not retain an
// Enforcer after releasing its lease when lifecycle cleanup may run concurrently.
func (r *TenantRegistry) Acquire(ctx context.Context, tenant string) (*Enforcer, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, nil, ErrRegistryClosed
	}
	e := r.cache[tenant]
	if e == nil {
		if r.config.capacity > 0 && len(r.cache) >= r.config.capacity {
			var oldest *registryEntry
			var name string
			for n, candidate := range r.cache {
				if candidate.refs != 0 || !entryReady(candidate) {
					continue
				}
				if oldest == nil || candidate.lastUsed.Before(oldest.lastUsed) {
					oldest, name = candidate, n
				}
			}
			if oldest == nil {
				r.mu.Unlock()
				return nil, nil, ErrTenantCapacity
			}
			delete(r.cache, name)
			r.retireLocked(oldest)
		}
		factoryCtx, cancel := context.WithCancel(r.ctx)
		if r.config.factoryTimeout > 0 {
			cancel()
			factoryCtx, cancel = context.WithTimeout(r.ctx, r.config.factoryTimeout)
		}
		e = &registryEntry{ctx: factoryCtx, ready: make(chan struct{}), finished: make(chan struct{}), cancel: cancel}
		r.cache[tenant], r.all[e] = e, struct{}{}
		go r.provision(factoryCtx, tenant, e)
	}
	e.refs++
	e.lastUsed = time.Now()
	r.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			r.mu.Lock()
			e.refs--
			e.lastUsed = time.Now()
			r.finishLocked(e)
			r.mu.Unlock()
		})
	}
	select {
	case <-ctx.Done():
		release()
		return nil, nil, ctx.Err()
	case <-e.ctx.Done():
		select {
		case <-e.ready:
			if e.err != nil {
				release()
				return nil, nil, e.err
			}
			if err := ctx.Err(); err != nil {
				release()
				return nil, nil, err
			}
			return e.enf, release, nil
		default:
			release()
			return nil, nil, e.ctx.Err()
		}
	case <-e.ready:
		if e.err != nil {
			release()
			return nil, nil, e.err
		}
		if err := ctx.Err(); err != nil {
			release()
			return nil, nil, err
		}
		return e.enf, release, nil
	}
}

func entryReady(e *registryEntry) bool {
	select {
	case <-e.ready:
		return true
	default:
		return false
	}
}

func (r *TenantRegistry) provision(ctx context.Context, tenant string, e *registryEntry) {
	var enf *Enforcer
	var err error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("%w: factory panic: %v", ErrTenantFactory, recovered)
			}
		}()
		enf, err = r.factory(ctx, tenant)
	}()
	if err == nil {
		err = ctx.Err()
	}
	if err == nil && (enf == nil || enf.TenantID() != tenant || enf.shutdown.Load()) {
		err = fmt.Errorf("%w: expected tenant %q", ErrTenantFactory, tenant)
	}
	if err != nil && enf != nil {
		_ = enf.Shutdown(context.Background())
		enf = nil
	}
	r.mu.Lock()
	e.enf, e.err = enf, err
	close(e.ready)
	e.cancel()
	r.finishLocked(e)
	r.mu.Unlock()
}

func (r *TenantRegistry) retireLocked(e *registryEntry) {
	e.retired = true
	e.cancel()
	r.finishLocked(e)
}

func (r *TenantRegistry) finishLocked(e *registryEntry) {
	if !e.retired || e.refs != 0 || !entryReady(e) || e.closing {
		return
	}
	e.closing = true
	go func() {
		if e.enf != nil {
			_ = e.enf.Shutdown(context.Background())
		}
		r.mu.Lock()
		delete(r.all, e)
		close(e.finished)
		r.signalStoppedLocked()
		r.mu.Unlock()
	}()
}

func (r *TenantRegistry) signalStoppedLocked() {
	if r.closed && len(r.all) == 0 {
		r.stopOnce.Do(func() { close(r.stopped) })
	}
}

// Clear forgets entries without closing them, retaining its original semantics.
// Their resources become the caller's responsibility. Prefer ClearAndClose.
func (r *TenantRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.cache {
		delete(r.all, e)
	}
	r.cache = make(map[string]*registryEntry)
}

func (r *TenantRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.cache)
}

func (r *TenantRegistry) Evict(tenant string) bool {
	ok, _ := r.EvictContext(context.Background(), tenant)
	return ok
}

// EvictContext removes an entry, cancels pending provisioning, and waits for
// its leases and factory before closing resources. A timeout does not restore it.
func (r *TenantRegistry) EvictContext(ctx context.Context, tenant string) (bool, error) {
	r.mu.Lock()
	e, ok := r.cache[tenant]
	if ok {
		delete(r.cache, tenant)
		r.retireLocked(e)
	}
	r.mu.Unlock()
	if !ok {
		return false, nil
	}
	select {
	case <-e.finished:
		return true, nil
	case <-ctx.Done():
		return true, ctx.Err()
	}
}

func (r *TenantRegistry) ClearAndClose() { _ = r.ClearAndCloseContext(context.Background()) }

// ClearAndCloseContext drains a snapshot of entries and remains reusable.
// Concurrent acquisitions may create entries outside that snapshot.
func (r *TenantRegistry) ClearAndCloseContext(ctx context.Context) error {
	r.mu.Lock()
	entries := r.cache
	r.cache = make(map[string]*registryEntry)
	for _, e := range entries {
		r.retireLocked(e)
	}
	r.mu.Unlock()
	for _, e := range entries {
		select {
		case <-e.finished:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Shutdown permanently rejects acquisitions, cancels factories, stops idle
// eviction, and drains all tracked leases before releasing owned resources.
// Cleanup continues after the caller's deadline; subsequent calls may wait again.
func (r *TenantRegistry) Shutdown(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	r.cancel()
	r.cache = make(map[string]*registryEntry)
	for e := range r.all {
		r.retireLocked(e)
	}
	r.signalStoppedLocked()
	r.mu.Unlock()
	select {
	case <-r.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// PruneIdle evicts initialized, unleased entries idle for at least the configured
// TTL. The automatic janitor uses the same operation. Pending factories remain
// bounded by capacity and the optional factory timeout.
func (r *TenantRegistry) PruneIdle() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.config.idleTTL <= 0 || r.closed {
		return 0
	}
	now, removed := time.Now(), 0
	for name, e := range r.cache {
		if e.refs == 0 && entryReady(e) && now.Sub(e.lastUsed) >= r.config.idleTTL {
			delete(r.cache, name)
			r.retireLocked(e)
			removed++
		}
	}
	return removed
}

func (r *TenantRegistry) reap() {
	interval := min(time.Minute, max(time.Millisecond, r.config.idleTTL/2))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.PruneIdle()
		}
	}
}
