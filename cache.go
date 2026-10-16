package rbacgo

import (
	"container/list"
	"strconv"
	"sync"
	"time"
)

// CacheBackend is the storage primitive used by the Enforcer's lookup cache.
// Implementations must be safe for concurrent use.
type CacheBackend interface {
	// Get returns the cached value and whether it was present.
	Get(key string) (any, bool)
	// Set stores a value under key.
	Set(key string, value any)
	// Delete removes a key.
	Delete(key string)
	// Flush removes all entries.
	Flush()
}

// GenerationCacheBackend optionally prevents stale cache fills across enforcers.
// Implementations must return an opaque token for the key and atomically reject
// SetIfGeneration after Delete/Flush invalidates it. Invalidated tokens must
// never become valid again, including after metadata expiration or recreation.
// A false result disables the fill.
// Custom backends without this interface retain per-enforcer protection only.
type GenerationCacheBackend interface {
	CacheBackend
	Generation(key string) (string, bool)
	SetIfGeneration(key string, value any, generation string)
}

// memoryLRU is an in-house, fixed-capacity LRU cache with TTL eviction. It has
// zero third-party dependencies.
type memoryLRU struct {
	mu         sync.Mutex
	generation uint64
	cap        int
	ttl        time.Duration
	order      *list.List
	items      map[string]*list.Element
}

type lruEntry struct {
	key     string
	value   any
	expires time.Time
}

// NewMemoryLRU returns a concurrency-safe LRU backend holding at most capacity
// entries. Entries older than ttl are treated as misses.
func NewMemoryLRU(capacity int, ttl time.Duration) CacheBackend {
	if capacity <= 0 {
		capacity = 1024
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &memoryLRU{
		cap:   capacity,
		ttl:   ttl,
		order: list.New(),
		items: make(map[string]*list.Element),
	}
}

func (c *memoryLRU) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	entry := el.Value.(*lruEntry)
	if time.Now().After(entry.expires) {
		c.removeElement(el)
		return nil, false
	}
	c.order.MoveToFront(el)
	return entry.value, true
}

func (c *memoryLRU) Generation(_ string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strconv.FormatUint(c.generation, 10), true
}

func (c *memoryLRU) SetIfGeneration(key string, value any, generation string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation == strconv.FormatUint(c.generation, 10) {
		c.setLocked(key, value)
	}
}

func (c *memoryLRU) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.setLocked(key, value)
}

func (c *memoryLRU) setLocked(key string, value any) {
	if el, ok := c.items[key]; ok {
		entry := el.Value.(*lruEntry)
		entry.value = value
		entry.expires = time.Now().Add(c.ttl)
		c.order.MoveToFront(el)
		return
	}
	el := c.order.PushFront(&lruEntry{key: key, value: value, expires: time.Now().Add(c.ttl)})
	c.items[key] = el
	if c.order.Len() > c.cap {
		c.removeElement(c.order.Back())
	}
}

func (c *memoryLRU) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
	if el, ok := c.items[key]; ok {
		c.removeElement(el)
	}
}

func (c *memoryLRU) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
	c.order.Init()
	c.items = make(map[string]*list.Element)
}

func (c *memoryLRU) removeElement(el *list.Element) {
	if el == nil {
		return
	}
	c.order.Remove(el)
	delete(c.items, el.Value.(*lruEntry).key)
}
