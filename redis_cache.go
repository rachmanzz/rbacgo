package rbacgo

import (
	"context"
	"encoding/json"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisLRU is a CacheBackend that stores JSON-encoded values in Redis with a
// per-entry TTL. Capacity is a hint; actual eviction follows Redis's own
// maxmemory policy plus the TTL.
type redisLRU struct {
	ctx    context.Context
	client redis.Cmdable
	prefix string
	ttl    time.Duration
}

// NewRedisLRU returns a Redis-backed cache using any go-redis Cmdable
// (*redis.Client, *redis.ClusterClient, ...). Keys are namespaced under
// prefix to allow safe multi-instance sharing.
func NewRedisLRU(client redis.Cmdable, prefix string, ttl time.Duration) CacheBackend {
	if prefix == "" {
		prefix = "rbacgo:cache:"
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &redisLRU{
		ctx:    context.Background(),
		client: client,
		prefix: prefix,
		ttl:    ttl,
	}
}

func (c *redisLRU) key(k string) string { return c.prefix + k }

func (c *redisLRU) Get(key string) (any, bool) {
	raw, err := c.client.Get(c.ctx, c.key(key)).Result()
	if err != nil {
		return nil, false
	}
	var value permissionSet
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, false
	}
	return value, true
}

func (c *redisLRU) Set(key string, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		return
	}
	_ = c.client.Set(c.ctx, c.key(key), raw, c.ttl).Err()
}

func (c *redisLRU) Delete(key string) {
	_ = c.client.Del(c.ctx, c.key(key)).Err()
}

func (c *redisLRU) Flush() {
	var cursor uint64
	for {
		keys, next, err := c.client.Scan(c.ctx, cursor, c.prefix+"*", 100).Result()
		if err != nil {
			return
		}
		if len(keys) > 0 {
			_ = c.client.Del(c.ctx, keys...).Err()
		}
		cursor = next
		if cursor == 0 {
			return
		}
	}
}
