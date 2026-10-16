package rbacgo

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"strings"
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
	if client == nil {
		panic("rbacgo: nil redis client")
	}
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
	raw, err := c.client.HGet(c.ctx, c.key(key), "value").Result()
	// Read legacy JSON string entries during a rolling upgrade.
	if err != nil && strings.HasPrefix(err.Error(), "WRONGTYPE") {
		raw, err = c.client.Get(c.ctx, c.key(key)).Result()
	}
	if err != nil {
		return nil, false
	}
	var value permissionSet
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, false
	}
	return value, true
}

// Each cache entry is a hash containing an opaque generation and JSON value.
// The scripts touch one key, so conditional fills also work on Redis Cluster.
const redisCacheGeneration = `
if redis.call('TYPE', KEYS[1]).ok == 'hash' then
 local generation = redis.call('HGET', KEYS[1], 'generation')
 if generation then return generation end
end
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[1], 'generation', ARGV[1])
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return ARGV[1]`

const redisCacheConditionalSet = `
if redis.call('TYPE', KEYS[1]).ok ~= 'hash' then return 0 end
if redis.call('HGET', KEYS[1], 'generation') ~= ARGV[1] then return 0 end
redis.call('HSET', KEYS[1], 'value', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1`

const redisCacheSet = `
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[1], 'generation', ARGV[1], 'value', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return 1`

func (c *redisLRU) ttlMilliseconds() int64 {
	// Redis requires a positive expiry; preserve sub-millisecond TTLs as 1ms.
	return max(1, c.ttl.Milliseconds())
}

func (c *redisLRU) Generation(key string) (string, bool) {
	token, err := c.client.Eval(c.ctx, redisCacheGeneration, []string{c.key(key)}, rand.Text(), c.ttlMilliseconds()).Text()
	return token, err == nil
}

func (c *redisLRU) SetIfGeneration(key string, value any, generation string) {
	raw, err := json.Marshal(value)
	if err != nil {
		return
	}
	_ = c.client.Eval(c.ctx, redisCacheConditionalSet, []string{c.key(key)}, generation, raw, c.ttlMilliseconds()).Err()
}

func (c *redisLRU) Set(key string, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		return
	}
	_ = c.client.Eval(c.ctx, redisCacheSet, []string{c.key(key)}, rand.Text(), raw, c.ttlMilliseconds()).Err()
}

func (c *redisLRU) Delete(key string) {
	_ = c.client.Del(c.ctx, c.key(key)).Err()
}

// escapeGlob escapes glob metacharacters so a prefix is matched literally
// when used inside a SCAN pattern.
func escapeGlob(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '*', '?', '[', ']':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (c *redisLRU) Flush() {
	var cursor uint64
	for {
		keys, next, err := c.client.Scan(c.ctx, cursor, escapeGlob(c.prefix)+"*", 100).Result()
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
