package rbacgo

import (
	"context"

	"github.com/redis/go-redis/v9"
)

// redisPolicyVersion is a PolicyVersioner backed by a single Redis key.
// NextPolicyVersion uses INCR, so every Enforcer instance — across processes —
// agrees on one monotonically increasing version (shared deployments).
type redisPolicyVersion struct {
	ctx    context.Context
	client redis.Cmdable
	key    string
}

// NewRedisPolicyVersion returns a shared policy-version source stored in
// Redis under key (e.g. "rbacgo:policy_version"). Prefix the key per
// application, exactly like the cache prefix. Pass it to WithPolicyVersionStore
// when the store has no version of its own, or to override the store's default.
func NewRedisPolicyVersion(client redis.Cmdable, key string) PolicyVersioner {
	if client == nil {
		panic("rbacgo: nil redis client")
	}
	if key == "" {
		key = "rbacgo:policy_version"
	}
	return &redisPolicyVersion{ctx: context.Background(), client: client, key: key}
}

// PolicyVersion returns the currently committed version (0 when no mutation
// has been recorded).
func (r *redisPolicyVersion) PolicyVersion(ctx context.Context) (uint64, error) {
	v, err := r.client.Get(ctx, r.key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return uint64(v), nil
}

// NextPolicyVersion atomically increments the key (INCR) and returns the new
// value.
func (r *redisPolicyVersion) NextPolicyVersion(ctx context.Context) (uint64, error) {
	v, err := r.client.Incr(ctx, r.key).Result()
	if err != nil {
		return 0, err
	}
	return uint64(v), nil
}
