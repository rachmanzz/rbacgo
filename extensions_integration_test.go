//go:build integration

package rbacgo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/redis/go-redis/v9"
)

func TestSQLConcurrentGraphMutationsPostgres(t *testing.T) {
	dsn := os.Getenv("RBAC_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set RBAC_TEST_POSTGRES_DSN")
	}
	db, err := sql.Open("pgx", dsn)
	mustFeature(t, err)
	defer db.Close()
	db.SetMaxOpenConns(4)
	prefix := fmt.Sprintf("graph_%d_", time.Now().UnixNano())
	store, err := NewSQLStore(db, WithTablePrefix(prefix))
	mustFeature(t, err)
	defer func() {
		for _, table := range []string{"role_rules", "role_metadata", "role_assignments", "role_parents", "role_permissions", "roles", "meta"} {
			if _, err := db.Exec("DROP TABLE " + prefix + table); err != nil {
				t.Error(err)
			}
		}
	}()
	ctx := context.Background()
	for _, role := range []Role{{Name: "a"}, {Name: "c"}, {Name: "b", Parents: []string{"c"}}, {Name: "d", Parents: []string{"a"}}} {
		mustFeature(t, store.AddRole(ctx, role))
	}
	s := store.(*sqlStore)
	// Hold the cycle-check statement's snapshot briefly, making overlapping
	// writes deterministic without adding a production test hook.
	s.sql.cycleCheck = strings.Replace(s.sql.cycleCheck,
		") SELECT COUNT(*) FROM reachable WHERE name = $2",
		"), pause AS MATERIALIZED (SELECT pg_sleep(0.05)) SELECT (SELECT COUNT(*) FROM reachable WHERE name = $2) FROM pause", 1)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, role := range []Role{{Name: "a", Parents: []string{"b"}}, {Name: "c", Parents: []string{"d"}}} {
		wg.Add(1)
		go func(role Role) { defer wg.Done(); <-start; results <- s.UpdateRole(ctx, role) }(role)
	}
	close(start)
	wg.Wait()
	close(results)
	success, rejected := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrCycleDetected) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || rejected != 1 {
		t.Fatalf("concurrent graph writes: success=%d, cycle-rejected=%d; want 1 each", success, rejected)
	}
	for _, operation := range []string{"metadata", "rules", "assignment"} {
		t.Run(operation+"_during_delete", func(t *testing.T) {
			mustFeature(t, s.AddRole(ctx, Role{Name: operation}))
			tx, owned, err := s.beginWrite(ctx)
			mustFeature(t, err)
			defer rollbackOwned(tx, owned)
			work := *s
			work.tx = tx
			mustFeature(t, work.DeleteRole(ctx, operation))
			result := make(chan error, 1)
			requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			go func() {
				switch operation {
				case "metadata":
					result <- s.SetRoleMetadata(requestCtx, operation, map[string]string{"label": "stale"})
				case "rules":
					result <- s.SetRoleRules(requestCtx, operation, []PolicyRule{{Effect: EffectAllow, Resource: "doc", Action: "read"}})
				default:
					result <- s.AssignRole(requestCtx, "alice", operation)
				}
			}()
			select {
			case err := <-result:
				t.Fatalf("write bypassed the deletion lock: %v", err)
			case <-time.After(50 * time.Millisecond):
			}
			mustFeature(t, commitOwned(tx, owned))
			if err := <-result; !errors.Is(err, ErrRoleNotFound) {
				t.Fatalf("write after delete: %v; want ErrRoleNotFound", err)
			}
			mustFeature(t, s.AddRole(ctx, Role{Name: operation}))
			metadata, err := s.GetRoleMetadata(ctx, operation)
			mustFeature(t, err)
			rules, err := s.GetRoleRules(ctx, operation)
			mustFeature(t, err)
			roles, err := s.GetRoles(ctx, "alice")
			mustFeature(t, err)
			if len(metadata)+len(rules)+len(roles) != 0 {
				t.Fatal("deleted role resurrected stale data")
			}
		})
	}
}

func TestPolicyExtensionsPostgres(t *testing.T) {
	dsn := os.Getenv("RBAC_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set RBAC_TEST_POSTGRES_DSN to an isolated test database")
	}
	db, err := sql.Open("pgx", dsn)
	mustFeature(t, err)
	defer db.Close()
	mustFeature(t, db.Ping())
	for _, scenario := range []string{"policy", "batch"} {
		t.Run(scenario, func(t *testing.T) {
			prefix := fmt.Sprintf("feature_%s_%d_", scenario, time.Now().UnixNano())
			store, err := NewSQLStore(db, WithTablePrefix(prefix))
			mustFeature(t, err)
			defer func() {
				for _, table := range []string{"role_rules", "role_metadata", "role_assignments", "role_parents", "role_permissions", "roles", "meta"} {
					if _, err := db.Exec("DROP TABLE " + prefix + table); err != nil {
						t.Error(err)
					}
				}
			}()
			if scenario == "policy" {
				exercisePolicyExtensions(t, store)
			} else {
				exerciseAtomicBatch(t, store)
			}
		})
	}
}

func TestRedisClusterFlush(t *testing.T) {
	addresses := os.Getenv("RBAC_TEST_REDIS_CLUSTER_ADDRS")
	if addresses == "" {
		t.Skip("set RBAC_TEST_REDIS_CLUSTER_ADDRS to an isolated test cluster")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := redis.NewClusterClient(&redis.ClusterOptions{Addrs: strings.Split(addresses, ",")})
	defer client.Close()
	mustFeature(t, client.Ping(ctx).Err())
	prefix := fmt.Sprintf("feature[ab]:%d:", time.Now().UnixNano())
	cache := NewRedisLRU(client, prefix, time.Minute).(*redisLRU)
	outside := strings.Replace(prefix, "[ab]", "a", 1) + "unrelated"
	mustFeature(t, client.Set(ctx, outside, "keep", time.Minute).Err())
	defer client.Del(ctx, outside)
	var keys []string
	for index := range 100 {
		key := fmt.Sprintf("tenant%d::user:%d", index%5, index)
		keys = append(keys, key)
		cache.Set(key, permissionSet{"doc": {"read": true}})
		if _, ok := cache.Get(key); !ok {
			t.Fatal("cluster cache write failed")
		}
	}
	token, ok := cache.Generation(keys[0])
	if !ok {
		t.Fatal("cluster generation failed")
	}
	mustFeature(t, cache.FlushContext(ctx))
	for _, key := range keys {
		if _, ok := cache.Get(key); ok {
			t.Fatalf("flush missed shard/key %s", key)
		}
	}
	cache.SetIfGeneration(keys[0], permissionSet{"doc": {"read": true}}, token)
	if _, ok := cache.Get(keys[0]); ok {
		t.Fatal("stale generation restored flushed entry")
	}
	if value, err := client.Get(ctx, outside).Result(); err != nil || value != "keep" {
		t.Fatalf("literal prefix isolation failed: %s, %v", value, err)
	}
}
