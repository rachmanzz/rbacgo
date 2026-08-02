package rbacgo

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// defaultEnvPrefix is the prefix used for all environment variables when
// WithEnvPrefix is not supplied.
const defaultEnvPrefix = "RBAC_"

// envConfig carries the prefix used by WithConfigFromEnv.
type envConfig struct {
	prefix string
}

// WithEnvPrefix sets the environment variable prefix read by
// WithConfigFromEnv (e.g. "MYAPP_"). Defaults to "RBAC_".
func WithEnvPrefix(prefix string) Option {
	return func(e *Enforcer) error {
		if e.env == nil {
			e.env = &envConfig{}
		}
		e.env.prefix = prefix
		return nil
	}
}

// WithConfigFromEnv configures the Enforcer from environment variables. It
// only fills settings not already set by explicit options. Read once at
// construction; restarts are required to apply changes.
//
// Supported variables (prefix defaults to "RBAC_", see WithEnvPrefix):
//
//	RBAC_STORE           sqlite | sql | memory                 (default sqlite)
//	RBAC_SQLITE_PATH     SQLite DSN / file path                (default ":memory:")
//	RBAC_DATABASE_URL    connection URL for STORE=sql
//	RBAC_CACHE           memory | redis | none                 (default memory)
//	RBAC_CACHE_CAPACITY  LRU capacity                          (default 1024)
//	RBAC_CACHE_TTL       cache TTL (Go duration, e.g. 5m)      (default 5m)
//	RBAC_REDIS_ADDR      Redis address                         (default localhost:6379)
//	RBAC_REDIS_PASSWORD  Redis password
//	RBAC_REDIS_DB        Redis DB index                        (default 0)
func WithConfigFromEnv() Option {
	return func(e *Enforcer) error {
		prefix := defaultEnvPrefix
		if e.env != nil && e.env.prefix != "" {
			prefix = e.env.prefix
		}
		if e.store == nil {
			switch envString(prefix+"STORE", "sqlite") {
			case "sqlite":
				path := envString(prefix+"SQLITE_PATH", ":memory:")
				if err := WithSQLite(path)(e); err != nil {
					return err
				}
			case "sql":
				url := os.Getenv(prefix + "DATABASE_URL")
				if url == "" {
					return fmt.Errorf("rbacgo: %sDATABASE_URL is required when STORE=sql", prefix)
				}
				driver := "pgx"
				if strings.HasPrefix(url, "postgres://") || strings.HasPrefix(url, "postgresql://") {
					if !driverRegistered("pgx") {
						return fmt.Errorf("rbacgo: pgx driver not registered; import %q",
							"github.com/jackc/pgx/v5/stdlib")
					}
				} else {
					driver = "sqlite3"
				}
				db, err := sqlOpen(driver, url)
				if err != nil {
					return fmt.Errorf("rbacgo: open %s: %w", driver, err)
				}
				if driver == "sqlite3" && url == ":memory:" {
					// See newSQLiteStore: a shared in-memory DB must be
					// serialized onto a single pooled connection.
					db.SetMaxOpenConns(1)
					db.SetMaxIdleConns(1)
				}
				if err := WithSQLStore(db)(e); err != nil {
					return err
				}
			case "memory":
				e.store = NewMemoryStore()
			default:
				return fmt.Errorf("rbacgo: unknown %sSTORE value %q (want sqlite, sql or memory)",
					prefix, envString(prefix+"STORE", "sqlite"))
			}
		}
		if e.cache == nil {
			switch envString(prefix+"CACHE", "memory") {
			case "memory":
				capacity := envInt(prefix+"CACHE_CAPACITY", 1024)
				ttl := envDuration(prefix+"CACHE_TTL", 5*time.Minute)
				e.cache = NewMemoryLRU(capacity, ttl)
			case "redis":
				addr := envString(prefix+"REDIS_ADDR", "localhost:6379")
				password := os.Getenv(prefix + "REDIS_PASSWORD")
				dbIdx := envInt(prefix+"REDIS_DB", 0)
				ttl := envDuration(prefix+"CACHE_TTL", 5*time.Minute)
				client := redis.NewClient(&redis.Options{
					Addr:     addr,
					Password: password,
					DB:       dbIdx,
				})
				e.cache = NewRedisLRU(client, prefix+"cache:", ttl)
			case "none":
				// caching disabled
			default:
				return fmt.Errorf("rbacgo: unknown %sCACHE value %q (want memory, redis or none)",
					prefix, envString(prefix+"CACHE", "memory"))
			}
		}
		return nil
	}
}

func envString(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envDuration(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func driverRegistered(name string) bool {
	for _, drv := range sql.Drivers() {
		if drv == name {
			return true
		}
	}
	return false
}
