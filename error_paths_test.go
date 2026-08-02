package rbacgo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

var errTest = errors.New("boom")

type failGetRolesStore struct {
	Store
}

func (failGetRolesStore) GetRoles(context.Context, string) ([]string, error) {
	return nil, errTest
}

type failGetRoleStore struct {
	Store
	fail map[string]bool
}

func (f failGetRoleStore) GetRole(ctx context.Context, name string) (Role, bool, error) {
	if f.fail[name] {
		return Role{}, false, errTest
	}
	return f.Store.GetRole(ctx, name)
}

type errQuerier struct{}

func (errQuerier) QueryContext(context.Context, string, ...any) (*sql.Rows, error) {
	return nil, errTest
}

func (errQuerier) ExecContext(context.Context, string, ...any) (sql.Result, error) {
	return nil, errTest
}

func (errQuerier) QueryRowContext(context.Context, string, ...any) *sql.Row {
	return &sql.Row{}
}

func TestEnforceCtxStoreError(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithStore(failGetRolesStore{Store: NewMemoryStore()}))

	if _, err := e.EnforceCtx(ctx, "u1", "r", "a"); !errors.Is(err, errTest) {
		t.Fatalf("EnforceCtx = %v, want store error", err)
	}
	if e.Enforce(ctx, "u1", "r", "a") {
		t.Fatal("Enforce should deny on store error")
	}
	if _, err := e.HasRole(ctx, "u1", "r"); !errors.Is(err, errTest) {
		t.Fatalf("HasRole = %v, want store error", err)
	}
}

func TestEnforcerCollectErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("GetRole error during Enforce", func(t *testing.T) {
		ms := NewMemoryStore()
		if err := ms.AddRole(ctx, Role{Name: "a"}); err != nil {
			t.Fatal(err)
		}
		if err := ms.AssignRole(ctx, "u1", "a"); err != nil {
			t.Fatal(err)
		}
		e := mustEnforcer(t, WithStore(failGetRoleStore{Store: ms, fail: map[string]bool{"a": true}}))
		if _, err := e.EnforceCtx(ctx, "u1", "r", "a"); !errors.Is(err, errTest) {
			t.Fatalf("EnforceCtx = %v, want store error", err)
		}
		if _, err := e.HasRole(ctx, "u1", "a"); !errors.Is(err, errTest) {
			t.Fatalf("HasRole = %v, want store error", err)
		}
	})

	t.Run("GetRole error on inherited parent", func(t *testing.T) {
		ms := NewMemoryStore()
		if err := ms.AddRole(ctx, Role{Name: "b"}); err != nil {
			t.Fatal(err)
		}
		if err := ms.AddRole(ctx, Role{Name: "a", Parents: []string{"b"}}); err != nil {
			t.Fatal(err)
		}
		if err := ms.AssignRole(ctx, "u1", "a"); err != nil {
			t.Fatal(err)
		}
		e := mustEnforcer(t, WithStore(failGetRoleStore{Store: ms, fail: map[string]bool{"b": true}}))
		if _, err := e.EnforceCtx(ctx, "u1", "r", "a"); !errors.Is(err, errTest) {
			t.Fatalf("EnforceCtx = %v, want store error on parent lookup", err)
		}
	})

	t.Run("HasRole recursion error on parent", func(t *testing.T) {
		ms := NewMemoryStore()
		if err := ms.AddRole(ctx, Role{Name: "b"}); err != nil {
			t.Fatal(err)
		}
		if err := ms.AddRole(ctx, Role{Name: "a", Parents: []string{"b"}}); err != nil {
			t.Fatal(err)
		}
		if err := ms.AssignRole(ctx, "u1", "a"); err != nil {
			t.Fatal(err)
		}
		e := mustEnforcer(t, WithStore(failGetRoleStore{Store: ms, fail: map[string]bool{"b": true}}))
		if _, err := e.HasRole(ctx, "u1", "b"); !errors.Is(err, errTest) {
			t.Fatalf("HasRole = %v, want store error on parent lookup", err)
		}
	})
}

func TestEnforceInjectedCycleDenies(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	ms := e.store.(*memoryStore)
	ms.roles["a"] = Role{Name: "a", Parents: []string{"b"}}
	ms.roles["b"] = Role{Name: "b", Parents: []string{"a"}}
	ms.users["u1"] = []string{"a"}

	if _, err := e.EnforceCtx(ctx, "u1", "r", "a"); !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("EnforceCtx = %v, want ErrCycleDetected", err)
	}
	if e.Enforce(ctx, "u1", "r", "a") {
		t.Fatal("expected deny on cycle")
	}
}

func TestEnforceMissingParentTolerated(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	ms := e.store.(*memoryStore)
	ms.roles["a"] = Role{Name: "a", Parents: []string{"ghost"}}
	ms.users["u1"] = []string{"a"}

	ok, err := e.EnforceCtx(ctx, "u1", "r", "a")
	if err != nil {
		t.Fatalf("missing parent should be tolerated, got %v", err)
	}
	if ok {
		t.Fatal("expected deny")
	}
}

func TestCollectRoleNamesDiamondAndMissing(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithMemoryStore())
	register(t, e,
		Role{Name: "viewer"},
		Role{Name: "a", Parents: []string{"viewer"}},
		Role{Name: "b", Parents: []string{"viewer"}},
		Role{Name: "top", Parents: []string{"a", "b"}},
	)
	if err := e.AssignRole(ctx, "u1", "top"); err != nil {
		t.Fatal(err)
	}
	// Diamond inheritance revisits "viewer" through both branches.
	has, err := e.HasRole(ctx, "u1", "viewer")
	if err != nil || !has {
		t.Errorf("HasRole(viewer) = %v, %v; want true, nil", has, err)
	}

	// A role whose parent no longer exists is tolerated (defensive).
	ms := e.store.(*memoryStore)
	ms.roles["orphan"] = Role{Name: "orphan", Parents: []string{"ghost"}}
	ms.users["u2"] = []string{"orphan"}
	has, err = e.HasRole(ctx, "u2", "ghost")
	if err != nil || has {
		t.Errorf("HasRole(ghost) = %v, %v; want false, nil", has, err)
	}
}

func TestMemoryStoreAssignRoleIdempotent(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore()
	if err := ms.AddRole(ctx, Role{Name: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := ms.AssignRole(ctx, "u1", "r"); err != nil {
		t.Fatal(err)
	}
	if err := ms.AssignRole(ctx, "u1", "r"); err != nil {
		t.Fatalf("idempotent assign should not error: %v", err)
	}
}

func TestDetectCycleDirect(t *testing.T) {
	noCycle := map[string]Role{"a": {Name: "a"}}
	if err := detectCycle(noCycle, "a", map[string]bool{}); err != nil {
		t.Fatalf("no cycle: %v", err)
	}
	if err := detectCycle(noCycle, "ghost", map[string]bool{}); err != nil {
		t.Fatalf("unknown role should be a no-op: %v", err)
	}
	chain := map[string]Role{
		"a": {Name: "a", Parents: []string{"b"}},
		"b": {Name: "b", Parents: []string{"c"}},
		"c": {Name: "c"},
	}
	if err := detectCycle(chain, "a", map[string]bool{}); err != nil {
		t.Fatalf("chain should be acyclic: %v", err)
	}
	self := map[string]Role{"a": {Name: "a", Parents: []string{"a"}}}
	if err := detectCycle(self, "a", map[string]bool{}); !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("self-cycle = %v, want ErrCycleDetected", err)
	}
	two := map[string]Role{
		"a": {Name: "a", Parents: []string{"b"}},
		"b": {Name: "b", Parents: []string{"a"}},
	}
	if err := detectCycle(two, "a", map[string]bool{}); !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("two-node cycle = %v, want ErrCycleDetected", err)
	}
}

func TestWithSQLStoreNil(t *testing.T) {
	if _, err := New(WithSQLStore(nil)); err == nil {
		t.Fatal("expected error for nil *sql.DB")
	}
}

func TestSQLOpenFailurePaths(t *testing.T) {
	old := sqlOpen
	sqlOpen = func(string, string) (*sql.DB, error) { return nil, errTest }
	defer func() { sqlOpen = old }()

	if _, err := newSQLiteStore(":memory:"); !errors.Is(err, errTest) {
		t.Fatalf("newSQLiteStore = %v, want sql.Open error", err)
	}
	if _, err := New(); !errors.Is(err, errTest) {
		t.Fatalf("New default store = %v, want sql.Open error", err)
	}
	t.Setenv("RBAC_STORE", "sql")
	t.Setenv("RBAC_DATABASE_URL", "sqlite://test")
	if _, err := New(WithConfigFromEnv()); !errors.Is(err, errTest) {
		t.Fatalf("New(WithConfigFromEnv) = %v, want sql.Open error", err)
	}
}

func TestNewSQLStoreClosedDB(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := NewSQLStore(db); err == nil {
		t.Fatal("expected migration error on closed database")
	}
}

func TestNewSQLiteStoreMigrationFailureClosesDB(t *testing.T) {
	// The _query_only pragma lets Open and Ping succeed while rejecting the
	// schema migration, exercising the close-on-failure path.
	if _, err := newSQLiteStore(":memory:?_query_only=1"); err == nil {
		t.Fatal("expected migration error on query-only database")
	}
}

func closedSQLStore(t *testing.T) *sqlStore {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	return &sqlStore{db: db, ph: dialectSQLite.param, sql: buildQueries(dialectSQLite)}
}

func TestSQLStoreClosedDBErrorPaths(t *testing.T) {
	ctx := context.Background()
	s := closedSQLStore(t)
	if _, _, err := s.GetRole(ctx, "x"); err == nil {
		t.Error("GetRole on closed db: want error")
	}
	if err := s.AssignRole(ctx, "u", "r"); err == nil {
		t.Error("AssignRole on closed db: want error")
	}
	if _, err := s.GetRoles(ctx, "u"); err == nil {
		t.Error("GetRoles on closed db: want error")
	}
	if err := s.AddRole(ctx, Role{Name: "r"}); err == nil {
		t.Error("AddRole on closed db: want error")
	}
}

func TestSQLStoreDropTableErrorPaths(t *testing.T) {
	ctx := context.Background()
	newStore := func(t *testing.T) *sqlStore {
		t.Helper()
		db, err := sql.Open("sqlite3", ":memory:")
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewSQLStore(db)
		if err != nil {
			t.Fatal(err)
		}
		return s.(*sqlStore)
	}

	t.Run("insertRole fails via non-insertable view", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.db.Exec(`DROP TABLE roles`); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`CREATE VIEW roles AS SELECT 'x' AS name`); err != nil {
			t.Fatal(err)
		}
		if err := s.AddRole(ctx, Role{Name: "r"}); err == nil {
			t.Error("expected insertRole error")
		}
	})

	t.Run("insertPerm fails", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.db.Exec(`DROP TABLE role_permissions`); err != nil {
			t.Fatal(err)
		}
		if err := s.AddRole(ctx, Role{Name: "r", Permissions: []Permission{{Resource: "x", Action: "y"}}}); err == nil {
			t.Error("expected insertPerm error")
		}
	})

	t.Run("insertParent fails", func(t *testing.T) {
		s := newStore(t)
		if err := s.AddRole(ctx, Role{Name: "p"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`DROP TABLE role_parents`); err != nil {
			t.Fatal(err)
		}
		if err := s.AddRole(ctx, Role{Name: "r", Parents: []string{"p"}}); err == nil {
			t.Error("expected insertParent error")
		}
	})

	t.Run("GetRole query fails after roleExists", func(t *testing.T) {
		s := newStore(t)
		if err := s.AddRole(ctx, Role{Name: "r"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`DROP TABLE role_permissions`); err != nil {
			t.Fatal(err)
		}
		if _, _, err := s.GetRole(ctx, "r"); err == nil {
			t.Error("expected GetRole perms query error")
		}
	})

	t.Run("AssignRole insertUser fails", func(t *testing.T) {
		s := newStore(t)
		if err := s.AddRole(ctx, Role{Name: "r"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`DROP TABLE users`); err != nil {
			t.Fatal(err)
		}
		if err := s.AssignRole(ctx, "u", "r"); err == nil {
			t.Error("expected insertUser error")
		}
	})

	t.Run("AssignRole assignRole fails", func(t *testing.T) {
		s := newStore(t)
		if err := s.AddRole(ctx, Role{Name: "r"}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`DROP TABLE user_roles`); err != nil {
			t.Fatal(err)
		}
		if err := s.AssignRole(ctx, "u", "r"); err == nil {
			t.Error("expected assignRole error")
		}
	})
}

func TestCheckCyclesQueryError(t *testing.T) {
	s := &sqlStore{sql: buildQueries(dialectSQLite)}
	if err := s.checkCycles(context.Background(), errQuerier{}, "a"); err == nil {
		t.Fatal("expected query error")
	}
}

func TestRedisLRUSetMarshalError(t *testing.T) {
	client := newTestRedisClient(t)
	c := NewRedisLRU(client, "test:", time.Minute)
	c.Set("k", make(chan int))
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected miss for unserializable value")
	}
}

func TestRedisLRUGetUnmarshalError(t *testing.T) {
	client := newTestRedisClient(t)
	c := NewRedisLRU(client, "test:", time.Minute)
	if err := client.Set(context.Background(), "test:k", "{not json", time.Minute).Err(); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected miss for invalid JSON")
	}
}

func TestRedisLRUFlushScanError(t *testing.T) {
	mr := miniredis.NewMiniRedis()
	if err := mr.Start(); err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	c := NewRedisLRU(client, "test:", time.Minute)
	c.Set("k", permissionSet{"a": {"b": true}})
	mr.Close()
	c.Flush() // must not panic when the scan fails
}

func TestConfigFromEnvSQLiteBadPath(t *testing.T) {
	t.Setenv("RBAC_STORE", "sqlite")
	t.Setenv("RBAC_SQLITE_PATH", "/nonexistent/dir/that/does/not/exist/rbac.db")
	if _, err := New(WithConfigFromEnv()); err == nil {
		t.Fatal("expected error for invalid sqlite path")
	}
}

func TestConfigFromEnvSQLPostgresNoDriver(t *testing.T) {
	t.Setenv("RBAC_STORE", "sql")
	t.Setenv("RBAC_DATABASE_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	if _, err := New(WithConfigFromEnv()); err == nil {
		t.Fatal("expected error: pgx driver not registered")
	}
}

func TestConfigFromEnvSQLMigrationError(t *testing.T) {
	// STORE=sql skips the ping done by the sqlite path, so a query-only
	// database fails only when the schema migration runs.
	t.Setenv("RBAC_STORE", "sql")
	t.Setenv("RBAC_DATABASE_URL", ":memory:?_query_only=1")
	if _, err := New(WithConfigFromEnv()); err == nil {
		t.Fatal("expected error: schema migration failed on query-only database")
	}
}

func TestEnvDurationInvalid(t *testing.T) {
	t.Setenv("RBAC_TEST_BAD_DUR", "not-a-duration")
	if got := envDuration("RBAC_TEST_BAD_DUR", time.Minute); got != time.Minute {
		t.Errorf("invalid duration fallback = %v, want 1m", got)
	}
}

func TestConfigFromEnvSQLiteMemorySingleConnection(t *testing.T) {
	ctx := context.Background()
	t.Setenv("RBAC_STORE", "sql")
	t.Setenv("RBAC_DATABASE_URL", ":memory:")
	e := mustEnforcer(t, WithConfigFromEnv())
	s, ok := e.store.(*sqlStore)
	if !ok {
		t.Fatalf("store is %T, want *sqlStore", e.store)
	}
	if err := e.RegisterRole(ctx, Role{Name: "viewer", Permissions: []Permission{{Resource: "a", Action: "read"}}}); err != nil {
		t.Fatal(err)
	}

	const workers, iters = 16, 10
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				user := fmt.Sprintf("u%d-%d", id, i)
				if err := e.AssignRole(ctx, user, "viewer"); err != nil {
					errCh <- fmt.Errorf("assign %s: %w", user, err)
					return
				}
				if !e.Enforce(ctx, user, "a", "read") {
					errCh <- fmt.Errorf("enforce %s: expected allow", user)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	if stats := s.dbStats(); stats.OpenConnections > 1 {
		t.Errorf("opened %d connections, want at most 1", stats.OpenConnections)
	}
}

func TestMemoryLRURemoveNil(t *testing.T) {
	c := NewMemoryLRU(2, time.Hour).(*memoryLRU)
	c.removeElement(nil) // must not panic
}

func TestMemoryStoreAddRoleCycleRollback(t *testing.T) {
	ctx := context.Background()
	ms := NewMemoryStore().(*memoryStore)
	// Pre-existing cycle injected directly into the graph; adding a child
	// pointing at it must be rejected and rolled back.
	ms.roles["a"] = Role{Name: "a", Parents: []string{"b"}}
	ms.roles["b"] = Role{Name: "b", Parents: []string{"a"}}
	if err := ms.AddRole(ctx, Role{Name: "c", Parents: []string{"a"}}); !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("AddRole = %v, want ErrCycleDetected", err)
	}
	if _, ok := ms.roles["c"]; ok {
		t.Fatal("role c must be rolled back after cycle detection")
	}
}

func TestMemoryStoreGetRoleReturnsCopy(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	if err := s.AddRole(ctx, Role{
		Name:        "a",
		Permissions: []Permission{{Resource: "r", Action: "read"}},
		Parents:     []string{},
	}); err != nil {
		t.Fatal(err)
	}

	role, ok, err := s.GetRole(ctx, "a")
	if err != nil || !ok {
		t.Fatalf("GetRole = ok %v, err %v", ok, err)
	}
	role.Permissions[0] = Permission{Resource: "HACKED", Action: "admin"}
	role.Permissions = append(role.Permissions, Permission{Resource: "x", Action: "y"})
	role.Parents = append(role.Parents, "ghost")

	got, _, _ := s.GetRole(ctx, "a")
	if len(got.Permissions) != 1 || got.Permissions[0] != (Permission{Resource: "r", Action: "read"}) {
		t.Errorf("store corrupted by caller mutation: %+v", got.Permissions)
	}
	if len(got.Parents) != 0 {
		t.Errorf("store parents corrupted by caller mutation: %+v", got.Parents)
	}
}

func TestMemoryStoreGetRoleConcurrentCopy(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	if err := s.AddRole(ctx, Role{Name: "a", Permissions: []Permission{{Resource: "r", Action: "read"}}}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				r, _, _ := s.GetRole(ctx, "a")
				if len(r.Permissions) > 0 {
					r.Permissions[0] = Permission{Resource: "x", Action: "y"}
				}
			}
		}()
	}
	wg.Wait()
	got, _, _ := s.GetRole(ctx, "a")
	if len(got.Permissions) != 1 || got.Permissions[0] != (Permission{Resource: "r", Action: "read"}) {
		t.Errorf("store corrupted under concurrent GetRole+mutation: %+v", got.Permissions)
	}
}

func TestDriverRegistered(t *testing.T) {
	if !driverRegistered("sqlite3") {
		t.Fatal("sqlite3 driver should be registered")
	}
	if driverRegistered("no-such-driver") {
		t.Fatal("no-such-driver must not be registered")
	}
}
