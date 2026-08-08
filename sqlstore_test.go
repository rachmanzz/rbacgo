package rbacgo

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func sqliteStore(t *testing.T, path string) Store {
	t.Helper()
	s, err := newSQLiteStore(path)
	if err != nil {
		t.Fatalf("newSQLiteStore(%q): %v", path, err)
	}
	return s
}

func TestSQLStoreCRUD(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t, ":memory:")

	if err := s.AddRole(ctx, Role{Name: "viewer", Permissions: []Permission{{Resource: "a", Action: "read"}}}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	role, ok, err := s.GetRole(ctx, "viewer")
	if err != nil || !ok {
		t.Fatalf("GetRole = %v, %v; err %v", role, ok, err)
	}
	if len(role.Permissions) != 1 || role.Permissions[0] != (Permission{Resource: "a", Action: "read"}) {
		t.Errorf("unexpected permissions: %+v", role.Permissions)
	}

	if err := s.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}
	roles, err := s.GetRoles(ctx, "u1")
	if err != nil || len(roles) != 1 || roles[0] != "viewer" {
		t.Errorf("GetRoles = %v, %v", roles, err)
	}

	if err := s.AssignRole(ctx, "u1", "viewer"); err != nil {
		t.Errorf("idempotent AssignRole should not error: %v", err)
	}
	if _, ok, _ := s.GetRole(ctx, "missing"); ok {
		t.Error("GetRole(missing) reported found")
	}
}

// TestSQLStoreNoOwnUsersTable pins ADR-016: the store must not create or touch
// a users table, so it coexists with an application-owned one even when that
// table has columns the library could not fill.
func TestSQLStoreNoOwnUsersTable(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT NOT NULL)`); err != nil {
		t.Fatalf("create app users table: %v", err)
	}
	s, err := NewSQLStore(db)
	if err != nil {
		t.Fatalf("NewSQLStore: %v", err)
	}
	if err := s.AddRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := s.AssignRole(ctx, "app-user-1", "viewer"); err != nil {
		t.Fatalf("AssignRole next to app users table: %v", err)
	}
	roles, err := s.GetRoles(ctx, "app-user-1")
	if err != nil || len(roles) != 1 || roles[0] != "viewer" {
		t.Fatalf("GetRoles = %v, %v", roles, err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatalf("count app users: %v", err)
	}
	if n != 0 {
		t.Fatalf("library inserted into app users table: %d rows", n)
	}
}

func TestSQLStoreHierarchyAndCycles(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t, ":memory:")
	if err := s.AddRole(ctx, Role{Name: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRole(ctx, Role{Name: "editor", Parents: []string{"viewer"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRole(ctx, Role{Name: "editor", Parents: []string{"viewer"}}); !errors.Is(err, ErrRoleExists) {
		t.Fatalf("got %v, want ErrRoleExists", err)
	}
	if err := s.AddRole(ctx, Role{Name: "solo", Parents: []string{"ghost"}}); !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("got %v, want ErrParentNotFound", err)
	}
}

func TestSQLStorePersistenceAcrossReopen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping file-backed persistence test in short mode")
	}
	dir := t.TempDir()
	path := dir + "/rbac.db"

	ctx := context.Background()
	s1 := sqliteStore(t, path)
	if err := s1.AddRole(ctx, Role{Name: "admin", Permissions: []Permission{{Resource: "users", Action: "delete"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s1.AssignRole(ctx, "u1", "admin"); err != nil {
		t.Fatal(err)
	}

	s2 := sqliteStore(t, path)
	role, ok, err := s2.GetRole(ctx, "admin")
	if err != nil || !ok {
		t.Fatalf("reopen GetRole = ok %v, err %v", ok, err)
	}
	if len(role.Permissions) != 1 || role.Permissions[0].Action != "delete" {
		t.Errorf("reopen permissions mismatch: %+v", role.Permissions)
	}
	roles, err := s2.GetRoles(ctx, "u1")
	if err != nil || len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("reopen GetRoles = %v, %v", roles, err)
	}
}

func TestEnforcerWithSQLStore(t *testing.T) {
	ctx := context.Background()
	e := mustEnforcer(t, WithSQLite(":memory:"))
	register(t, e,
		Role{Name: "viewer", Permissions: []Permission{{Resource: "articles", Action: "read"}}},
		Role{Name: "editor", Permissions: []Permission{{Resource: "articles", Action: "write"}}, Parents: []string{"viewer"}},
	)
	if err := e.AssignRole(ctx, "u1", "editor"); err != nil {
		t.Fatal(err)
	}
	if !e.Enforce(ctx, "u1", "articles", "write") {
		t.Error("expected allow write")
	}
	if !e.Enforce(ctx, "u1", "articles", "read") {
		t.Error("expected inherited read")
	}
	if e.Enforce(ctx, "u1", "articles", "delete") {
		t.Error("expected deny delete")
	}
}

func TestSQLStoreListRoles(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t, ":memory:").(*sqlStore)
	if roles, err := s.ListRoles(ctx); err != nil || len(roles) != 0 {
		t.Fatalf("ListRoles on empty store = %v, %v; want empty", roles, err)
	}
	if err := s.AddRole(ctx, Role{Name: "z"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRole(ctx, Role{Name: "a", Permissions: []Permission{{Resource: "x", Action: "read"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRole(ctx, Role{Name: "m", Parents: []string{"a"}}); err != nil {
		t.Fatal(err)
	}
	roles, err := s.ListRoles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 3 || roles[0].Name != "a" || roles[1].Name != "m" || roles[2].Name != "z" {
		t.Fatalf("ListRoles = %+v, want [a m z]", roles)
	}
	if len(roles[1].Parents) != 1 || roles[1].Parents[0] != "a" {
		t.Fatalf("ListRoles parents = %+v, want [a]", roles[1].Parents)
	}
}

func TestSQLStoreUpdateRole(t *testing.T) {
	ctx := context.Background()
	s := sqliteStore(t, ":memory:").(*sqlStore)
	if err := s.AddRole(ctx, Role{Name: "viewer", Permissions: []Permission{{Resource: "a", Action: "read"}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRole(ctx, Role{Name: "editor", Permissions: []Permission{{Resource: "a", Action: "write"}}, Parents: []string{"viewer"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRole(ctx, Role{Name: "top", Parents: []string{"editor"}}); err != nil {
		t.Fatal(err)
	}

	if err := s.UpdateRole(ctx, Role{}); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("UpdateRole invalid = %v, want ErrInvalidRole", err)
	}
	if err := s.UpdateRole(ctx, Role{Name: "ghost"}); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("UpdateRole missing = %v, want ErrRoleNotFound", err)
	}
	if err := s.UpdateRole(ctx, Role{Name: "viewer", Parents: []string{"ghost"}}); !errors.Is(err, ErrParentNotFound) {
		t.Fatalf("UpdateRole missing parent = %v, want ErrParentNotFound", err)
	}
	// editor -> viewer exists; viewer -> editor would cycle.
	if err := s.UpdateRole(ctx, Role{Name: "viewer", Parents: []string{"editor"}}); !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("UpdateRole cycle = %v, want ErrCycleDetected", err)
	}
	// top -> editor -> viewer chain: updating viewer to parent top cycles too.
	if err := s.UpdateRole(ctx, Role{Name: "viewer", Parents: []string{"top"}}); !errors.Is(err, ErrCycleDetected) {
		t.Fatalf("UpdateRole transitive cycle = %v, want ErrCycleDetected", err)
	}
	// Failed updates roll back: viewer still has no parents.
	viewer, ok, err := s.GetRole(ctx, "viewer")
	if err != nil || !ok || len(viewer.Parents) != 0 {
		t.Fatalf("viewer after failed updates = %+v, ok %v, err %v", viewer, ok, err)
	}

	// Successful in-place replace: permissions and parents swap entirely.
	if err := s.UpdateRole(ctx, Role{
		Name:        "viewer",
		Permissions: []Permission{{Resource: "b", Action: "delete"}},
	}); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	got, ok, err := s.GetRole(ctx, "viewer")
	if err != nil || !ok {
		t.Fatalf("GetRole viewer = ok %v, err %v", ok, err)
	}
	if len(got.Permissions) != 1 || got.Permissions[0] != (Permission{Resource: "b", Action: "delete"}) {
		t.Fatalf("updated permissions = %+v, want replace semantics", got.Permissions)
	}
	if len(got.Parents) != 0 {
		t.Fatalf("updated parents = %+v, want none", got.Parents)
	}
	// Adding an acyclic parent works: top -> viewer is fine (viewer has none).
	if err := s.UpdateRole(ctx, Role{Name: "top", Parents: []string{"viewer"}}); err != nil {
		t.Fatalf("UpdateRole parents: %v", err)
	}
	got, _, _ = s.GetRole(ctx, "top")
	if len(got.Parents) != 1 || got.Parents[0] != "viewer" {
		t.Fatalf("top parents = %+v, want [viewer]", got.Parents)
	}
	// Clearing parents works too.
	if err := s.UpdateRole(ctx, Role{Name: "top"}); err != nil {
		t.Fatalf("UpdateRole clear: %v", err)
	}
	got, _, _ = s.GetRole(ctx, "top")
	if len(got.Permissions) != 0 || len(got.Parents) != 0 {
		t.Fatalf("top after clear = %+v, want empty", got)
	}
}

func TestSQLiteMemoryConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	store := sqliteStore(t, ":memory:")
	s, ok := store.(*sqlStore)
	if !ok {
		t.Fatalf("newSQLiteStore returned %T, want *sqlStore", store)
	}
	if err := store.AddRole(ctx, Role{Name: "viewer", Permissions: []Permission{{Resource: "a", Action: "read"}}}); err != nil {
		t.Fatal(err)
	}

	// A pool that opens a second ":memory:" connection would see an empty
	// database ("no such table") or silently missing data. The default store
	// must serialize all access onto one connection.
	const workers, iters = 32, 20
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				user := fmt.Sprintf("u%d-%d", id, i)
				if err := store.AssignRole(ctx, user, "viewer"); err != nil {
					errCh <- fmt.Errorf("assign %s: %w", user, err)
					return
				}
				roles, err := store.GetRoles(ctx, user)
				if err != nil {
					errCh <- fmt.Errorf("getroles %s: %w", user, err)
					return
				}
				if len(roles) != 1 || roles[0] != "viewer" {
					errCh <- fmt.Errorf("getroles %s = %v, want [viewer]", user, roles)
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
		t.Errorf(":memory: store opened %d connections, want at most 1", stats.OpenConnections)
	}
}

func TestSQLiteMemoryDSNVariantSingleConnection(t *testing.T) {
	ctx := context.Background()
	for _, dsn := range []string{":memory:", "file::memory:", "file:memdb1?mode=memory"} {
		t.Run(dsn, func(t *testing.T) {
			store := sqliteStore(t, dsn)
			s, ok := store.(*sqlStore)
			if !ok {
				t.Fatalf("newSQLiteStore(%q) returned %T, want *sqlStore", dsn, store)
			}
			if err := store.AddRole(ctx, Role{Name: "viewer", Permissions: []Permission{{Resource: "a", Action: "read"}}}); err != nil {
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
						if err := store.AssignRole(ctx, user, "viewer"); err != nil {
							errCh <- err
							return
						}
						roles, err := store.GetRoles(ctx, user)
						if err != nil {
							errCh <- err
							return
						}
						if len(roles) != 1 || roles[0] != "viewer" {
							errCh <- fmt.Errorf("getroles %s = %v, want [viewer]", user, roles)
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
				t.Errorf("dsn %q opened %d connections, want at most 1", dsn, stats.OpenConnections)
			}
		})
	}
}
