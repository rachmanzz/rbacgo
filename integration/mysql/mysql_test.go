package mysqlintegration

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/go-mysql-org/go-mysql/driver"
	"github.com/rachmanzz/rbacgo"
)

func TestMySQLPolicyFlow(t *testing.T) {
	dsn := os.Getenv("RBAC_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set RBAC_TEST_MYSQL_DSN to an isolated test database")
	}
	db, err := sql.Open("mysql", dsn)
	check(t, err)
	defer db.Close()
	check(t, db.Ping())
	prefix := fmt.Sprintf("audit_%d_", time.Now().UnixNano())
	store, err := rbacgo.NewSQLStore(db, rbacgo.WithTablePrefix(prefix), rbacgo.WithSQLDialect(rbacgo.SQLDialectMySQL))
	check(t, err)
	defer func() {
		for _, table := range []string{"role_rules", "role_metadata", "role_assignments", "role_parents", "role_permissions", "roles", "meta"} {
			_, err := db.Exec("DROP TABLE " + prefix + table)
			check(t, err)
		}
	}()
	ctx := context.Background()
	e, err := rbacgo.New(rbacgo.WithTenant("Case_%tenant"), rbacgo.WithStore(store), rbacgo.WithPolicyRules(), rbacgo.WithWildcardPermissions())
	check(t, err)
	defer e.Shutdown(ctx)
	check(t, e.RegisterRole(ctx, rbacgo.Role{Name: "manager", Permissions: []rbacgo.Permission{{Resource: "roles", Action: "manage"}}}))
	check(t, e.AssignRole(ctx, "admin", "manager"))
	check(t, e.ApplyPolicyBatch(ctx, "admin", rbacgo.PolicyBatch{
		Register:        []rbacgo.Role{{Name: "reader", Permissions: []rbacgo.Permission{{Resource: "*", Action: "read"}}}, {Name: "child", Parents: []string{"reader"}}},
		Assign:          []rbacgo.RoleAssignment{{UserID: "alice", RoleName: "child"}},
		MetadataUpdates: map[string]map[string]string{"reader": {"label": "Readers"}},
		RuleUpdates:     map[string][]rbacgo.PolicyRule{"reader": {{Effect: rbacgo.EffectDeny, Resource: "doc", Action: "read", Conditions: []rbacgo.Condition{{Attribute: "secret", Operator: "eq", Value: true}}}}},
	}))
	if !e.EnforceAttributes(ctx, "alice", "doc", "read", rbacgo.Attributes{"secret": false}) {
		t.Fatal("wildcard allow missing")
	}
	if e.EnforceAttributes(ctx, "alice", "doc", "read", rbacgo.Attributes{"secret": true}) {
		t.Fatal("inherited deny ignored")
	}
	metadata, err := e.RoleMetadata(ctx, "admin", "reader")
	check(t, err)
	if metadata["label"] != "Readers" {
		t.Fatal("metadata not persisted")
	}
	view, err := e.PermissionView(ctx, "alice")
	check(t, err)
	bad := rbacgo.PolicyBatch{
		Register: []rbacgo.Role{{Name: "temporary"}},
		Update:   []rbacgo.Role{{Name: "reader", Permissions: []rbacgo.Permission{{Resource: "doc", Action: "delete"}}}},
		Assign:   []rbacgo.RoleAssignment{{UserID: "alice", RoleName: "missing"}},
	}
	if err := e.ApplyPolicyBatch(ctx, "admin", bad); !errors.Is(err, rbacgo.ErrRoleNotFound) {
		t.Fatalf("rollback error: %v", err)
	}
	after, err := e.PermissionView(ctx, "alice")
	check(t, err)
	if after.PolicyVersion != view.PolicyVersion {
		t.Fatal("failed batch incremented version")
	}
	roles, err := e.ListRolesAs(ctx, "admin")
	check(t, err)
	if len(roles) != 3 {
		t.Fatalf("rollback or listing broken: %+v", roles)
	}
	if err := e.UpdateRole(ctx, "admin", rbacgo.Role{Name: "reader", Parents: []string{"child"}}); !errors.Is(err, rbacgo.ErrCycleDetected) {
		t.Fatalf("cycle accepted: %v", err)
	}
	other, err := rbacgo.New(rbacgo.WithTenant("case_%tenant"), rbacgo.WithStore(store))
	check(t, err)
	defer other.Shutdown(ctx)
	otherRoles, err := other.ListRoles(ctx)
	check(t, err)
	if len(otherRoles) != 0 || other.Enforce(ctx, "alice", "doc", "read") {
		t.Fatal("case-sensitive tenant isolation failed")
	}
	check(t, e.ApplyPolicyBatch(ctx, "admin", rbacgo.PolicyBatch{Unassign: []rbacgo.RoleAssignment{{UserID: "alice", RoleName: "child"}}, Delete: []string{"child", "reader"}}))
	check(t, e.RegisterRoles(ctx, []rbacgo.Role{{Name: "a"}, {Name: "c"}, {Name: "b", Parents: []string{"c"}}, {Name: "d", Parents: []string{"a"}}}...))
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, role := range []rbacgo.Role{{Name: "a", Parents: []string{"b"}}, {Name: "c", Parents: []string{"d"}}} {
		wg.Add(1)
		go func(role rbacgo.Role) { defer wg.Done(); <-start; results <- e.UpdateRole(ctx, "admin", role) }(role)
	}
	close(start)
	wg.Wait()
	close(results)
	success, rejected := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, rbacgo.ErrCycleDetected) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || rejected != 1 {
		t.Fatalf("concurrent cycle: success=%d rejected=%d; want one each", success, rejected)
	}
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
