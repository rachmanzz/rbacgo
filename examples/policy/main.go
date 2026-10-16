// Policy demonstrates attribute rules, deny precedence, atomic provisioning,
// metadata, metrics, and append/fsync audit without an external service.
// The temporary demo path may use tmpfs; use persistent storage in production.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/rachmanzz/rbacgo"
)

func main() {
	ctx := context.Background()
	file, err := os.CreateTemp("", "rbacgo-policy-audit-*.jsonl")
	check(err)
	path := file.Name()
	check(file.Close())
	audit, err := rbacgo.NewFileAuditSink(path)
	check(err)
	defer audit.Close()
	metrics := &rbacgo.Metrics{}
	e, err := rbacgo.New(
		rbacgo.WithTenant("acme"), rbacgo.WithMemoryStore(),
		rbacgo.WithWildcardPermissions(), rbacgo.WithPolicyRules(),
		rbacgo.WithMetrics(metrics), rbacgo.WithAuditSink(audit),
	)
	check(err)
	defer e.Shutdown(ctx)
	// Bootstrap is trusted provisioning, not a user-facing unguarded endpoint.
	check(e.RegisterRole(ctx, rbacgo.Role{Name: "manager", Permissions: []rbacgo.Permission{{Resource: "roles", Action: "manage"}}}))
	check(e.AssignRole(ctx, "admin", "manager"))
	check(e.ApplyPolicyBatch(ctx, "admin", rbacgo.PolicyBatch{
		Register:        []rbacgo.Role{{Name: "reviewer"}},
		Assign:          []rbacgo.RoleAssignment{{UserID: "alice", RoleName: "reviewer"}},
		MetadataUpdates: map[string]map[string]string{"reviewer": {"description": "Finance reviewers"}},
		RuleUpdates: map[string][]rbacgo.PolicyRule{"reviewer": {
			{Effect: rbacgo.EffectAllow, Resource: "invoice", Action: "approve", Conditions: []rbacgo.Condition{{Attribute: "amount", Operator: "le", Value: 1000}}},
			{Effect: rbacgo.EffectDeny, Resource: "invoice", Action: "approve", Conditions: []rbacgo.Condition{{Attribute: "locked", Operator: "eq", Value: true}}},
		}},
	}))
	allowed, err := e.EnforceAttributesCtx(ctx, "alice", "invoice", "approve", rbacgo.Attributes{"amount": 500, "locked": false})
	check(err)
	fmt.Println("Approval allowed:", allowed)
	allowed, err = e.EnforceAttributesCtx(ctx, "alice", "invoice", "approve", rbacgo.Attributes{"amount": 500, "locked": true})
	check(err)
	fmt.Println("Locked invoice allowed:", allowed)
	fmt.Printf("Metrics: %+v\n", metrics.Snapshot())
	fmt.Println("Audit log (temporary demo file):", path)
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
