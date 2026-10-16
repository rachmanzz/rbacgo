package rbacgo

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func extensionStores() map[string]func(*testing.T) Store {
	return map[string]func(*testing.T) Store{
		"memory": func(t *testing.T) Store { return NewMemoryStore() },
		"sqlite": func(t *testing.T) Store {
			db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "policy.db"))
			mustFeature(t, err)
			db.SetMaxOpenConns(1)
			t.Cleanup(func() { _ = db.Close() })
			store, err := NewSQLStore(db, WithTablePrefix("feature_"))
			mustFeature(t, err)
			return store
		},
	}
}

func mustFeature(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func extensionEnforcer(t *testing.T, store Store) *Enforcer {
	t.Helper()
	e, err := New(WithTenant("acme"), WithStore(store), WithPolicyRules(), WithWildcardPermissions())
	mustFeature(t, err)
	t.Cleanup(func() { _ = e.Shutdown(context.Background()) })
	ctx := context.Background()
	mustFeature(t, e.RegisterRole(ctx, Role{Name: "manager", Permissions: []Permission{{Resource: "roles", Action: "manage"}}}))
	mustFeature(t, e.AssignRole(ctx, "admin", "manager"))
	return e
}

func exercisePolicyExtensions(t *testing.T, store Store) {
	ctx := context.Background()
	e := extensionEnforcer(t, store)
	mustFeature(t, e.RegisterRoleAs(ctx, "admin", Role{Name: "reader", Permissions: []Permission{{Resource: "*", Action: "read"}}}))
	mustFeature(t, e.AssignRoleAs(ctx, "admin", "alice", "reader"))
	if !e.Enforce(ctx, "alice", "document", "read") {
		t.Fatal("opt-in wildcard not matched")
	}
	literal, err := New(WithTenant("acme"), WithStore(store))
	mustFeature(t, err)
	defer literal.Shutdown(ctx)
	if literal.Enforce(ctx, "alice", "document", "read") {
		t.Fatal("wildcards must remain opt-in")
	}
	mustFeature(t, e.SetRoleMetadata(ctx, "admin", "reader", map[string]string{"description": "Readers"}))
	metadata, err := e.RoleMetadata(ctx, "admin", "reader")
	mustFeature(t, err)
	metadata["description"] = "mutated copy"
	metadata, err = e.RoleMetadata(ctx, "admin", "reader")
	mustFeature(t, err)
	if metadata["description"] != "Readers" {
		t.Fatal("metadata aliases caller memory")
	}
	rules := []PolicyRule{
		{Effect: EffectDeny, Resource: "document", Action: "read", Conditions: []Condition{{Attribute: "resource.classification", Operator: "eq", Value: "secret"}}},
		{Effect: EffectAllow, Resource: "document", Action: "write", Conditions: []Condition{
			{Attribute: "subject.department", Operator: "in", Value: []string{"finance", "legal"}},
			{Attribute: "resource.amount", Operator: "le", Value: 100},
			{Attribute: "resource.owner", Operator: "eq", OtherAttribute: "subject.id"},
		}},
	}
	mustFeature(t, e.SetRoleRules(ctx, "admin", "reader", rules))
	rules[0].Conditions[0].Value = "tampered"
	if !e.EnforceAttributes(ctx, "alice", "document", "read", Attributes{"resource.classification": "public"}) {
		t.Fatal("public document denied")
	}
	if e.EnforceAttributes(ctx, "alice", "document", "read", Attributes{"resource.classification": "secret"}) {
		t.Fatal("deny did not override wildcard allow")
	}
	if e.Enforce(ctx, "alice", "document", "read") {
		t.Fatal("missing deny facts must fail closed")
	}
	facts := Attributes{"subject.department": "finance", "resource.amount": 99, "resource.owner": "alice"}
	if !e.EnforceAttributes(ctx, "alice", "document", "write", facts) {
		t.Fatal("ABAC allow not satisfied")
	}
	facts["resource.amount"] = 101
	if e.EnforceAttributes(ctx, "alice", "document", "write", facts) {
		t.Fatal("numeric condition ignored")
	}
	facts["resource.amount"], facts["resource.owner"], facts["subject.id"] = 99, "mallory", "mallory"
	if e.EnforceAttributes(ctx, "alice", "document", "write", facts) {
		t.Fatal("caller-supplied subject.id overrode authenticated actor")
	}
	mustFeature(t, e.RegisterRoleAs(ctx, "admin", Role{Name: "child", Parents: []string{"reader"}}))
	mustFeature(t, e.AssignRoleAs(ctx, "admin", "bob", "child"))
	if e.EnforceAttributes(ctx, "bob", "document", "read", Attributes{"resource.classification": "secret"}) {
		t.Fatal("inherited deny ignored")
	}
	mustFeature(t, e.RegisterRoleAs(ctx, "admin", Role{Name: "superadmin", Permissions: []Permission{{Resource: "*", Action: "*"}}}))
	mustFeature(t, e.AssignRoleAs(ctx, "admin", "root", "superadmin"))
	mustFeature(t, e.AssignRoleAs(ctx, "admin", "root", "reader"))
	if !e.Enforce(ctx, "root", "other", "anything") {
		t.Fatal("wildcard superadmin not effective")
	}
	if e.EnforceAttributes(ctx, "root", "document", "read", Attributes{"resource.classification": "secret"}) {
		t.Fatal("superadmin bypassed explicit deny")
	}
	view, err := e.PermissionView(ctx, "alice")
	mustFeature(t, err)
	if len(view.Permissions["*"]) != 1 {
		t.Fatal("frontend view should expose patterns without context expansion")
	}
	if err := e.SetRoleRules(ctx, "admin", "reader", []PolicyRule{{Effect: "invalid", Resource: "document", Action: "read"}}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid effect: %v", err)
	}
	if err := e.SetRoleMetadata(ctx, "alice", "reader", nil); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("metadata write bypassed management: %v", err)
	}
	other, err := New(WithTenant("other"), WithStore(store), WithPolicyRules(), WithWildcardPermissions())
	mustFeature(t, err)
	defer other.Shutdown(ctx)
	if _, err := other.RoleRules(ctx, "admin", "reader"); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("cross-tenant policy access: %v", err)
	}
	// Read persisted rules from a separately constructed Enforcer.
	reopened, err := New(WithTenant("acme"), WithStore(store), WithPolicyRules(), WithWildcardPermissions())
	mustFeature(t, err)
	defer reopened.Shutdown(ctx)
	if reopened.EnforceAttributes(ctx, "alice", "document", "read", Attributes{"resource.classification": "secret"}) {
		t.Fatal("rules missing on another Enforcer")
	}
}

func TestPolicyExtensions(t *testing.T) {
	for name, factory := range extensionStores() {
		t.Run(name, func(t *testing.T) { exercisePolicyExtensions(t, factory(t)) })
	}
}

func exerciseAtomicBatch(t *testing.T, store Store) {
	e := extensionEnforcer(t, store)
	ctx := context.Background()
	batch := PolicyBatch{
		Register:        []Role{{Name: "reader", Permissions: []Permission{{Resource: "document", Action: "read"}}}},
		Assign:          []RoleAssignment{{UserID: "alice", RoleName: "reader"}},
		MetadataUpdates: map[string]map[string]string{"reader": {"label": "Original"}},
		RuleUpdates:     map[string][]PolicyRule{"reader": {{Effect: EffectAllow, Resource: "document", Action: "write"}}},
	}
	mustFeature(t, e.ApplyPolicyBatch(ctx, "admin", batch))
	if !e.Enforce(ctx, "alice", "document", "read") || !e.Enforce(ctx, "alice", "document", "write") {
		t.Fatal("committed batch incomplete")
	}
	before, err := e.PermissionView(ctx, "alice")
	mustFeature(t, err)
	bad := PolicyBatch{
		Register:        []Role{{Name: "temporary"}},
		Update:          []Role{{Name: "reader", Permissions: []Permission{{Resource: "document", Action: "delete"}}}},
		MetadataUpdates: map[string]map[string]string{"reader": {"label": "Changed"}},
		RuleUpdates:     map[string][]PolicyRule{"reader": nil},
		Assign:          []RoleAssignment{{UserID: "alice", RoleName: "missing"}},
	}
	if err := e.ApplyPolicyBatch(ctx, "admin", bad); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("batch failure: %v", err)
	}
	if _, exists, err := store.GetRole(ctx, "acme::temporary"); err != nil || exists {
		t.Fatal("rollback left registered role")
	}
	metadata, err := e.RoleMetadata(ctx, "admin", "reader")
	mustFeature(t, err)
	if metadata["label"] != "Original" {
		t.Fatal("rollback changed metadata")
	}
	after, err := e.PermissionView(ctx, "alice")
	mustFeature(t, err)
	if after.PolicyVersion != before.PolicyVersion {
		t.Fatal("failed batch changed version")
	}
	if e.Enforce(ctx, "alice", "document", "delete") || !e.Enforce(ctx, "alice", "document", "write") {
		t.Fatal("rollback changed permissions or rules")
	}
	if err := e.ApplyPolicyBatch(ctx, "alice", batch); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("unguarded batch: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.(AtomicPolicyStore).ApplyPolicyBatch(cancelled, PolicyBatch{Register: []Role{{Name: "cancelled"}}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled batch: %v", err)
	}
	mustFeature(t, e.ApplyPolicyBatch(ctx, "admin", PolicyBatch{Unassign: []RoleAssignment{{"alice", "reader"}}, Delete: []string{"reader"}}))
	mustFeature(t, e.RegisterRoleAs(ctx, "admin", Role{Name: "reader"}))
	rules, err := e.RoleRules(ctx, "admin", "reader")
	mustFeature(t, err)
	metadata, err = e.RoleMetadata(ctx, "admin", "reader")
	mustFeature(t, err)
	if len(rules) != 0 || len(metadata) != 0 {
		t.Fatal("deleted role retained policy extensions")
	}
}

func TestAtomicPolicyBatch(t *testing.T) {
	for name, factory := range extensionStores() {
		t.Run(name, func(t *testing.T) { exerciseAtomicBatch(t, factory(t)) })
	}
}

type failingAuditSink struct{}

func (failingAuditSink) Emit(context.Context, AuditEvent) error {
	return errors.New("audit unavailable")
}

func TestDurableAuditAndMetrics(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	sink, err := NewFileAuditSink(path)
	mustFeature(t, err)
	defer sink.Close()
	metrics := &Metrics{}
	e := mustEnforcer(t, WithMemoryStore(), WithMetrics(metrics), WithAuditSink(sink))
	defer e.Shutdown(ctx)
	mustFeature(t, e.RegisterRole(ctx, Role{Name: "reader", Permissions: []Permission{{Resource: "document", Action: "read"}}}))
	mustFeature(t, e.AssignRole(ctx, "alice", "reader"))
	if !e.Enforce(ctx, "alice", "document", "read") || e.Enforce(ctx, "alice", "document", "delete") {
		t.Fatal("unexpected decision")
	}
	const workers = 20
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !e.Enforce(ctx, "alice", "document", "read") {
				t.Error("concurrent audit denied")
			}
		}()
	}
	wg.Wait()
	stats := metrics.Snapshot()
	if stats.Decisions != workers+2 || stats.Allowed != workers+1 || stats.Denied != 1 || stats.CacheMisses != 1 || stats.CacheHits != workers+1 || stats.Mutations != 2 || stats.DecisionNanoseconds == 0 {
		t.Fatalf("metrics: %+v", stats)
	}
	mustFeature(t, sink.Close())
	wouldAllow, closedErr := e.EnforceCtx(ctx, "alice", "document", "read")
	var closedAuditErr *AuditWriteError
	if wouldAllow || !errors.As(closedErr, &closedAuditErr) {
		t.Fatalf("closed sink allowed an otherwise permitted action: %t, %v", wouldAllow, closedErr)
	}
	file, err := os.Open(path)
	mustFeature(t, err)
	defer file.Close()
	decoder := json.NewDecoder(file)
	ids := make(map[string]bool)
	for range workers + 4 {
		var event AuditEvent
		mustFeature(t, decoder.Decode(&event))
		if event.ID == "" || ids[event.ID] || event.Tenant != "t" || event.Time.IsZero() {
			t.Fatalf("invalid audit event: %+v", event)
		}
		ids[event.ID] = true
	}
	reopened, err := NewFileAuditSink(path)
	mustFeature(t, err)
	mustFeature(t, reopened.Emit(ctx, AuditEvent{Operation: "reopen"}))
	mustFeature(t, reopened.Close())
	failedMetrics := &Metrics{}
	failed := mustEnforcer(t, WithMemoryStore(), WithMetrics(failedMetrics), WithAuditSink(failingAuditSink{}))
	defer failed.Shutdown(ctx)
	err = failed.RegisterRole(ctx, Role{Name: "committed"})
	var auditErr *AuditWriteError
	if !errors.As(err, &auditErr) || !auditErr.Committed {
		t.Fatalf("missing committed marker: %v", err)
	}
	if _, exists, err := failed.Store().GetRole(ctx, "t::committed"); err != nil || !exists {
		t.Fatal("committed mutation was lost")
	}
	allowed, err := failed.EnforceCtx(ctx, "alice", "document", "read")
	if allowed || !errors.As(err, &auditErr) || auditErr.Committed {
		t.Fatalf("audit failure did not fail closed: %t, %v", allowed, err)
	}
	if failedMetrics.Snapshot().AuditErrors != 2 {
		t.Fatal("audit failure metric missing")
	}
	broken := filepath.Join(t.TempDir(), "broken.jsonl")
	mustFeature(t, os.WriteFile(broken, []byte("incomplete"), 0600))
	if _, err := NewFileAuditSink(broken); err == nil {
		t.Fatal("incomplete audit tail accepted")
	}
}

func TestRegistryBoundsAndDrain(t *testing.T) {
	ctx := context.Background()
	reg := NewTenantRegistryWithOptions(func(tenant string) (*Enforcer, error) { return New(WithTenant(tenant)) }, WithRegistryCapacity(1))
	e, release, err := reg.Acquire(ctx, "a")
	mustFeature(t, err)
	if _, err := reg.Get("b"); !errors.Is(err, ErrTenantCapacity) {
		t.Fatalf("leased entry evicted: %v", err)
	}
	deadline, cancel := context.WithTimeout(ctx, time.Millisecond)
	defer cancel()
	if err := reg.Shutdown(deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown did not wait for lease: %v", err)
	}
	if _, err := reg.Get("a"); !errors.Is(err, ErrRegistryClosed) {
		t.Fatalf("shutdown allowed acquisition: %v", err)
	}
	if e.shutdown.Load() {
		t.Fatal("leased Enforcer closed before request drained")
	}
	release()
	release()
	mustFeature(t, reg.Shutdown(ctx))
	if err := e.Store().(*sqlStore).db.Ping(); !errors.Is(err, sql.ErrConnDone) && err == nil {
		t.Fatal("owned SQLite pool was not closed")
	}
	if _, err := e.EnforceCtx(ctx, "alice", "document", "read"); !errors.Is(err, ErrEnforcerClosed) {
		t.Fatalf("closed Enforcer accepted decision: %v", err)
	}
}

func TestRegistryLRUIdleAndFactoryTimeout(t *testing.T) {
	ctx := context.Background()
	reg := NewTenantRegistryWithOptions(func(tenant string) (*Enforcer, error) { return New(WithTenant(tenant), WithMemoryStore()) }, WithRegistryCapacity(1), WithRegistryIdleTTL(5*time.Millisecond))
	defer reg.Shutdown(ctx)
	a, err := reg.Get("a")
	mustFeature(t, err)
	b, err := reg.Get("b")
	mustFeature(t, err)
	if a == b || reg.Len() != 1 {
		t.Fatal("capacity did not evict LRU")
	}
	mustFeature(t, a.Shutdown(ctx))
	deadline := time.Now().Add(time.Second)
	for reg.Len() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if reg.Len() != 0 {
		t.Fatal("idle janitor did not evict")
	}
	timed := NewTenantRegistryContext(func(ctx context.Context, tenant string) (*Enforcer, error) { <-ctx.Done(); return nil, ctx.Err() }, WithRegistryFactoryTimeout(time.Millisecond))
	defer timed.Shutdown(ctx)
	if _, err := timed.Get("a"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("factory timeout: %v", err)
	}
	if !timed.Evict("a") {
		t.Fatal("failed factory entry missing")
	}
	invalid := NewTenantRegistry(func(string) (*Enforcer, error) { return nil, nil })
	defer invalid.Shutdown(ctx)
	if _, err := invalid.Get("a"); !errors.Is(err, ErrTenantFactory) {
		t.Fatalf("invalid factory result: %v", err)
	}
}

func TestPolicyOperators(t *testing.T) {
	for _, test := range []struct {
		op       string
		value    any
		expected any
		match    bool
	}{
		{"eq", 1, json.Number("1.0"), true}, {"ne", "a", "b", true},
		{"gt", 2, 1, true}, {"ge", 2, 2, true}, {"lt", 1, 2, true}, {"le", 2, 2, true},
		{"in", "a", []string{"a", "b"}, true}, {"not_in", "c", []string{"a", "b"}, true},
		{"exists", nil, nil, true}, {"not_exists", nil, nil, false},
	} {
		t.Run(test.op, func(t *testing.T) {
			matched, known := conditionMatches(Condition{Attribute: "x", Operator: test.op, Value: test.expected}, Attributes{"x": test.value})
			if !known || matched != test.match {
				t.Fatalf("condition = %t,%t", matched, known)
			}
		})
	}
	if _, known := conditionMatches(Condition{Attribute: "x", Operator: "gt", Value: 1}, Attributes{"x": "not numeric"}); known {
		t.Fatal("invalid numeric fact treated as known")
	}
	for _, op := range []string{"ne", "not_in"} {
		expected := any("anything")
		if op == "not_in" {
			expected = []string{"anything"}
		}
		if _, known := conditionMatches(Condition{Attribute: "x", Operator: op, Value: expected}, Attributes{"x": func() {}}); known {
			t.Fatalf("invalid fact could grant %s", op)
		}
	}
	large := json.Number("9007199254740993")
	if equalAttribute(large, json.Number("9007199254740992")) {
		t.Fatal("numeric comparison lost precision")
	}
}

func TestFactoryIgnoringContextStillBoundsCallerAndClosesLateResult(t *testing.T) {
	ctx := context.Background()
	resume := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(resume) }) }
	result := make(chan *Enforcer, 1)
	reg := NewTenantRegistryContext(func(context.Context, string) (*Enforcer, error) {
		<-resume
		e, err := New(WithTenant("a"), WithMemoryStore())
		result <- e
		return e, err
	}, WithRegistryFactoryTimeout(time.Millisecond))
	defer reg.Shutdown(ctx)
	defer unblock()
	_, err := reg.Get("a")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("factory bounded wait = %v", err)
	}
	unblock()
	e := <-result
	mustFeature(t, reg.Shutdown(ctx))
	if !e.shutdown.Load() {
		t.Fatal("late factory result leaked")
	}
}

func TestExtendedConcurrentWorkload(t *testing.T) {
	e := extensionEnforcer(t, NewMemoryStore())
	ctx := context.Background()
	mustFeature(t, e.RegisterRoleAs(ctx, "admin", Role{Name: "worker"}))
	mustFeature(t, e.AssignRoleAs(ctx, "admin", "alice", "worker"))
	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for iteration := range 100 {
				switch worker % 4 {
				case 0:
					err := e.SetRoleRules(ctx, "admin", "worker", []PolicyRule{{Effect: EffectAllow, Resource: "doc", Action: "read", Conditions: []Condition{{Attribute: "x", Operator: "eq", Value: iteration % 2}}}})
					if err != nil {
						t.Error(err)
					}
				case 1:
					_, err := e.EnforceAttributesCtx(ctx, "alice", "doc", "read", Attributes{"x": iteration % 2})
					if err != nil {
						t.Error(err)
					}
				case 2:
					if err := e.ApplyPolicyBatch(ctx, "admin", PolicyBatch{MetadataUpdates: map[string]map[string]string{"worker": {"iteration": fmt.Sprint(iteration)}}}); err != nil {
						t.Error(err)
					}
				case 3:
					if _, err := e.RoleRules(ctx, "admin", "worker"); err != nil {
						t.Error(err)
					}
				}
			}
		}(worker)
	}
	wg.Wait()
}
