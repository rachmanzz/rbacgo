# Policy and Operations Guide

These APIs are working-tree additions requiring a subsequent release or local
module replacement. Exact-match behavior remains the default.

## Wildcards, deny rules, and attributes

WithWildcardPermissions enables a complete resource/action field equal to "*".
Matching checks exact, resource plus "*", "*" plus action, and "*" plus "*".
There is no path-glob or regex matching. A role holding "*"/"*" acts as a
tenant-scoped superadmin, subject to explicit deny rules.

Enable WithPolicyRules on every Enforcer sharing a rule dataset. Without it,
legacy decisions do not load extended rules; SetRoleRules and
EnforceAttributesCtx return ErrPolicyRulesDisabled. Custom stores must
implement RoleRuleStore; the shipped stores implement it.

~~~go
e, err := rbacgo.New(
    rbacgo.WithTenant("acme"),
    rbacgo.WithStore(sharedStore),
    rbacgo.WithWildcardPermissions(),
    rbacgo.WithPolicyRules(),
)
// Handle err and bootstrap a trusted administrator.
err = e.SetRoleRules(ctx, adminID, "editor", []rbacgo.PolicyRule{
    {
        Effect: rbacgo.EffectAllow, Resource: "invoice", Action: "approve",
        Conditions: []rbacgo.Condition{
            {Attribute: "subject.department", Operator: "eq", Value: "finance"},
            {Attribute: "resource.amount", Operator: "le", Value: 1000},
        },
    },
    {
        Effect: rbacgo.EffectDeny, Resource: "invoice", Action: "approve",
        Conditions: []rbacgo.Condition{
            {Attribute: "environment.lockdown", Operator: "eq", Value: true},
        },
    },
})
allowed, err := e.EnforceAttributesCtx(ctx, userID, "invoice", "approve",
    rbacgo.Attributes{
        "subject.department": "finance",
        "resource.amount": 500,
        "environment.lockdown": false,
    },
)
~~~

Rules are inherited. Conditions within one rule use AND; multiple allow rules
provide alternatives. Any matching deny wins, including against superadmin.
Conditional allows are additive to ordinary RBAC grants: do not assign a broad
ordinary permission when approval must depend exclusively on an allow condition.

Operators are eq, ne, in, not_in, gt, ge, lt, le, exists, and not_exists.
Values must be JSON-serializable; membership operators require a list.
Numeric comparisons preserve integer precision. OtherAttribute compares two
facts, such as resource.owner to subject.id; do not combine it with Value.
An empty condition list matches unconditionally.

The engine supplies subject.id and tenant.id, overriding caller-supplied values.
All other facts must come from trusted authentication/resource/server data.
Missing or invalid facts cannot satisfy an allow. A candidate deny with unknown
facts fails closed unless another condition definitely excludes that deny.
Do not mutate facts or nested values during evaluation.

WithAttributes(ctx, attrs) supplies facts to existing middleware and Enforce
methods. EnforceOwned also supplies resource.owner and resource.group from its
arguments. Rules are evaluated per call; attribute-sensitive decisions are not
cached. PermissionView exposes ordinary RBAC allow patterns/scopes without
expanding them or applying conditional denies. Treat it as a frontend hint;
enforce every protected backend action with trusted context.

## Metadata and atomic bulk changes

SetRoleMetadata(ctx, actorID, roleName, map[string]string) and
RoleMetadata(ctx, actorID, roleName) check the management capability.
Metadata is descriptive and never authorizes access. Reads return copies.
The original Role struct layout remains unchanged. SQL adds role_metadata and
role_rules tables, honoring WithTablePrefix. Deleting a role removes its details.

~~~go
err := e.ApplyPolicyBatch(ctx, adminID, rbacgo.PolicyBatch{
    Register: []rbacgo.Role{{Name: "reviewer"}},
    Assign: []rbacgo.RoleAssignment{{UserID: userID, RoleName: "reviewer"}},
    MetadataUpdates: map[string]map[string]string{
        "reviewer": {"description": "Review team"},
    },
})
~~~

Batch order is register, update, rules, metadata, unassign, assign, delete.
Parents must precede children during registration. Missing roles, invalid
rules, cycles, cancellation, or write errors roll the whole batch back.
SQL uses one transaction; memory validates a copied state and swaps it under
one lock. Custom stores must implement AtomicPolicyStore.

Authorization precedes the batch. Cache invalidation, best-effort versioning,
and audit emission follow commit. Atomic writes do not make a multi-query
authorization decision an atomic snapshot. RegisterRoles/RegisterRolesAs
retain their original sequential, partially committing behavior.

## Metrics and durable audit

~~~go
metrics := &rbacgo.Metrics{}
audit, err := rbacgo.NewFileAuditSink("authorization.jsonl")
// Handle err; the application owns audit.Close().
e, err := rbacgo.New(
    rbacgo.WithTenant("acme"),
    rbacgo.WithStore(sharedStore),
    rbacgo.WithMetrics(metrics),
    rbacgo.WithAuditSink(audit),
)
stats := metrics.Snapshot()
// Encode stats at an authenticated endpoint or adapt to an existing exporter.
~~~

Metrics count decisions, allowed/denied/errors, cache hits/misses, successful
mutations, audit/invalidation/policy-version failures, and cumulative decision
nanoseconds. Counters are atomic; Snapshot is not one global transaction.
Share an instance across Enforcers for process aggregation or provide separate
instances per tenant. There is no built-in public metrics HTTP endpoint.

Audit events identify the tenant, actor, operation, target user/role, or
resource/action. Decisions and successful mutations are emitted. Failed
mutation attempts are not a separate event stream; management decisions are
audited. Raw attributes and permission bodies are omitted. Backend error
strings may contain operational details.

FileAuditSink appends JSONL and fsyncs every acknowledged event. Persistence
across restart requires a persistent filesystem; a temporary tmpfs path (used
by the example/benchmark) does not provide that guarantee. Use one
instance/writer for a local regular file. Incomplete tails are rejected rather
than silently truncated. A write/fsync failure poisons the sink until explicit
repair/reopening. The caller owns permissions, rotation, retention and backups.
This is not a tamper-resistant ledger or distributed transactional outbox.

Audit failure denies a decision and returns AuditWriteError. When a mutation
already committed, AuditWriteError.Committed is true: inspect it rather than
blindly retrying. Reconcile missing audit records explicitly. Sinks are
synchronous; include their latency and availability in deployment testing.
WithLogger is a separate optional operational warning logger.

## Bounded registries and graceful shutdown

All adapters share the core TenantRegistry. Original constructors remain:

~~~go
registry := httpadapter.NewTenantRegistryContext(
    func(ctx context.Context, tenant string) (*rbacgo.Enforcer, error) {
        if err := ctx.Err(); err != nil { return nil, err }
        return rbacgo.New(rbacgo.WithTenant(tenant), rbacgo.WithStore(sharedStore))
    },
    rbacgo.WithRegistryCapacity(100),
    rbacgo.WithRegistryIdleTTL(15*time.Minute),
    rbacgo.WithRegistryFactoryTimeout(5*time.Second),
)
~~~

Middleware holds an Acquire lease until the downstream handler returns.
Capacity evicts initialized, unleased entries in LRU order; if every entry is
active/provisioning, acquisition returns ErrTenantCapacity. Idle eviction runs
automatically when configured; PruneIdle also supports explicit pruning.
Capacity bounds cached entries, not resources retained by active leases or
arbitrary application references.

Direct users needing cleanup protection call Acquire(ctx, tenant) and defer
its idempotent release. Get/GetContext do not retain a lease after return.
Do not reuse an Enforcer after releasing its lease when eviction may run.
Factories must return independently owned, correctly scoped Enforcers.

EvictContext cancels one factory and waits for its leases before cleanup.
ClearAndCloseContext drains a snapshot and remains reusable; concurrent
acquisitions may create entries outside the snapshot. Shutdown permanently
rejects new acquisitions, cancels factories, stops the janitor, and drains
tracked leases. Cleanup continues after a caller deadline, and subsequent
Shutdown calls may wait again.

Factories must cooperate with cancellation; arbitrary callbacks cannot be
forcibly killed. Calls return promptly on the configured factory timeout; a
late result is closed when it arrives. Do not invoke blocking cleanup from a
handler holding the same lease or from that entry's factory.

At shutdown, stop accepting requests and drain the HTTP server, then shut down
its registry. Registry Shutdown can also reject new leases while waiting for
existing requests. Context deadlines bound the wait. Factory errors are cached;
evict a failed entry to retry. Clear retains forget-only semantics and transfers
cleanup responsibility to the caller.

Enforcer.Shutdown is terminal and closes SQL/SQLite and Redis resources created
by its options. Close retains its historical nonterminal behavior, stopping
invalidation and closing env-owned Redis only. Caller-owned stores, SQL pools,
Redis clients, invalidators and audit sinks are never closed automatically.

## MySQL and Redis Cluster

WithSQLDialect(SQLDialectMySQL) selects MySQL syntax explicitly. The store uses
InnoDB transactions, recursive CTEs, and binary keys. MySQL 8+ syntax is required.
Local verification used MySQL 8.4.11 and 9.6.0; dedicated CI targets MySQL 8.4.
Keys are limited to 768 bytes, including tenant prefixes. Database recursion
limits still apply to pathological hierarchies.

~~~go
store, err := rbacgo.NewSQLStore(db,
    rbacgo.WithSQLDialect(rbacgo.SQLDialectMySQL),
    rbacgo.WithTablePrefix("myapp_"),
)
e, err := rbacgo.New(rbacgo.WithTenant("acme"), rbacgo.WithStore(store))
~~~

Bring your own database/sql driver/pool. The separate integration/mysql module
tests go-mysql-org/go-mysql v1.16.0 (MIT), without adding it to core runtime
dependencies. DSN formats are driver-specific. Environment-driven STORE=sql
retains PostgreSQL/SQLite inference; use explicit options for MySQL.

NewRedisLRU accepts a *redis.ClusterClient. FlushContext visits every primary,
scans the literal prefix, and routes single-key deletes, avoiding CROSSSLOT.
One-key scripts fence conditional fills. FlushContext reports backend errors;
Enforcer logs/counts flush failures when observability is configured.
Existing Flush remains best-effort. Flushing is not an atomic snapshot during
writes/resharding; partitions can prevent invalidation. Pub/sub is asynchronous
and best-effort. Use finite TTLs as recovery protection and validate revocation
requirements instead of assuming instantaneous global revocation.

## Concurrent SQL mutations

PostgreSQL and MySQL serialize store mutations using the mutation_lock row in
this store's meta table. The lock is held until transaction completion, including
an entire policy batch. This prevents concurrent graph changes from creating a
cycle and prevents assignments/rules/metadata from racing role deletion. The
lock works across pools and processes sharing a table prefix. SQL credentials
need INSERT, UPDATE and SELECT rights on the meta table as well as the existing
schema permissions. SQLite relies on its writer locking and rejects conflicting
snapshots. Expect contention under high write volume; different table prefixes
have independent locks. Direct SQL writers must preserve the same invariants.
Decisions still read through multiple queries and are not snapshot transactions.
