# Known Limitations — rbacgo

- **Last updated:** 2026-10-16
- **Reference:** docs/feature-guide.md and .knowledges/audit/feature-audit_v3.md

## Policy semantics

- Exact RBAC matching remains the default. Wildcards require
  WithWildcardPermissions and match only a complete resource/action field equal
  to "*". There is no path glob, regex, or arbitrary policy scripting language.
- Attribute conditions and deny rules require WithPolicyRules on every relevant
  Enforcer and a RoleRuleStore. Conditions use the documented JSON operators;
  they do not execute arbitrary callbacks or external queries. Applications
  must supply trusted facts. Any matching deny overrides allows, including
  wildcard superadmin. Unknown deny facts conservatively fail closed.
- Conditional allows are additive to ordinary permissions, not restrictions on
  broad grants. Metadata is descriptive and does not affect decisions.
- PermissionView exposes ordinary allow patterns/scopes. It does not evaluate
  attribute-sensitive rules or represent final authorization for a resource.
- No administration UI, per-field authorization, or adapter aggregator.

## Administrative boundaries

- RegisterRole, RegisterRoles, AssignRole, and ListRoles remain trusted APIs
  without caller checks. Their As variants and update/delete/unassign check the
  configured tenant management permission. Authenticate actors and verify
  tenant membership before selecting an Enforcer.
- Direct Store calls bypass Enforcer scoping, capability checks, audit emission,
  version bookkeeping, and cache invalidation.
- RegisterRoles/RegisterRolesAs retain sequential partial commits.
  ApplyPolicyBatch atomically changes policy data on stores implementing
  AtomicPolicyStore. Cache/version/audit work follows commit, and multi-query
  decisions are not atomic snapshots of concurrent policy changes.

## Storage and consistency

- Shipped SQL dialects are SQLite, PostgreSQL, and explicit MySQL syntax.
  Tested drivers are listed in the README. Other dialects require a custom Store.
  MySQL requires recursive-CTE support (8+ syntax), InnoDB, and keys no longer
  than 768 bytes including tenant prefixes. Server recursion limits apply.
- The go-sqlite3 backend requires CGO. Default SQLite is :memory: and resets on restart. Use a path for persistence.
  Memory storage loses all state on restart. Custom Store concurrency and
  optional capabilities remain the implementer's responsibility.
- PostgreSQL/MySQL mutations serialize per table prefix through a meta-row
  transaction lock, including batches. This limits concurrent write throughput;
  credentials need meta INSERT/UPDATE/SELECT rights. SQLite uses its writer
  locking. Direct SQL writers bypass this serialization.
- Role rules/metadata use additive SQL side tables. Direct SQL edits must
  preserve invariants and require explicit invalidation or TTL expiry.
  There is no database change watcher or automatic env configuration reload.
- Shared policy versions are best-effort hints, not atomic policy revisions.
  Source outages use local counters, which can diverge or move backward after
  recovery. Clients must fetch fresh snapshots; versions are not notifications.
- Pub/sub invalidation is asynchronous and best-effort. Network failures can
  leave remote caches stale until TTL expiry or another invalidation. There is
  no instantaneous distributed revocation guarantee.
- Redis Cluster flush visits primaries and deletes individual keys. It is not
  an atomic snapshot during writes/resharding; errors can leave entries behind.
  FlushContext reports failures; legacy Flush is best-effort. Redis eviction
  follows server policy/TTL rather than a bounded client-side LRU.
- Custom shared caches should implement GenerationCacheBackend; otherwise
  stale-fill protection is limited to mutations observed by one Enforcer.

## Registry and resource lifecycle

- Capacity/idle eviction/factory timeouts are optional. Without them, the
  registry retains entries until explicit removal. Factory failures are cached.
  Bounds apply to cached entries, not all active leases or retained references.
- Middleware leases protect active handlers from cleanup. Direct Get calls
  retain no lease; use Acquire for lifecycle protection. Release leases promptly.
- Shutdown is terminal; ClearAndClose drains a reusable snapshot; Clear only
  forgets entries. Cleanup deadlines do not forcibly terminate factories or
  handlers. Callbacks must cooperate with cancellation; late factory results
  are closed when they arrive. Do not block on cleanup from a holder of the
  same lease or its factory.
- Enforcer.Shutdown closes owned SQLite/SQL and Redis resources. Close retains
  its older nonterminal behavior. Caller-owned SQL pools, Stores, Redis clients,
  invalidators, and audit sinks must be closed separately.
- Tenants are fixed per Enforcer; IDs cannot contain the reserved separator ::.
  Namespacing does not authenticate or authorize the tenant resolver.

## Observability and performance

- Metrics are counters and cumulative latency, not histograms or a public HTTP
  exporter. Snapshot reads counters individually. Configure the application's
  own authenticated exporter and cardinality/retention policy.
- Durable file audit uses synchronous append and fsync on a persistent
  filesystem; tmpfs cannot preserve events across restart. One local writer is
  supported; rotation, retention, backups and file access belong to the caller.
  It is not tamper-resistant, a distributed outbox, or atomic with SQL mutations.
  AuditWriteError.Committed identifies changes that succeeded before audit
  persistence failed. Do not blindly retry them. Failed mutation attempts are
  not a separate event stream; management decisions are audited.
- Audit sink failure denies authorization. Sink latency and availability affect
  request paths. Operational logging is separate and opt-in.
- Warm memory-cache lookups are constant-time; role graph resolution, extended
  rule reads, attribute conditions, Redis I/O and audit fsync add work. Measure
  the actual deployment rather than assuming historical benchmark latency.
- Recursive traversals and SQL recursion limits constrain pathological role
  graphs. Registration of long chains is quadratic. Keep hierarchies shallow.
- Passing tests/scans are dated evidence, not universal workload guarantees.
  Fiber v3, Echo v5 and Gin v1 are the supported framework major lines.
