package rbacgo

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics has no external exporter dependency. Share it across Enforcers to
// aggregate a process, or use one per tenant. Snapshot may be JSON-encoded or
// adapted to an existing metrics exporter. Counters use atomic operations.
type Metrics struct {
	decisions           atomic.Uint64
	allowed             atomic.Uint64
	denied              atomic.Uint64
	errors              atomic.Uint64
	cacheHits           atomic.Uint64
	cacheMisses         atomic.Uint64
	mutations           atomic.Uint64
	auditErrors         atomic.Uint64
	invalidationErrors  atomic.Uint64
	policyVersionErrors atomic.Uint64
	decisionNanoseconds atomic.Uint64
}

type MetricsSnapshot struct {
	Decisions           uint64
	Allowed             uint64
	Denied              uint64
	Errors              uint64
	CacheHits           uint64
	CacheMisses         uint64
	Mutations           uint64
	AuditErrors         uint64
	InvalidationErrors  uint64
	PolicyVersionErrors uint64
	DecisionNanoseconds uint64
}

// Snapshot loads each counter atomically, not as one global transaction.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{m.decisions.Load(), m.allowed.Load(), m.denied.Load(), m.errors.Load(),
		m.cacheHits.Load(), m.cacheMisses.Load(), m.mutations.Load(), m.auditErrors.Load(),
		m.invalidationErrors.Load(), m.policyVersionErrors.Load(), m.decisionNanoseconds.Load()}
}

func WithMetrics(metrics *Metrics) Option {
	return func(e *Enforcer) error {
		if metrics == nil {
			return fmt.Errorf("rbacgo: nil metrics")
		}
		e.metrics = metrics
		return nil
	}
}

// AuditEvent describes a decision or successful policy mutation. Attribute
// payloads and permission contents are deliberately omitted. Errors may contain
// backend details; apply appropriate access/retention controls to the sink.
type AuditEvent struct {
	ID           string
	Time         time.Time
	Tenant       string
	Operation    string
	ActorID      string
	TargetUserID string
	RoleName     string
	Resource     string
	Action       string
	Allowed      bool
	Error        string
}

// AuditSink must support concurrent calls and durably acknowledge events before
// returning nil. The caller owns its lifecycle and retention policy.
type AuditSink interface {
	Emit(context.Context, AuditEvent) error
}

func WithAuditSink(sink AuditSink) Option {
	return func(e *Enforcer) error {
		if sink == nil {
			return fmt.Errorf("rbacgo: nil audit sink")
		}
		e.audit = sink
		return nil
	}
}

// AuditWriteError distinguishes an already-committed policy change from an
// authorization decision denied because its audit event could not be persisted.
// Do not blindly retry a mutation when Committed is true.
type AuditWriteError struct {
	Committed bool
	Cause     error
}

func (e *AuditWriteError) Error() string {
	return fmt.Sprintf("rbacgo: audit write failed (mutation committed=%t): %v", e.Committed, e.Cause)
}
func (e *AuditWriteError) Unwrap() error { return e.Cause }

// FileAuditSink appends one JSON event per line and fsyncs every event. Use a
// single instance/writer for a file on a local filesystem. No rotation, tamper
// resistance, or cross-host locking is implied. Existing incomplete JSONL tails
// are rejected instead of silently deleting evidence.
type FileAuditSink struct {
	mu     sync.Mutex
	file   *os.File
	failed error
}

func NewFileAuditSink(path string) (*FileAuditSink, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("rbacgo: audit sink must be a regular file")
	}
	if err == nil && info.Size() > 0 {
		var tail [1]byte
		_, err = file.ReadAt(tail[:], info.Size()-1)
		if err == nil && tail[0] != '\n' {
			err = errors.New("rbacgo: incomplete audit file tail; repair explicitly before appending")
		}
	}
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &FileAuditSink{file: file}, nil
}

func (s *FileAuditSink) Emit(ctx context.Context, event AuditEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return os.ErrClosed
	}
	if s.failed != nil {
		return s.failed
	}
	if n, err := s.file.Write(raw); err != nil {
		s.failed = err
		return err
	} else if n != len(raw) {
		s.failed = io.ErrShortWrite
		return s.failed
	}
	s.failed = s.file.Sync()
	return s.failed
}

func (s *FileAuditSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

func (e *Enforcer) emitAudit(ctx context.Context, event AuditEvent) error {
	if e.audit == nil {
		return nil
	}
	event.ID, event.Time, event.Tenant = rand.Text(), time.Now().UTC(), e.tenant
	if err := e.audit.Emit(ctx, event); err != nil {
		if e.metrics != nil {
			e.metrics.auditErrors.Add(1)
		}
		e.logError(ctx, "audit persistence failed", err)
		return err
	}
	return nil
}

type auditActorContextKey struct{}

func withAuditActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, auditActorContextKey{}, actor)
}

func (e *Enforcer) recordMutation(ctx context.Context, operation, actorID, targetUserID, roleName string) error {
	if e.metrics != nil {
		e.metrics.mutations.Add(1)
	}
	if actorID == "" {
		actorID, _ = ctx.Value(auditActorContextKey{}).(string)
	}
	if err := e.emitAudit(ctx, AuditEvent{Operation: operation, ActorID: actorID, TargetUserID: targetUserID, RoleName: roleName}); err != nil {
		return &AuditWriteError{Committed: true, Cause: err}
	}
	return nil
}

func (e *Enforcer) decisionStarted() time.Time {
	if e.metrics == nil {
		return time.Time{}
	}
	return time.Now()
}

func (e *Enforcer) recordDecision(ctx context.Context, started time.Time, operation, userID, resource, action string, allowed *bool, err *error) {
	event := AuditEvent{Operation: operation, ActorID: userID, Resource: resource, Action: action, Allowed: *allowed && *err == nil}
	if *err != nil {
		event.Error = (*err).Error()
	}
	if auditErr := e.emitAudit(ctx, event); auditErr != nil {
		*allowed = false
		*err = errors.Join(*err, &AuditWriteError{Cause: auditErr})
	}
	if m := e.metrics; m != nil {
		m.decisions.Add(1)
		m.decisionNanoseconds.Add(uint64(time.Since(started)))
		if *err != nil {
			m.errors.Add(1)
		}
		if *allowed && *err == nil {
			m.allowed.Add(1)
		} else {
			m.denied.Add(1)
		}
	}
}
