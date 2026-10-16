package rbacgo

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

type loggingInvalidator struct{}

func (loggingInvalidator) Publish(context.Context, InvalidationEvent) error { return errTest }
func (loggingInvalidator) Messages() <-chan InvalidationEvent               { return nil }
func (loggingInvalidator) Close() error                                     { return nil }

func TestLoggerBestEffortFailures(t *testing.T) {
	ctx := context.Background()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	e := mustEnforcer(t, WithMemoryStore(), WithLogger(logger), WithCacheInvalidator(loggingInvalidator{}), WithPolicyVersionStore(errPolicyVersion{}))
	t.Cleanup(func() { _ = e.Close() })
	if err := e.RegisterRole(ctx, Role{Name: "reader"}); err != nil {
		t.Fatalf("bookkeeping must not fail mutation: %v", err)
	}
	if err := e.AssignRole(ctx, "user", "reader"); err != nil {
		t.Fatal(err)
	}
	view, err := e.PermissionView(ctx, "user")
	if err != nil || view.PolicyVersion != 2 {
		t.Fatalf("fallback version = %d, %v", view.PolicyVersion, err)
	}
	output := buf.String()
	for _, want := range []string{"policy version increment failed", "policy version read failed", "cache invalidation publish failed", `"tenant":"t"`, `"error":"boom"`} {
		if !strings.Contains(output, want) {
			t.Fatalf("missing %q in logs: %s", want, output)
		}
	}
	// Logger configuration must not change fail-closed permission decisions.
	failed := mustEnforcer(t, WithStore(failGetRolesStore{Store: NewMemoryStore()}), WithLogger(logger))
	if failed.Enforce(ctx, "user", "articles", "read") {
		t.Fatal("lookup error granted access")
	}
	if _, err := failed.EnforceOwnedCtx(ctx, "user", "user", "hr", "articles", "read"); err == nil {
		t.Fatal("owned lookup error was hidden")
	}
	if !strings.Contains(buf.String(), "permission lookup failed") {
		t.Fatal("missing lookup failure log")
	}
}

func TestWithLoggerRejectsNil(t *testing.T) {
	if _, err := New(WithTenant("t"), WithLogger(nil)); err == nil {
		t.Fatal("nil logger must be rejected")
	}
}
