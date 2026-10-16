package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rachmanzz/rbacgo"
)

func TestTenantMiddlewareHoldsLeaseUntilHandlerReturns(t *testing.T) {
	ctx := context.Background()
	reg := NewTenantRegistry(tenantFactory(t, func(string) []rbacgo.Permission {
		return []rbacgo.Permission{{Resource: "/articles", Action: "GET"}}
	}))
	defer reg.Shutdown(ctx)
	started, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(resume) }) }
	defer unblock()
	handler := tenantMiddleware(t, reg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-resume
		e, _ := EnforcerFromContext(r.Context())
		if !e.Enforce(r.Context(), "alice", "/articles", "GET") {
			t.Error("active request lost its Enforcer during shutdown")
		}
		w.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodGet, "/articles", nil)
	request.Header.Set("X-Tenant-ID", "a")
	request.Header.Set("X-User-ID", "alice")
	recorder := httptest.NewRecorder()
	go func() { handler.ServeHTTP(recorder, request); close(done) }()
	<-started
	deadline, cancel := context.WithTimeout(ctx, time.Millisecond)
	defer cancel()
	if err := reg.Shutdown(deadline); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown did not wait for middleware: %v", err)
	}
	unblock()
	<-done
	mustClose := reg.Shutdown(ctx)
	if mustClose != nil || recorder.Code != http.StatusOK {
		t.Fatalf("drain failed: %v, %d", mustClose, recorder.Code)
	}
}
