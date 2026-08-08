package httpadapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/rachmanzz/rbacgo"
)

var errTest = errors.New("boom")

func tenantFactory(t *testing.T, perms func(string) []rbacgo.Permission) func(string) (*rbacgo.Enforcer, error) {
	t.Helper()
	return func(tenant string) (*rbacgo.Enforcer, error) {
		e, err := rbacgo.New(rbacgo.WithTenant(tenant), rbacgo.WithMemoryStore())
		if err != nil {
			return nil, err
		}
		ctx := context.Background()
		if err := e.RegisterRole(ctx, rbacgo.Role{Name: "viewer", Permissions: perms(tenant)}); err != nil {
			return nil, err
		}
		if err := e.AssignRole(ctx, "alice", "viewer"); err != nil {
			return nil, err
		}
		return e, nil
	}
}

func tenantMiddleware(t *testing.T, registry *TenantRegistry, opts ...TenantOption) func(http.Handler) http.Handler {
	t.Helper()
	all := []TenantOption{
		WithTenantResolver(func(r *http.Request) (string, bool) {
			t := r.Header.Get("X-Tenant-ID")
			return t, t != ""
		}),
		WithTenantUserID(func(r *http.Request) (string, bool) {
			if u := r.Header.Get("X-User-ID"); u != "" {
				return u, true
			}
			return "", false
		}),
	}
	all = append(all, opts...)
	return NewTenant(registry, all...)
}

func simpleTenantFactory() func(string) (*rbacgo.Enforcer, error) {
	return func(tenant string) (*rbacgo.Enforcer, error) {
		e, err := rbacgo.New(rbacgo.WithTenant(tenant), rbacgo.WithMemoryStore())
		if err != nil {
			return nil, err
		}
		ctx := context.Background()
		if err := e.RegisterRole(ctx, rbacgo.Role{Name: "viewer", Permissions: []rbacgo.Permission{{Resource: "/articles", Action: http.MethodGet}}}); err != nil {
			return nil, err
		}
		if err := e.AssignRole(ctx, "alice", "viewer"); err != nil {
			return nil, err
		}
		return e, nil
	}
}

func doTenantRequest(mw func(http.Handler) http.Handler, tenant, user, path string) *httptest.ResponseRecorder {
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tid, ok := TenantFromContext(r.Context())
		if !ok {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		enf, ok := EnforcerFromContext(r.Context())
		if !ok || enf == nil {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		if enf.TenantID() != tid {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	if user != "" {
		req.Header.Set("X-User-ID", user)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestTenantAllow(t *testing.T) {
	reg := NewTenantRegistry(tenantFactory(t, func(string) []rbacgo.Permission {
		return []rbacgo.Permission{{Resource: "/articles", Action: http.MethodGet}}
	}))
	rr := doTenantRequest(tenantMiddleware(t, reg), "org-a", "alice", "/articles")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestTenantUnauthorized(t *testing.T) {
	reg := NewTenantRegistry(tenantFactory(t, func(string) []rbacgo.Permission { return nil }))
	mw := tenantMiddleware(t, reg)
	if rr := doTenantRequest(mw, "", "alice", "/articles"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing tenant status = %d, want 401", rr.Code)
	}
	if rr := doTenantRequest(mw, "org-a", "", "/articles"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing user status = %d, want 401", rr.Code)
	}
}

func TestTenantForbidden(t *testing.T) {
	reg := NewTenantRegistry(tenantFactory(t, func(string) []rbacgo.Permission {
		return []rbacgo.Permission{{Resource: "/articles", Action: http.MethodGet}}
	}))
	if rr := doTenantRequest(tenantMiddleware(t, reg), "org-a", "alice", "/articles/1"); rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

func TestTenantEnforcerError(t *testing.T) {
	reg := NewTenantRegistry(func(string) (*rbacgo.Enforcer, error) {
		return nil, errTest
	})
	if rr := doTenantRequest(tenantMiddleware(t, reg), "org-a", "alice", "/articles"); rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestTenantIsolation(t *testing.T) {
	reg := NewTenantRegistry(tenantFactory(t, func(tenant string) []rbacgo.Permission {
		if tenant == "org-a" {
			return []rbacgo.Permission{{Resource: "/articles", Action: http.MethodGet}}
		}
		return []rbacgo.Permission{{Resource: "/reports", Action: http.MethodGet}}
	}))
	mw := tenantMiddleware(t, reg)
	if rr := doTenantRequest(mw, "org-a", "alice", "/articles"); rr.Code != http.StatusOK {
		t.Fatalf("org-a /articles = %d, want 200", rr.Code)
	}
	if rr := doTenantRequest(mw, "org-a", "alice", "/reports"); rr.Code != http.StatusForbidden {
		t.Fatalf("org-a /reports = %d, want 403 (tenant isolation)", rr.Code)
	}
	if rr := doTenantRequest(mw, "org-b", "alice", "/articles"); rr.Code != http.StatusForbidden {
		t.Fatalf("org-b /articles = %d, want 403 (tenant isolation)", rr.Code)
	}
	if rr := doTenantRequest(mw, "org-b", "alice", "/reports"); rr.Code != http.StatusOK {
		t.Fatalf("org-b /reports = %d, want 200", rr.Code)
	}
}

func TestTenantFactoryCached(t *testing.T) {
	var calls atomic.Int64
	reg := NewTenantRegistry(func(tenant string) (*rbacgo.Enforcer, error) {
		calls.Add(1)
		return simpleTenantFactory()(tenant)
	})
	mw := tenantMiddleware(t, reg)
	for i := 0; i < 3; i++ {
		if rr := doTenantRequest(mw, "org-a", "alice", "/articles"); rr.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, rr.Code)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("factory called %d times for one tenant, want 1", calls.Load())
	}
}

func TestTenantFactoryConcurrent(t *testing.T) {
	var calls atomic.Int64
	reg := NewTenantRegistry(func(tenant string) (*rbacgo.Enforcer, error) {
		calls.Add(1)
		return simpleTenantFactory()(tenant)
	})
	mw := tenantMiddleware(t, reg)
	const workers = 16
	done := make(chan int, workers)
	for w := 0; w < workers; w++ {
		go func() {
			rr := doTenantRequest(mw, "org-new", "alice", "/articles")
			done <- rr.Code
		}()
	}
	for w := 0; w < workers; w++ {
		if code := <-done; code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("factory called %d times under concurrency, want 1", calls.Load())
	}
}

func TestTenantRegistryClear(t *testing.T) {
	var calls atomic.Int64
	reg := NewTenantRegistry(func(tenant string) (*rbacgo.Enforcer, error) {
		calls.Add(1)
		return simpleTenantFactory()(tenant)
	})
	mw := tenantMiddleware(t, reg)
	if rr := doTenantRequest(mw, "org-a", "alice", "/articles"); rr.Code != http.StatusOK {
		t.Fatal("first request failed")
	}
	reg.Clear()
	if rr := doTenantRequest(mw, "org-a", "alice", "/articles"); rr.Code != http.StatusOK {
		t.Fatal("request after Clear failed")
	}
	if calls.Load() != 2 {
		t.Fatalf("factory called %d times, want 2 (one before and after Clear)", calls.Load())
	}
}

func TestTenantContextHelpersEmpty(t *testing.T) {
	ctx := context.Background()
	if _, ok := TenantFromContext(ctx); ok {
		t.Fatal("TenantFromContext on empty context must report false")
	}
	if _, ok := EnforcerFromContext(ctx); ok {
		t.Fatal("EnforcerFromContext on empty context must report false")
	}
}

func TestTenantPanics(t *testing.T) {
	reg := NewTenantRegistry(func(tenant string) (*rbacgo.Enforcer, error) {
		return rbacgo.New(rbacgo.WithTenant(tenant), rbacgo.WithMemoryStore())
	})
	if err := func() (err any) {
		defer func() { err = recover() }()
		NewTenantRegistry(nil)
		return nil
	}(); err == nil {
		t.Fatal("nil factory must panic")
	}
	if err := func() (err any) {
		defer func() { err = recover() }()
		NewTenant(nil)
		return nil
	}(); err == nil {
		t.Fatal("nil registry must panic")
	}
	if err := func() (err any) {
		defer func() { err = recover() }()
		NewTenant(reg, WithTenantUserID(func(*http.Request) (string, bool) { return "", true }))
		return nil
	}(); err == nil {
		t.Fatal("missing WithTenantResolver must panic")
	}
	if err := func() (err any) {
		defer func() { err = recover() }()
		NewTenant(reg, WithTenantResolver(func(*http.Request) (string, bool) { return "", false }))
		return nil
	}(); err == nil {
		t.Fatal("missing WithUserID must panic")
	}
}
