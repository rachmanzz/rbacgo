package echoadapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/rachmanzz/rbacgo"
)

var errTest = errors.New("boom")

func tenantFactory(perms func(string) []rbacgo.Permission) func(string) (*rbacgo.Enforcer, error) {
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

func simpleTenantFactory() func(string) (*rbacgo.Enforcer, error) {
	return tenantFactory(func(string) []rbacgo.Permission {
		return []rbacgo.Permission{{Resource: "/articles", Action: http.MethodGet}}
	})
}

func tenantMiddleware(registry *TenantRegistry, opts ...TenantOption) echo.MiddlewareFunc {
	all := []TenantOption{
		WithTenantResolver(func(c *echo.Context) (string, bool) {
			t := c.Request().Header.Get("X-Tenant-ID")
			return t, t != ""
		}),
		WithTenantUserID(func(c *echo.Context) (string, bool) {
			id := c.Request().Header.Get("X-User-ID")
			return id, id != ""
		}),
	}
	all = append(all, opts...)
	return TenantMiddleware(registry, all...)
}

func doTenantRequest(mw echo.MiddlewareFunc, tenant, user string) *httptest.ResponseRecorder {
	app := echo.New()
	app.Use(mw)
	app.GET("/articles", func(c *echo.Context) error {
		tid, ok := TenantFromContext(c.Request().Context())
		if !ok {
			return c.JSON(http.StatusTeapot, nil)
		}
		enf, ok := EnforcerFromContext(c.Request().Context())
		if !ok || enf == nil {
			return c.JSON(http.StatusTeapot, nil)
		}
		if enf.TenantID() != tid {
			return c.JSON(http.StatusTeapot, nil)
		}
		return c.JSON(http.StatusOK, nil)
	})
	req := httptest.NewRequest(http.MethodGet, "/articles", nil)
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	if user != "" {
		req.Header.Set("X-User-ID", user)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestTenantAllow(t *testing.T) {
	reg := NewTenantRegistry(simpleTenantFactory())
	if rr := doTenantRequest(tenantMiddleware(reg), "org-a", "alice"); rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
}

func TestTenantUnauthorized(t *testing.T) {
	reg := NewTenantRegistry(simpleTenantFactory())
	mw := tenantMiddleware(reg)
	if rr := doTenantRequest(mw, "", "alice"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing tenant status = %d, want 401", rr.Code)
	}
	if rr := doTenantRequest(mw, "org-a", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing user status = %d, want 401", rr.Code)
	}
}

func TestTenantForbidden(t *testing.T) {
	reg := NewTenantRegistry(tenantFactory(func(string) []rbacgo.Permission {
		return []rbacgo.Permission{{Resource: "/reports", Action: http.MethodGet}}
	}))
	if rr := doTenantRequest(tenantMiddleware(reg), "org-a", "alice"); rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
}

func TestTenantEnforcerError(t *testing.T) {
	reg := NewTenantRegistry(func(string) (*rbacgo.Enforcer, error) {
		return nil, errTest
	})
	if rr := doTenantRequest(tenantMiddleware(reg), "org-a", "alice"); rr.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rr.Code)
	}
}

func TestTenantIsolation(t *testing.T) {
	reg := NewTenantRegistry(tenantFactory(func(tenant string) []rbacgo.Permission {
		if tenant == "org-a" {
			return []rbacgo.Permission{{Resource: "/articles", Action: http.MethodGet}}
		}
		return []rbacgo.Permission{{Resource: "/reports", Action: http.MethodGet}}
	}))
	mw := tenantMiddleware(reg)
	if rr := doTenantRequest(mw, "org-a", "alice"); rr.Code != http.StatusOK {
		t.Fatalf("org-a /articles = %d, want 200", rr.Code)
	}
	if rr := doTenantRequest(mw, "org-b", "alice"); rr.Code != http.StatusForbidden {
		t.Fatalf("org-b /articles = %d, want 403 (tenant isolation)", rr.Code)
	}
}

func TestTenantFactoryCached(t *testing.T) {
	var calls atomic.Int64
	reg := NewTenantRegistry(func(tenant string) (*rbacgo.Enforcer, error) {
		calls.Add(1)
		return simpleTenantFactory()(tenant)
	})
	mw := tenantMiddleware(reg)
	for i := 0; i < 3; i++ {
		if rr := doTenantRequest(mw, "org-a", "alice"); rr.Code != http.StatusOK {
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
	mw := tenantMiddleware(reg)
	const workers = 16
	done := make(chan int, workers)
	for w := 0; w < workers; w++ {
		go func() {
			done <- doTenantRequest(mw, "org-new", "alice").Code
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
	mw := tenantMiddleware(reg)
	if rr := doTenantRequest(mw, "org-a", "alice"); rr.Code != http.StatusOK {
		t.Fatal("first request failed")
	}
	reg.Clear()
	if rr := doTenantRequest(mw, "org-a", "alice"); rr.Code != http.StatusOK {
		t.Fatal("request after Clear failed")
	}
	if calls.Load() != 2 {
		t.Fatalf("factory called %d times, want 2 (one before and after Clear)", calls.Load())
	}
}

func TestTenantContextHelpersEmpty(t *testing.T) {
	if _, ok := TenantFromContext(context.Background()); ok {
		t.Fatal("TenantFromContext on empty context must report false")
	}
	if _, ok := EnforcerFromContext(context.Background()); ok {
		t.Fatal("EnforcerFromContext on empty context must report false")
	}
}

func TestTenantPanics(t *testing.T) {
	reg := NewTenantRegistry(simpleTenantFactory())
	if err := func() (err any) {
		defer func() { err = recover() }()
		NewTenantRegistry(nil)
		return nil
	}(); err == nil {
		t.Fatal("nil factory must panic")
	}
	if err := func() (err any) {
		defer func() { err = recover() }()
		TenantMiddleware(nil)
		return nil
	}(); err == nil {
		t.Fatal("nil registry must panic")
	}
	if err := func() (err any) {
		defer func() { err = recover() }()
		TenantMiddleware(reg, WithTenantUserID(func(*echo.Context) (string, bool) { return "", true }))
		return nil
	}(); err == nil {
		t.Fatal("missing WithTenantResolver must panic")
	}
	if err := func() (err any) {
		defer func() { err = recover() }()
		TenantMiddleware(reg, WithTenantResolver(func(*echo.Context) (string, bool) { return "", false }))
		return nil
	}(); err == nil {
		t.Fatal("missing WithTenantUserID must panic")
	}
}
