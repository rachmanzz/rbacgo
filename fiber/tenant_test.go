package fiberadapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gofiber/fiber/v3"
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

func tenantMiddleware(registry *TenantRegistry, opts ...TenantOption) fiber.Handler {
	all := []TenantOption{
		WithTenantResolver(func(c fiber.Ctx) (string, bool) {
			t := c.Get("X-Tenant-ID")
			return t, t != ""
		}),
		WithTenantUserID(func(c fiber.Ctx) (string, bool) {
			id := c.Get("X-User-ID")
			return id, id != ""
		}),
	}
	all = append(all, opts...)
	return TenantMiddleware(registry, all...)
}

func doTenantRequest(mw fiber.Handler, tenant, user string) *http.Response {
	app := fiber.New()
	app.Use(mw)
	app.Get("/articles", func(c fiber.Ctx) error {
		tid, ok := TenantFromContext(c.Context())
		if !ok {
			return c.SendStatus(fiber.StatusTeapot)
		}
		enf, ok := EnforcerFromContext(c.Context())
		if !ok || enf == nil {
			return c.SendStatus(fiber.StatusTeapot)
		}
		if enf.TenantID() != tid {
			return c.SendStatus(fiber.StatusTeapot)
		}
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/articles", nil)
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	if user != "" {
		req.Header.Set("X-User-ID", user)
	}
	resp, err := app.Test(req)
	if err != nil {
		panic(err)
	}
	return resp
}

func TestTenantAllow(t *testing.T) {
	reg := NewTenantRegistry(simpleTenantFactory())
	if resp := doTenantRequest(tenantMiddleware(reg), "org-a", "alice"); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestTenantUnauthorized(t *testing.T) {
	reg := NewTenantRegistry(simpleTenantFactory())
	mw := tenantMiddleware(reg)
	if resp := doTenantRequest(mw, "", "alice"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing tenant status = %d, want 401", resp.StatusCode)
	}
	if resp := doTenantRequest(mw, "org-a", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing user status = %d, want 401", resp.StatusCode)
	}
}

func TestTenantForbidden(t *testing.T) {
	reg := NewTenantRegistry(tenantFactory(func(string) []rbacgo.Permission {
		return []rbacgo.Permission{{Resource: "/reports", Action: http.MethodGet}}
	}))
	if resp := doTenantRequest(tenantMiddleware(reg), "org-a", "alice"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestTenantEnforcerError(t *testing.T) {
	reg := NewTenantRegistry(func(string) (*rbacgo.Enforcer, error) {
		return nil, errTest
	})
	if resp := doTenantRequest(tenantMiddleware(reg), "org-a", "alice"); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
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
	if resp := doTenantRequest(mw, "org-a", "alice"); resp.StatusCode != http.StatusOK {
		t.Fatalf("org-a /articles = %d, want 200", resp.StatusCode)
	}
	if resp := doTenantRequest(mw, "org-b", "alice"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("org-b /articles = %d, want 403 (tenant isolation)", resp.StatusCode)
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
		if resp := doTenantRequest(mw, "org-a", "alice"); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i, resp.StatusCode)
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
			done <- doTenantRequest(mw, "org-new", "alice").StatusCode
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
	if resp := doTenantRequest(mw, "org-a", "alice"); resp.StatusCode != http.StatusOK {
		t.Fatal("first request failed")
	}
	reg.Clear()
	if resp := doTenantRequest(mw, "org-a", "alice"); resp.StatusCode != http.StatusOK {
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
		TenantMiddleware(reg, WithTenantUserID(func(fiber.Ctx) (string, bool) { return "", true }))
		return nil
	}(); err == nil {
		t.Fatal("missing WithTenantResolver must panic")
	}
	if err := func() (err any) {
		defer func() { err = recover() }()
		TenantMiddleware(reg, WithTenantResolver(func(fiber.Ctx) (string, bool) { return "", false }))
		return nil
	}(); err == nil {
		t.Fatal("missing WithTenantUserID must panic")
	}
}
