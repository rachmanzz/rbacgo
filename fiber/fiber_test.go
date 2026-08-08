package fiberadapter

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/rachmanzz/rbacgo"
)

func setup(t *testing.T) *rbacgo.Enforcer {
	t.Helper()
	e, err := rbacgo.New(rbacgo.WithTenant("test"), rbacgo.WithMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.RegisterRoles(t.Context(),
		rbacgo.Role{Name: "viewer", Permissions: []rbacgo.Permission{{Resource: "/articles", Action: "GET"}}},
	); err != nil {
		t.Fatal(err)
	}
	if err := e.AssignRole(t.Context(), "user-1", "viewer"); err != nil {
		t.Fatal(err)
	}
	return e
}

func do(t *testing.T, app *fiber.App, userID string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/articles", nil)
	if userID != "" {
		req.Header.Set("X-Test-User", userID)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// testMiddleware builds the RBAC middleware with a test extractor that reads
// the X-Test-User header — the real app provides its own WithUserID.
func testMiddleware(e *rbacgo.Enforcer, opts ...Option) fiber.Handler {
	return Middleware(e, append([]Option{
		WithUserID(func(c fiber.Ctx) (string, bool) {
			id := c.Get("X-Test-User")
			return id, id != ""
		}),
	}, opts...)...)
}

func TestAllow(t *testing.T) {
	e := setup(t)
	app := fiber.New()
	app.Use(testMiddleware(e))
	app.Get("/articles", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	if resp := do(t, app, "user-1"); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestForbidden(t *testing.T) {
	e := setup(t)
	app := fiber.New()
	app.Use(testMiddleware(e))
	app.Get("/articles", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	resp := do(t, app, "user-2")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "forbidden" {
		t.Fatalf("body = %v", body)
	}
}

func TestUnauthorized(t *testing.T) {
	e := setup(t)
	app := fiber.New()
	app.Use(testMiddleware(e))
	app.Get("/articles", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	if resp := do(t, app, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestCustomDenied(t *testing.T) {
	e := setup(t)
	app := fiber.New()
	app.Use(testMiddleware(e, WithDeniedHandler(func(c fiber.Ctx) error {
		return c.Status(fiber.StatusForbidden).SendString("custom-denied")
	})))
	app.Get("/articles", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	resp := do(t, app, "user-2")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "custom-denied" {
		t.Fatalf("body = %q, want custom-denied", body)
	}
}

func TestCustomUnauthorized(t *testing.T) {
	e := setup(t)
	app := fiber.New()
	app.Use(testMiddleware(e, WithUnauthorizedHandler(func(c fiber.Ctx) error {
		return c.Status(fiber.StatusUnauthorized).SendString("custom-unauthorized")
	})))
	app.Get("/articles", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	resp := do(t, app, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "custom-unauthorized" {
		t.Fatalf("body = %q, want custom-unauthorized", body)
	}
}

func TestCustomExtractors(t *testing.T) {
	e := setup(t)
	app := fiber.New()
	app.Use(Middleware(e,
		WithUserID(func(c fiber.Ctx) (string, bool) {
			id := c.Get("Authorization")
			return id, id != ""
		}),
		WithResourceAction(func(c fiber.Ctx) (string, string) {
			return c.Path(), "GET"
		}),
	))
	app.Get("/articles", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/articles", nil)
	req.Header.Set("Authorization", "user-1")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestMissingUserIDPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for missing WithUserID")
		}
	}()
	Middleware(setup(t))
}

func TestNilEnforcerPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil enforcer")
		}
	}()
	Middleware(nil)
}
