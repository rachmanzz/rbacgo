package fiberadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/rachmanzz/rbacgo"
)

func setup(t *testing.T) *rbacgo.Enforcer {
	t.Helper()
	e, err := rbacgo.New(rbacgo.WithMemoryStore())
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
		req.Header.Set("X-User-ID", userID)
	}
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAllow(t *testing.T) {
	e := setup(t)
	app := fiber.New()
	app.Use(Middleware(e))
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
	app.Use(Middleware(e))
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
	app.Use(Middleware(e))
	app.Get("/articles", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})
	if resp := do(t, app, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
