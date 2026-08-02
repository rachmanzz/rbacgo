package echoadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
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

func do(t *testing.T, app *echo.Echo, userID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/articles", nil)
	if userID != "" {
		req.Header.Set("X-User-ID", userID)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestAllow(t *testing.T) {
	e := setup(t)
	app := echo.New()
	app.Use(Middleware(e))
	app.GET("/articles", func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	if rec := do(t, app, "user-1"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestForbidden(t *testing.T) {
	e := setup(t)
	app := echo.New()
	app.Use(Middleware(e))
	app.GET("/articles", func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	rec := do(t, app, "user-2")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "forbidden" {
		t.Fatalf("body = %v", body)
	}
}

func TestUnauthorized(t *testing.T) {
	e := setup(t)
	app := echo.New()
	app.Use(Middleware(e))
	app.GET("/articles", func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	if rec := do(t, app, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
