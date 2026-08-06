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
		req.Header.Set("X-Test-User", userID)
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

// testMiddleware builds the RBAC middleware with a test extractor that reads
// the X-Test-User header — the real app provides its own WithUserID.
func testMiddleware(e *rbacgo.Enforcer, opts ...Option) echo.MiddlewareFunc {
	return Middleware(e, append([]Option{
		WithUserID(func(c *echo.Context) (string, bool) {
			id := c.Request().Header.Get("X-Test-User")
			return id, id != ""
		}),
	}, opts...)...)
}

func TestAllow(t *testing.T) {
	e := setup(t)
	app := echo.New()
	app.Use(testMiddleware(e))
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
	app.Use(testMiddleware(e))
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
	app.Use(testMiddleware(e))
	app.GET("/articles", func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	if rec := do(t, app, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestCustomDenied(t *testing.T) {
	e := setup(t)
	app := echo.New()
	app.Use(testMiddleware(e, WithDeniedHandler(func(c *echo.Context) error {
		return c.String(http.StatusForbidden, "custom-denied")
	})))
	app.GET("/articles", func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	rec := do(t, app, "user-2")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if rec.Body.String() != "custom-denied" {
		t.Fatalf("body = %q, want custom-denied", rec.Body.String())
	}
}

func TestCustomUnauthorized(t *testing.T) {
	e := setup(t)
	app := echo.New()
	app.Use(testMiddleware(e, WithUnauthorizedHandler(func(c *echo.Context) error {
		return c.String(http.StatusUnauthorized, "custom-unauthorized")
	})))
	app.GET("/articles", func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	rec := do(t, app, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Body.String() != "custom-unauthorized" {
		t.Fatalf("body = %q, want custom-unauthorized", rec.Body.String())
	}
}

func TestCustomExtractors(t *testing.T) {
	e := setup(t)
	app := echo.New()
	app.Use(Middleware(e,
		WithUserID(func(c *echo.Context) (string, bool) {
			id := c.Request().Header.Get("Authorization")
			return id, id != ""
		}),
		WithResourceAction(func(c *echo.Context) (string, string) {
			r := c.Request()
			return r.URL.Path, "GET"
		}),
	))
	app.GET("/articles", func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	req := httptest.NewRequest(http.MethodGet, "/articles", nil)
	req.Header.Set("Authorization", "user-1")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
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
