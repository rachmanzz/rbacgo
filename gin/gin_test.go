package ginadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rachmanzz/rbacgo"
)

func setup(t *testing.T) *rbacgo.Enforcer {
	t.Helper()
	gin.SetMode(gin.TestMode)
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

func do(t *testing.T, router *gin.Engine, userID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/articles", nil)
	if userID != "" {
		req.Header.Set("X-User-ID", userID)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestAllow(t *testing.T) {
	e := setup(t)
	r := gin.New()
	r.Use(Middleware(e))
	r.GET("/articles", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	if rec := do(t, r, "user-1"); rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestForbidden(t *testing.T) {
	e := setup(t)
	r := gin.New()
	r.Use(Middleware(e))
	r.GET("/articles", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	rec := do(t, r, "user-2")
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
	r := gin.New()
	r.Use(Middleware(e))
	r.GET("/articles", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	if rec := do(t, r, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
