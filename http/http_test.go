package httpadapter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

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

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func do(t *testing.T, h http.Handler, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/articles", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAllow(t *testing.T) {
	e := setup(t)
	h := New(e)(okHandler())
	rec := do(t, h, map[string]string{"X-User-ID": "user-1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestForbidden(t *testing.T) {
	e := setup(t)
	h := New(e)(okHandler())
	// user-2 has no role.
	rec := do(t, h, map[string]string{"X-User-ID": "user-2"})
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
	h := New(e)(okHandler())
	rec := do(t, h, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestCustomHandlers(t *testing.T) {
	e := setup(t)
	denied := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Denied", "yes")
		w.WriteHeader(http.StatusForbidden)
	}
	h := New(e, WithDeniedHandler(denied))(okHandler())
	rec := do(t, h, map[string]string{"X-User-ID": "user-2"})
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-Denied") != "yes" {
		t.Fatalf("custom denied handler not used: %d %q", rec.Code, rec.Header().Get("X-Denied"))
	}
}

func TestCustomExtractors(t *testing.T) {
	e := setup(t)
	h := New(e,
		WithUserID(func(r *http.Request) (string, bool) {
			id := r.Header.Get("Authorization")
			return id, id != ""
		}),
		WithResourceAction(func(r *http.Request) (string, string) {
			return r.URL.Path, "GET"
		}),
	)(okHandler())
	rec := do(t, h, map[string]string{"Authorization": "user-1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestCustomUnauthorized(t *testing.T) {
	e := setup(t)
	unauthorized := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Unauthorized", "yes")
		w.WriteHeader(http.StatusUnauthorized)
	}
	h := New(e, WithUnauthorizedHandler(unauthorized))(okHandler())
	rec := do(t, h, nil)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("X-Unauthorized") != "yes" {
		t.Fatalf("custom unauthorized handler not used: %d %q", rec.Code, rec.Header().Get("X-Unauthorized"))
	}
}
