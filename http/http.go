// Package httpadapter provides an RBAC middleware for the standard library
// net/http. Because Chi is built on net/http, Chi users can use this package
// directly.
package httpadapter

import (
	"encoding/json"
	"net/http"

	"github.com/rachmanzz/rbacgo"
)

// Options configures the middleware.
type Options struct {
	userID         func(*http.Request) (string, bool)
	resourceAction func(*http.Request) (string, string)
	unauthorized   func(http.ResponseWriter, *http.Request)
	denied         func(http.ResponseWriter, *http.Request)
}

// Option mutates Options.
type Option func(*Options)

// WithUserID sets the function that extracts an authenticated subject ID from
// the request. If it reports false or returns an empty ID, the request is
// treated as unauthenticated (401). Defaults to reading the X-User-ID header.
func WithUserID(fn func(*http.Request) (string, bool)) Option {
	return func(o *Options) { o.userID = fn }
}

// WithResourceAction sets the function that derives (resource, action) from
// the request. Defaults to (URL path, HTTP method).
func WithResourceAction(fn func(*http.Request) (string, string)) Option {
	return func(o *Options) { o.resourceAction = fn }
}

// WithUnauthorizedHandler overrides the default 401 handler.
func WithUnauthorizedHandler(h func(http.ResponseWriter, *http.Request)) Option {
	return func(o *Options) { o.unauthorized = h }
}

// WithDeniedHandler overrides the default 403 handler.
func WithDeniedHandler(h func(http.ResponseWriter, *http.Request)) Option {
	return func(o *Options) { o.denied = h }
}

func defaultOptions() Options {
	return Options{
		userID: func(r *http.Request) (string, bool) {
			id := r.Header.Get("X-User-ID")
			return id, id != ""
		},
		resourceAction: func(r *http.Request) (string, string) {
			return r.URL.Path, r.Method
		},
		unauthorized: writeJSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"}),
		denied:       writeJSON(http.StatusForbidden, map[string]string{"error": "forbidden"}),
	}
}

func writeJSON(status int, body any) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
}

// New builds a net/http middleware. Wrap any http.Handler with it:
//
//	handler := httpadapter.New(enforcer, httpadapter.WithUserID(...))
//	http.Handle("/articles", handler(http.HandlerFunc(listArticles)))
func New(enforcer *rbacgo.Enforcer, opts ...Option) func(http.Handler) http.Handler {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := o.userID(r)
			if !ok || userID == "" {
				o.unauthorized(w, r)
				return
			}
			resource, action := o.resourceAction(r)
			if !enforcer.Enforce(r.Context(), userID, resource, action) {
				o.denied(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
