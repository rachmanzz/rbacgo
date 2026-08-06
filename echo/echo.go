// Package echoadapter provides an RBAC middleware for Echo v5.
package echoadapter

import (
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/rachmanzz/rbacgo"
)

// Options configures the middleware.
type Options struct {
	userID         func(*echo.Context) (string, bool)
	resourceAction func(*echo.Context) (string, string)
	unauthorized   func(*echo.Context) error
	denied         func(*echo.Context) error
}

// Option mutates Options.
type Option func(*Options)

// WithUserID sets the function that extracts an authenticated subject ID from
// the request (e.g. from your session, JWT claims, or auth middleware context).
// Empty or missing IDs are treated as unauthenticated (401). This option is
// REQUIRED: user identity comes from your application's auth, not from raw
// HTTP headers, so Middleware panics if it is not set.
func WithUserID(fn func(*echo.Context) (string, bool)) Option {
	return func(o *Options) { o.userID = fn }
}

// WithResourceAction sets the function that derives (resource, action) from
// the request. Defaults to (URL path, HTTP method).
func WithResourceAction(fn func(*echo.Context) (string, string)) Option {
	return func(o *Options) { o.resourceAction = fn }
}

// WithUnauthorizedHandler overrides the default 401 handler.
func WithUnauthorizedHandler(fn func(*echo.Context) error) Option {
	return func(o *Options) { o.unauthorized = fn }
}

// WithDeniedHandler overrides the default 403 handler.
func WithDeniedHandler(fn func(*echo.Context) error) Option {
	return func(o *Options) { o.denied = fn }
}

func defaultOptions() Options {
	return Options{
		resourceAction: func(c *echo.Context) (string, string) {
			r := c.Request()
			return r.URL.Path, r.Method
		},
		unauthorized: func(c *echo.Context) error {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		},
		denied: func(c *echo.Context) error {
			return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden"})
		},
	}
}

// Middleware builds an Echo middleware. Register it with:
//
//	e.Use(echoadapter.Middleware(enforcer, echoadapter.WithUserID(...)))
func Middleware(enforcer *rbacgo.Enforcer, opts ...Option) echo.MiddlewareFunc {
	if enforcer == nil {
		panic("rbacgo: nil enforcer")
	}
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	if o.userID == nil {
		panic("rbacgo: WithUserID is required (user identity comes from your auth middleware, not HTTP headers)")
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			userID, ok := o.userID(c)
			if !ok || userID == "" {
				return o.unauthorized(c)
			}
			resource, action := o.resourceAction(c)
			if !enforcer.Enforce(c.Request().Context(), userID, resource, action) {
				return o.denied(c)
			}
			return next(c)
		}
	}
}
