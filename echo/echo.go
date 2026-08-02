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
// the request. Empty or missing IDs are treated as unauthenticated (401).
// Defaults to reading the X-User-ID header.
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
		userID: func(c *echo.Context) (string, bool) {
			id := c.Request().Header.Get("X-User-ID")
			return id, id != ""
		},
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
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
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
