// Package fiberadapter provides an RBAC middleware for Fiber v3.
package fiberadapter

import (
	"github.com/gofiber/fiber/v3"
	"github.com/rachmanzz/rbacgo"
)

// Options configures the middleware.
type Options struct {
	userID         func(fiber.Ctx) (string, bool)
	resourceAction func(fiber.Ctx) (string, string)
	unauthorized   func(fiber.Ctx) error
	denied         func(fiber.Ctx) error
}

// Option mutates Options.
type Option func(*Options)

// WithUserID sets the function that extracts an authenticated subject ID from
// the request. Empty or missing IDs are treated as unauthenticated (401).
// Defaults to reading the X-User-ID header.
func WithUserID(fn func(fiber.Ctx) (string, bool)) Option {
	return func(o *Options) { o.userID = fn }
}

// WithResourceAction sets the function that derives (resource, action) from
// the request. Defaults to (path, method).
func WithResourceAction(fn func(fiber.Ctx) (string, string)) Option {
	return func(o *Options) { o.resourceAction = fn }
}

// WithUnauthorizedHandler overrides the default 401 handler.
func WithUnauthorizedHandler(fn func(fiber.Ctx) error) Option {
	return func(o *Options) { o.unauthorized = fn }
}

// WithDeniedHandler overrides the default 403 handler.
func WithDeniedHandler(fn func(fiber.Ctx) error) Option {
	return func(o *Options) { o.denied = fn }
}

func defaultOptions() Options {
	return Options{
		userID: func(c fiber.Ctx) (string, bool) {
			id := c.Get("X-User-ID")
			return id, id != ""
		},
		resourceAction: func(c fiber.Ctx) (string, string) {
			return c.Path(), c.Method()
		},
		unauthorized: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
		},
		denied: func(c fiber.Ctx) error {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
		},
	}
}

// Middleware builds a Fiber handler. Register it with:
//
//	app.Use(fiberadapter.Middleware(enforcer, fiberadapter.WithUserID(...)))
func Middleware(enforcer *rbacgo.Enforcer, opts ...Option) fiber.Handler {
	if enforcer == nil {
		panic("rbacgo: nil enforcer")
	}
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return func(c fiber.Ctx) error {
		userID, ok := o.userID(c)
		if !ok || userID == "" {
			return o.unauthorized(c)
		}
		resource, action := o.resourceAction(c)
		if !enforcer.Enforce(c.Context(), userID, resource, action) {
			return o.denied(c)
		}
		return c.Next()
	}
}
