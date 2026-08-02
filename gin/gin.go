// Package ginadapter provides an RBAC middleware for Gin.
package ginadapter

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rachmanzz/rbacgo"
)

// Options configures the middleware.
type Options struct {
	userID         func(*gin.Context) (string, bool)
	resourceAction func(*gin.Context) (string, string)
	unauthorized   func(*gin.Context)
	denied         func(*gin.Context)
}

// Option mutates Options.
type Option func(*Options)

// WithUserID sets the function that extracts an authenticated subject ID from
// the request. Empty or missing IDs are treated as unauthenticated (401).
// Defaults to reading the X-User-ID header.
func WithUserID(fn func(*gin.Context) (string, bool)) Option {
	return func(o *Options) { o.userID = fn }
}

// WithResourceAction sets the function that derives (resource, action) from
// the request. Defaults to (URL path, HTTP method).
func WithResourceAction(fn func(*gin.Context) (string, string)) Option {
	return func(o *Options) { o.resourceAction = fn }
}

// WithUnauthorizedHandler overrides the default 401 handler.
func WithUnauthorizedHandler(fn func(*gin.Context)) Option {
	return func(o *Options) { o.unauthorized = fn }
}

// WithDeniedHandler overrides the default 403 handler.
func WithDeniedHandler(fn func(*gin.Context)) Option {
	return func(o *Options) { o.denied = fn }
}

func defaultOptions() Options {
	return Options{
		userID: func(c *gin.Context) (string, bool) {
			id := c.GetHeader("X-User-ID")
			return id, id != ""
		},
		resourceAction: func(c *gin.Context) (string, string) {
			r := c.Request
			return r.URL.Path, r.Method
		},
		unauthorized: func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		},
		denied: func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		},
	}
}

// Middleware builds a Gin middleware. Register it with:
//
//	r := gin.New()
//	r.Use(ginadapter.Middleware(enforcer, ginadapter.WithUserID(...)))
func Middleware(enforcer *rbacgo.Enforcer, opts ...Option) gin.HandlerFunc {
	if enforcer == nil {
		panic("rbacgo: nil enforcer")
	}
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return func(c *gin.Context) {
		userID, ok := o.userID(c)
		if !ok || userID == "" {
			o.unauthorized(c)
			return
		}
		resource, action := o.resourceAction(c)
		if !enforcer.Enforce(c.Request.Context(), userID, resource, action) {
			o.denied(c)
			return
		}
		c.Next()
	}
}
