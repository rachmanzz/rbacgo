// Per-tenant RBAC middleware for Echo v5. One Enforcer is created lazily per
// tenant, resolved from each request by a caller-supplied function.
package echoadapter

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/rachmanzz/rbacgo"
)

// TenantRegistry is the shared core registry, including bounded storage,
// context-aware provisioning, request leases, idle eviction, and shutdown.
type TenantRegistry = rbacgo.TenantRegistry

func NewTenantRegistry(factory func(string) (*rbacgo.Enforcer, error)) *TenantRegistry {
	return rbacgo.NewTenantRegistry(factory)
}

func NewTenantRegistryWithOptions(factory func(string) (*rbacgo.Enforcer, error), opts ...rbacgo.TenantRegistryOption) *TenantRegistry {
	return rbacgo.NewTenantRegistryWithOptions(factory, opts...)
}

func NewTenantRegistryContext(factory func(context.Context, string) (*rbacgo.Enforcer, error), opts ...rbacgo.TenantRegistryOption) *TenantRegistry {
	return rbacgo.NewTenantRegistryContext(factory, opts...)
}

type tenantContextKey int

const (
	tenantIDKey tenantContextKey = iota
	enforcerKey
)

// TenantFromContext returns the tenant ID the per-tenant middleware resolved
// for this request.
func TenantFromContext(ctx context.Context) (string, bool) {
	v, ok := ctx.Value(tenantIDKey).(string)
	return v, ok && v != ""
}

// EnforcerFromContext returns the tenant's Enforcer the per-tenant middleware
// selected for this request (e.g. for PermissionView or ListRoles in handlers).
func EnforcerFromContext(ctx context.Context) (*rbacgo.Enforcer, bool) {
	e, ok := ctx.Value(enforcerKey).(*rbacgo.Enforcer)
	return e, ok
}

// TenantOptions configures the per-tenant middleware.
type TenantOptions struct {
	tenantResolver func(*echo.Context) (string, bool)
	userID         func(*echo.Context) (string, bool)
	resourceAction func(*echo.Context) (string, string)
	unauthorized   func(*echo.Context) error
	denied         func(*echo.Context) error
	enforcerError  func(*echo.Context, error) error
}

// TenantOption mutates TenantOptions.
type TenantOption func(*TenantOptions)

// WithTenantResolver sets the function that derives the tenant ID from the
// request (header, subdomain, JWT claim, ...). It is REQUIRED: a missing or
// empty tenant is treated as unauthenticated (401).
func WithTenantResolver(fn func(*echo.Context) (string, bool)) TenantOption {
	return func(o *TenantOptions) { o.tenantResolver = fn }
}

// WithTenantUserID sets the function that extracts an authenticated subject
// ID from the request. It is REQUIRED, with the same semantics as the
// single-tenant middleware.
func WithTenantUserID(fn func(*echo.Context) (string, bool)) TenantOption {
	return func(o *TenantOptions) { o.userID = fn }
}

// WithTenantResourceAction sets the function that derives (resource, action)
// from the request. Defaults to (URL path, HTTP method).
func WithTenantResourceAction(fn func(*echo.Context) (string, string)) TenantOption {
	return func(o *TenantOptions) { o.resourceAction = fn }
}

// WithTenantUnauthorizedHandler overrides the default 401 handler (also used
// when the tenant cannot be resolved).
func WithTenantUnauthorizedHandler(fn func(*echo.Context) error) TenantOption {
	return func(o *TenantOptions) { o.unauthorized = fn }
}

// WithTenantDeniedHandler overrides the default 403 handler.
func WithTenantDeniedHandler(fn func(*echo.Context) error) TenantOption {
	return func(o *TenantOptions) { o.denied = fn }
}

// WithTenantEnforcerErrorHandler overrides the default 500 handler invoked
// when the tenant's Enforcer cannot be created (factory error).
func WithTenantEnforcerErrorHandler(fn func(*echo.Context, error) error) TenantOption {
	return func(o *TenantOptions) { o.enforcerError = fn }
}

func defaultTenantOptions() TenantOptions {
	return TenantOptions{
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
		enforcerError: func(c *echo.Context, _ error) error {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})
		},
	}
}

// TenantMiddleware builds a per-tenant Echo middleware. For every request it
// resolves the tenant, fetches (or lazily creates) that tenant's Enforcer
// from registry, stores both in the request context, and gates the request
// with the tenant's Enforcer:
//
//	e.Use(echoadapter.TenantMiddleware(registry,
//		echoadapter.WithTenantResolver(func(c *echo.Context) (string, bool) {
//			t := c.Request().Header.Get("X-Tenant-ID")
//			return t, t != ""
//		}),
//		echoadapter.WithTenantUserID(func(c *echo.Context) (string, bool) {
//			return c.Request().Context().Value(authUserKey).(string), true
//		}),
//	))
//
// Handlers read the resolved tenant and Enforcer with TenantFromContext and
// EnforcerFromContext on c.Request().Context().
func TenantMiddleware(registry *TenantRegistry, opts ...TenantOption) echo.MiddlewareFunc {
	if registry == nil {
		panic("rbacgo: nil tenant registry")
	}
	o := defaultTenantOptions()
	for _, opt := range opts {
		opt(&o)
	}
	if o.tenantResolver == nil {
		panic("rbacgo: WithTenantResolver is required (tenants are identified by your application)")
	}
	if o.userID == nil {
		panic("rbacgo: WithTenantUserID is required (user identity comes from your auth middleware, not HTTP headers)")
	}
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			tenant, ok := o.tenantResolver(c)
			if !ok || tenant == "" {
				return o.unauthorized(c)
			}
			enf, release, err := registry.Acquire(c.Request().Context(), tenant)
			if err != nil {
				return o.enforcerError(c, err)
			}
			defer release()
			ctx := context.WithValue(c.Request().Context(), tenantIDKey, tenant)
			ctx = context.WithValue(ctx, enforcerKey, enf)
			c.SetRequest(c.Request().WithContext(ctx))
			userID, ok := o.userID(c)
			if !ok || userID == "" {
				return o.unauthorized(c)
			}
			resource, action := o.resourceAction(c)
			if !enf.Enforce(c.Request().Context(), userID, resource, action) {
				return o.denied(c)
			}
			return next(c)
		}
	}
}
