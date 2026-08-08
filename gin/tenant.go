// Per-tenant RBAC middleware for Gin. One Enforcer is created lazily per
// tenant, resolved from each request by a caller-supplied function.
package ginadapter

import (
	"context"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/rachmanzz/rbacgo"
)

// TenantRegistry lazily creates and caches one *rbacgo.Enforcer per tenant.
// The factory is called at most once per tenant, even under concurrent
// requests, so tenants can be provisioned on first use.
type TenantRegistry struct {
	factory func(tenant string) (*rbacgo.Enforcer, error)
	mu      sync.Mutex
	cache   map[string]*tenantEntry
}

type tenantEntry struct {
	once sync.Once
	enf  *rbacgo.Enforcer
	err  error
}

// NewTenantRegistry builds a registry. The factory receives the tenant ID
// resolved from the request and must return that tenant's Enforcer. It panics
// on a nil factory.
func NewTenantRegistry(factory func(tenant string) (*rbacgo.Enforcer, error)) *TenantRegistry {
	if factory == nil {
		panic("rbacgo: nil tenant enforcer factory")
	}
	return &TenantRegistry{factory: factory, cache: make(map[string]*tenantEntry)}
}

// Get returns the Enforcer for tenant, creating it on first use. The factory
// error, if any, is returned to every caller of this tenant.
func (r *TenantRegistry) Get(tenant string) (*rbacgo.Enforcer, error) {
	r.mu.Lock()
	e, ok := r.cache[tenant]
	if !ok {
		e = &tenantEntry{}
		r.cache[tenant] = e
	}
	r.mu.Unlock()
	e.once.Do(func() { e.enf, e.err = r.factory(tenant) })
	return e.enf, e.err
}

// Clear forgets every cached Enforcer. The next request for a tenant creates
// a fresh one.
func (r *TenantRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]*tenantEntry)
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
	tenantResolver func(*gin.Context) (string, bool)
	userID         func(*gin.Context) (string, bool)
	resourceAction func(*gin.Context) (string, string)
	unauthorized   func(*gin.Context)
	denied         func(*gin.Context)
	enforcerError  func(*gin.Context, error)
}

// TenantOption mutates TenantOptions.
type TenantOption func(*TenantOptions)

// WithTenantResolver sets the function that derives the tenant ID from the
// request (header, subdomain, JWT claim, ...). It is REQUIRED: a missing or
// empty tenant is treated as unauthenticated (401).
func WithTenantResolver(fn func(*gin.Context) (string, bool)) TenantOption {
	return func(o *TenantOptions) { o.tenantResolver = fn }
}

// WithTenantUserID sets the function that extracts an authenticated subject
// ID from the request. It is REQUIRED, with the same semantics as the
// single-tenant middleware.
func WithTenantUserID(fn func(*gin.Context) (string, bool)) TenantOption {
	return func(o *TenantOptions) { o.userID = fn }
}

// WithTenantResourceAction sets the function that derives (resource, action)
// from the request. Defaults to (URL path, HTTP method).
func WithTenantResourceAction(fn func(*gin.Context) (string, string)) TenantOption {
	return func(o *TenantOptions) { o.resourceAction = fn }
}

// WithTenantUnauthorizedHandler overrides the default 401 handler (also used
// when the tenant cannot be resolved).
func WithTenantUnauthorizedHandler(fn func(*gin.Context)) TenantOption {
	return func(o *TenantOptions) { o.unauthorized = fn }
}

// WithTenantDeniedHandler overrides the default 403 handler.
func WithTenantDeniedHandler(fn func(*gin.Context)) TenantOption {
	return func(o *TenantOptions) { o.denied = fn }
}

// WithTenantEnforcerErrorHandler overrides the default 500 handler invoked
// when the tenant's Enforcer cannot be created (factory error).
func WithTenantEnforcerErrorHandler(fn func(*gin.Context, error)) TenantOption {
	return func(o *TenantOptions) { o.enforcerError = fn }
}

func defaultTenantOptions() TenantOptions {
	return TenantOptions{
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
		enforcerError: func(c *gin.Context, _ error) {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		},
	}
}

// TenantMiddleware builds a per-tenant Gin middleware. For every request it
// resolves the tenant, fetches (or lazily creates) that tenant's Enforcer
// from registry, stores both in the request context, and gates the request
// with the tenant's Enforcer:
//
//	r := gin.New()
//	r.Use(ginadapter.TenantMiddleware(registry,
//		ginadapter.WithTenantResolver(func(c *gin.Context) (string, bool) {
//			t := c.GetHeader("X-Tenant-ID")
//			return t, t != ""
//		}),
//		ginadapter.WithTenantUserID(func(c *gin.Context) (string, bool) {
//			return c.GetString("userID"), true
//		}),
//	))
//
// Handlers read the resolved tenant and Enforcer with TenantFromContext and
// EnforcerFromContext on c.Request.Context().
func TenantMiddleware(registry *TenantRegistry, opts ...TenantOption) gin.HandlerFunc {
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
	return func(c *gin.Context) {
		tenant, ok := o.tenantResolver(c)
		if !ok || tenant == "" {
			o.unauthorized(c)
			return
		}
		enf, err := registry.Get(tenant)
		if err != nil {
			o.enforcerError(c, err)
			return
		}
		ctx := context.WithValue(c.Request.Context(), tenantIDKey, tenant)
		ctx = context.WithValue(ctx, enforcerKey, enf)
		c.Request = c.Request.WithContext(ctx)
		userID, ok := o.userID(c)
		if !ok || userID == "" {
			o.unauthorized(c)
			return
		}
		resource, action := o.resourceAction(c)
		if !enf.Enforce(c.Request.Context(), userID, resource, action) {
			o.denied(c)
			return
		}
		c.Next()
	}
}
