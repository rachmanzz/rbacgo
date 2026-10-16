// Per-tenant RBAC middleware for net/http. One Enforcer is created lazily per
// tenant (the documented multi-tenant pattern: one Enforcer per tenant sharing
// one store), resolved from each request by a caller-supplied function.
package httpadapter

import (
	"context"
	"net/http"

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
	tenantResolver func(*http.Request) (string, bool)
	userID         func(*http.Request) (string, bool)
	resourceAction func(*http.Request) (string, string)
	unauthorized   func(http.ResponseWriter, *http.Request)
	denied         func(http.ResponseWriter, *http.Request)
	enforcerError  func(http.ResponseWriter, *http.Request, error)
}

// TenantOption mutates TenantOptions.
type TenantOption func(*TenantOptions)

// WithTenantResolver sets the function that derives the tenant ID from the
// request (header, subdomain, JWT claim, ...). It is REQUIRED: tenants are
// identified by your application, not by a fixed convention. A missing or
// empty tenant is treated as unauthenticated (401).
func WithTenantResolver(fn func(*http.Request) (string, bool)) TenantOption {
	return func(o *TenantOptions) { o.tenantResolver = fn }
}

// WithTenantUserID sets the function that extracts an authenticated subject ID from
// the request. It is REQUIRED, with the same semantics as the single-tenant
// middleware.
func WithTenantUserID(fn func(*http.Request) (string, bool)) TenantOption {
	return func(o *TenantOptions) { o.userID = fn }
}

// WithTenantResourceAction sets the function that derives (resource, action) from
// the request. Defaults to (URL path, HTTP method).
func WithTenantResourceAction(fn func(*http.Request) (string, string)) TenantOption {
	return func(o *TenantOptions) { o.resourceAction = fn }
}

// WithTenantUnauthorizedHandler overrides the default 401 handler (also used when
// the tenant cannot be resolved).
func WithTenantUnauthorizedHandler(h func(http.ResponseWriter, *http.Request)) TenantOption {
	return func(o *TenantOptions) { o.unauthorized = h }
}

// WithTenantDeniedHandler overrides the default 403 handler.
func WithTenantDeniedHandler(h func(http.ResponseWriter, *http.Request)) TenantOption {
	return func(o *TenantOptions) { o.denied = h }
}

// WithTenantEnforcerErrorHandler overrides the default 500 handler invoked when the
// tenant's Enforcer cannot be created (factory error).
func WithTenantEnforcerErrorHandler(h func(http.ResponseWriter, *http.Request, error)) TenantOption {
	return func(o *TenantOptions) { o.enforcerError = h }
}

func defaultTenantOptions() TenantOptions {
	return TenantOptions{
		resourceAction: func(r *http.Request) (string, string) {
			return r.URL.Path, r.Method
		},
		unauthorized: writeJSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"}),
		denied:       writeJSON(http.StatusForbidden, map[string]string{"error": "forbidden"}),
		enforcerError: func(w http.ResponseWriter, r *http.Request, _ error) {
			writeJSON(http.StatusInternalServerError, map[string]string{"error": "internal error"})(w, r)
		},
	}
}

// NewTenant builds a per-tenant net/http middleware. For every request it
// resolves the tenant, fetches (or lazily creates) that tenant's Enforcer
// from registry, stores both in the request context, and gates the request
// with the tenant's Enforcer:
//
//	registry := httpadapter.NewTenantRegistry(func(tenant string) (*rbacgo.Enforcer, error) {
//		return rbacgo.New(rbacgo.WithTenant(tenant), rbacgo.WithStore(sharedStore))
//	})
//	handler := httpadapter.NewTenant(registry,
//		httpadapter.WithTenantResolver(func(r *http.Request) (string, bool) {
//			t := r.Header.Get("X-Tenant-ID")
//			return t, t != ""
//		}),
//		httpadapter.WithTenantUserID(func(r *http.Request) (string, bool) {
//			return r.Context().Value(authUserKey).(string), true
//		}),
//	)
//	http.Handle("/articles", handler(http.HandlerFunc(listArticles)))
//
// Handlers read the resolved tenant and Enforcer with TenantFromContext and
// EnforcerFromContext.
func NewTenant(registry *TenantRegistry, opts ...TenantOption) func(http.Handler) http.Handler {
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
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tenant, ok := o.tenantResolver(r)
			if !ok || tenant == "" {
				o.unauthorized(w, r)
				return
			}
			enf, release, err := registry.Acquire(r.Context(), tenant)
			if err != nil {
				o.enforcerError(w, r, err)
				return
			}
			defer release()
			r = r.WithContext(context.WithValue(r.Context(), tenantIDKey, tenant))
			r = r.WithContext(context.WithValue(r.Context(), enforcerKey, enf))
			userID, ok := o.userID(r)
			if !ok || userID == "" {
				o.unauthorized(w, r)
				return
			}
			resource, action := o.resourceAction(r)
			if !enf.Enforce(r.Context(), userID, resource, action) {
				o.denied(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
