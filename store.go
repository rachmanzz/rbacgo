package rbacgo

import "context"

// Store abstracts persistence of roles, permissions, and user-role
// assignments. Implementations may be in-memory, SQL-backed, or any other
// backend that fits the interface.
type Store interface {
	// AddRole persists a role together with its permissions and parent links.
	// It must reject duplicate role names and cycles in the hierarchy.
	AddRole(ctx context.Context, role Role) error
	// GetRole returns the role with the given name. The bool reports whether
	// the role was found.
	GetRole(ctx context.Context, name string) (Role, bool, error)
	// AssignRole assigns a role to a user, creating the user if needed.
	// It must fail if the role does not exist.
	AssignRole(ctx context.Context, userID, roleName string) error
	// GetRoles returns the names of all roles assigned to a user.
	GetRoles(ctx context.Context, userID string) ([]string, error)
}

// RoleDeleter is optionally implemented by stores that support deleting
// roles. Enforcer.DeleteRole reports ErrUnsupported for stores that do not
// implement it, so existing stores keep working unchanged.
type RoleDeleter interface {
	// DeleteRole removes a role and its metadata. It must return
	// ErrRoleNotFound when the role does not exist and ErrRoleInUse when the
	// role is still assigned to at least one user.
	DeleteRole(ctx context.Context, name string) error
}

// RoleUnassigner is optionally implemented by stores that support removing a
// role from a user. Enforcer.UnassignRole reports ErrUnsupported for stores
// that do not implement it.
type RoleUnassigner interface {
	// UnassignRole removes roleName from userID's assignments. It must
	// return ErrRoleNotFound when the role does not exist; unassigning a
	// role the user does not hold is a no-op.
	UnassignRole(ctx context.Context, userID, roleName string) error
}

// PolicyVersioner is optionally implemented by stores that persist a shared
// policy version (e.g. a SQL meta table). Multi-instance deployments agree on
// one version through the store; stores that do not implement it fall back to
// a per-Enforcer counter.
type PolicyVersioner interface {
	// PolicyVersion returns the currently committed policy version. It must
	// report 0 when no mutation has ever been recorded.
	PolicyVersion(ctx context.Context) (uint64, error)
	// NextPolicyVersion atomically advances the policy version and returns
	// the new value.
	NextPolicyVersion(ctx context.Context) (uint64, error)
}
