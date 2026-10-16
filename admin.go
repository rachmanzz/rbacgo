package rbacgo

import "context"

// RegisterRoleAs registers a role only when actorID holds the configured
// role-management capability in this tenant. The application must derive
// actorID from its authenticated identity, not an untrusted request field.
// Use RegisterRole only for trusted provisioning or initial admin bootstrap.
func (e *Enforcer) RegisterRoleAs(ctx context.Context, actorID string, role Role) error {
	if err := e.requireManagement(ctx, actorID); err != nil {
		return err
	}
	return e.RegisterRole(withAuditActor(ctx, actorID), role)
}

// RegisterRolesAs checks actorID's role-management capability, then registers
// roles in order. As with RegisterRoles, the batch is not atomic: registration
// stops at the first error, retaining earlier successful registrations.
func (e *Enforcer) RegisterRolesAs(ctx context.Context, actorID string, roles ...Role) error {
	if err := e.requireManagement(ctx, actorID); err != nil {
		return err
	}
	return e.RegisterRoles(withAuditActor(ctx, actorID), roles...)
}

// AssignRoleAs assigns roleName to targetUserID only when actorID holds the
// configured role-management capability. All identities and roles are scoped
// to this Enforcer's tenant. The application must authenticate actorID.
func (e *Enforcer) AssignRoleAs(ctx context.Context, actorID, targetUserID, roleName string) error {
	if err := e.requireManagement(ctx, actorID); err != nil {
		return err
	}
	return e.AssignRole(withAuditActor(ctx, actorID), targetUserID, roleName)
}

// ListRolesAs lists this tenant's roles only when actorID holds the configured
// role-management capability. It returns ErrUnsupported if the Store does not
// implement role listing. The application must authenticate actorID.
func (e *Enforcer) ListRolesAs(ctx context.Context, actorID string) ([]Role, error) {
	if err := e.requireManagement(ctx, actorID); err != nil {
		return nil, err
	}
	return e.ListRoles(ctx)
}
