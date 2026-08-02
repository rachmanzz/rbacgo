package rbacgo

import "errors"

// Sentinel errors returned by the engine and stores.
var (
	// ErrRoleNotFound is returned when a referenced role does not exist.
	ErrRoleNotFound = errors.New("rbacgo: role not found")
	// ErrRoleExists is returned when registering a role that already exists.
	ErrRoleExists = errors.New("rbacgo: role already exists")
	// ErrParentNotFound is returned when a role declares a parent that does not exist.
	ErrParentNotFound = errors.New("rbacgo: parent role not found")
	// ErrCycleDetected is returned when a role hierarchy would introduce a cycle.
	ErrCycleDetected = errors.New("rbacgo: role hierarchy cycle detected")
	// ErrInvalidRole is returned for a malformed role (empty name, invalid permissions).
	ErrInvalidRole = errors.New("rbacgo: invalid role")
	// ErrUserNotFound is returned when a referenced user does not exist.
	ErrUserNotFound = errors.New("rbacgo: user not found")
)
