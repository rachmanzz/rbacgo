package rbacgo

// Permission represents the ability to perform an Action on a Resource.
type Permission struct {
	Resource string
	Action   string
}

// Role is a named set of permissions. A role may inherit from one or more
// parent roles; its effective permission set is the union of its own
// permissions and all inherited permissions.
type Role struct {
	Name        string
	Permissions []Permission
	Parents     []string
}

// User is identified by an ID and assigned zero or more roles.
type User struct {
	ID    string
	Roles []string
}
