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

// PermissionView is the JSON-serializable snapshot of a user's access rights:
// their directly assigned roles, their effective permission set (own +
// inherited, deduplicated, alphabetically sorted), and the policy version at
// snapshot time. Marshal it directly as the response of a "my permissions"
// endpoint; frontends compare PolicyVersion across snapshots to detect policy
// changes without diffing the payload.
type PermissionView struct {
	UserID        string              `json:"user_id"`
	Roles         []string            `json:"roles"`
	Permissions   map[string][]string `json:"permissions"`
	PolicyVersion uint64              `json:"policy_version"`
}
