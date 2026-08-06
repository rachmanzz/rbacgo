package rbacgo

import (
	"context"
	"strings"
	"sync"
)

// memoryStore is a concurrency-safe, pure-Go Store kept entirely in RAM.
// Data is lost on restart.
type memoryStore struct {
	mu sync.RWMutex
	// roles: role name -> role; users: user ID -> roles (insertion order);
	// roleUsers: role name -> set of assigned user IDs (O(1) membership
	// index for duplicate checks and in-use lookups).
	roles     map[string]Role
	users     map[string][]string
	roleUsers map[string]map[string]struct{}
}

// NewMemoryStore returns a Store backed by maps in memory. Useful for tests,
// caching layers, and single-instance deployments without persistence.
func NewMemoryStore() Store {
	return &memoryStore{
		roles:     make(map[string]Role),
		users:     make(map[string][]string),
		roleUsers: make(map[string]map[string]struct{}),
	}
}

func (s *memoryStore) AddRole(_ context.Context, role Role) error {
	if !validRole(role) {
		return ErrInvalidRole
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.roles[role.Name]; exists {
		return ErrRoleExists
	}
	for _, parent := range role.Parents {
		if _, ok := s.roles[parent]; !ok {
			return ErrParentNotFound
		}
	}
	s.roles[role.Name] = role
	if err := detectCycle(s.roles, role.Name, map[string]bool{}); err != nil {
		delete(s.roles, role.Name)
		return err
	}
	return nil
}

func (s *memoryStore) GetRole(_ context.Context, name string) (Role, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	role, ok := s.roles[name]
	if !ok {
		return Role{}, false, nil
	}
	cp := Role{Name: role.Name}
	cp.Permissions = append([]Permission(nil), role.Permissions...)
	cp.Parents = append([]string(nil), role.Parents...)
	return cp, true, nil
}

func (s *memoryStore) AssignRole(_ context.Context, userID, roleName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[roleName]; !ok {
		return ErrRoleNotFound
	}
	assigned, ok := s.roleUsers[roleName]
	if !ok {
		assigned = make(map[string]struct{})
		s.roleUsers[roleName] = assigned
	}
	if _, exists := assigned[userID]; exists {
		return nil
	}
	assigned[userID] = struct{}{}
	s.users[userID] = append(s.users[userID], roleName)
	return nil
}

func (s *memoryStore) GetRoles(_ context.Context, userID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	roles := s.users[userID]
	out := make([]string, len(roles))
	copy(out, roles)
	return out, nil
}

func (s *memoryStore) DeleteRole(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[name]; !ok {
		return ErrRoleNotFound
	}
	if len(s.roleUsers[name]) > 0 {
		return ErrRoleInUse
	}
	delete(s.roles, name)
	delete(s.roleUsers, name)
	// Cascade: drop the deleted role from every child role's parent list.
	for roleName, role := range s.roles {
		filtered := role.Parents[:0]
		for _, parent := range role.Parents {
			if parent != name {
				filtered = append(filtered, parent)
			}
		}
		role.Parents = filtered
		s.roles[roleName] = role
	}
	return nil
}

func (s *memoryStore) UnassignRole(_ context.Context, userID, roleName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[roleName]; !ok {
		return ErrRoleNotFound
	}
	roles := s.users[userID]
	filtered := roles[:0]
	removed := false
	for _, r := range roles {
		if r == roleName {
			removed = true
			continue
		}
		filtered = append(filtered, r)
	}
	if removed {
		if assigned, ok := s.roleUsers[roleName]; ok {
			delete(assigned, userID)
		}
	}
	s.users[userID] = filtered
	return nil
}

// detectCycle performs a DFS over the parent graph starting at roleName.
// A cycle exists if roleName is reachable from itself through its parents.
func detectCycle(roles map[string]Role, roleName string, visiting map[string]bool) error {
	if visiting[roleName] {
		return ErrCycleDetected
	}
	role, ok := roles[roleName]
	if !ok {
		return nil
	}
	visiting[roleName] = true
	for _, parent := range role.Parents {
		if err := detectCycle(roles, parent, visiting); err != nil {
			return err
		}
	}
	visiting[roleName] = false
	return nil
}

func validRole(role Role) bool {
	if strings.TrimSpace(role.Name) == "" {
		return false
	}
	for _, p := range role.Permissions {
		if strings.TrimSpace(p.Resource) == "" || strings.TrimSpace(p.Action) == "" {
			return false
		}
	}
	return true
}
