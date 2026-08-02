package rbacgo

import (
	"context"
	"strings"
	"sync"
)

// memoryStore is a concurrency-safe, pure-Go Store kept entirely in RAM.
// Data is lost on restart.
type memoryStore struct {
	mu    sync.RWMutex
	roles map[string]Role
	users map[string][]string
}

// NewMemoryStore returns a Store backed by maps in memory. Useful for tests,
// caching layers, and single-instance deployments without persistence.
func NewMemoryStore() Store {
	return &memoryStore{
		roles: make(map[string]Role),
		users: make(map[string][]string),
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
	for _, existing := range s.users[userID] {
		if existing == roleName {
			return nil
		}
	}
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
