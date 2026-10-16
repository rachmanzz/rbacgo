package rbacgo

import "context"

func cloneMetadata(metadata map[string]string) map[string]string {
	copy := make(map[string]string, len(metadata))
	for k, v := range metadata {
		copy[k] = v
	}
	return copy
}

func (s *memoryStore) SetRoleRules(ctx context.Context, name string, rules []PolicyRule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	copy, err := cloneRules(rules)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[name]; !ok {
		return ErrRoleNotFound
	}
	if s.rules == nil {
		s.rules = make(map[string][]PolicyRule)
	}
	s.rules[name] = copy
	return nil
}

func (s *memoryStore) GetRoleRules(ctx context.Context, name string) ([]PolicyRule, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.roles[name]; !ok {
		return nil, ErrRoleNotFound
	}
	return cloneRules(s.rules[name])
}

func (s *memoryStore) SetRoleMetadata(ctx context.Context, name string, metadata map[string]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[name]; !ok {
		return ErrRoleNotFound
	}
	if s.metadata == nil {
		s.metadata = make(map[string]map[string]string)
	}
	s.metadata[name] = cloneMetadata(metadata)
	return nil
}

func (s *memoryStore) GetRoleMetadata(ctx context.Context, name string) (map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.roles[name]; !ok {
		return nil, ErrRoleNotFound
	}
	return cloneMetadata(s.metadata[name]), nil
}

func (s *memoryStore) ApplyPolicyBatch(ctx context.Context, batch PolicyBatch) error {
	if err := validateBatch(batch); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := NewMemoryStore().(*memoryStore)
	for name, role := range s.roles {
		role.Permissions = append([]Permission(nil), role.Permissions...)
		role.Parents = append([]string(nil), role.Parents...)
		copy.roles[name] = role
	}
	for user, roles := range s.users {
		copy.users[user] = append([]string(nil), roles...)
	}
	for role, users := range s.roleUsers {
		copy.roleUsers[role] = make(map[string]struct{}, len(users))
		for user := range users {
			copy.roleUsers[role][user] = struct{}{}
		}
	}
	for name, metadata := range s.metadata {
		copy.metadata[name] = cloneMetadata(metadata)
	}
	for name, rules := range s.rules {
		cloned, err := cloneRules(rules)
		if err != nil {
			return err
		}
		copy.rules[name] = cloned
	}
	if err := applyBatch(ctx, copy, batch); err != nil {
		return err
	}
	s.roles, s.users, s.roleUsers = copy.roles, copy.users, copy.roleUsers
	s.rules, s.metadata = copy.rules, copy.metadata
	return nil
}
