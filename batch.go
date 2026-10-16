package rbacgo

import "context"

type RoleAssignment struct {
	UserID   string
	RoleName string
}

// PolicyBatch runs in the documented order: register, update, rules, metadata,
// unassign, assign, delete. Every policy data change commits or rolls back as
// one operation. Cache invalidation, audit emission and the best-effort policy
// counter happen after commit; this is not an atomic authorization snapshot.
type PolicyBatch struct {
	Register        []Role
	Update          []Role
	RuleUpdates     map[string][]PolicyRule
	MetadataUpdates map[string]map[string]string
	Unassign        []RoleAssignment
	Assign          []RoleAssignment
	Delete          []string
}

type AtomicPolicyStore interface {
	ApplyPolicyBatch(context.Context, PolicyBatch) error
}

func validateBatch(batch PolicyBatch) error {
	for _, roles := range [][]Role{batch.Register, batch.Update} {
		for _, role := range roles {
			if !validRole(role) {
				return ErrInvalidRole
			}
		}
	}
	for _, rules := range batch.RuleUpdates {
		if err := validateRules(rules); err != nil {
			return err
		}
	}
	return nil
}

func applyBatch(ctx context.Context, store Store, batch PolicyBatch) error {
	if err := validateBatch(batch); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, role := range batch.Register {
		if err := store.AddRole(ctx, role); err != nil {
			return err
		}
	}
	if len(batch.Update) > 0 {
		updater, ok := store.(RoleUpdater)
		if !ok {
			return ErrUnsupported
		}
		for _, role := range batch.Update {
			if err := updater.UpdateRole(ctx, role); err != nil {
				return err
			}
		}
	}
	if len(batch.RuleUpdates) > 0 {
		rules, ok := store.(RoleRuleStore)
		if !ok {
			return ErrUnsupported
		}
		for name, value := range batch.RuleUpdates {
			if err := rules.SetRoleRules(ctx, name, value); err != nil {
				return err
			}
		}
	}
	if len(batch.MetadataUpdates) > 0 {
		metadata, ok := store.(RoleMetadataStore)
		if !ok {
			return ErrUnsupported
		}
		for name, value := range batch.MetadataUpdates {
			if err := metadata.SetRoleMetadata(ctx, name, value); err != nil {
				return err
			}
		}
	}
	if len(batch.Unassign) > 0 {
		unassigner, ok := store.(RoleUnassigner)
		if !ok {
			return ErrUnsupported
		}
		for _, assignment := range batch.Unassign {
			if err := unassigner.UnassignRole(ctx, assignment.UserID, assignment.RoleName); err != nil {
				return err
			}
		}
	}
	for _, assignment := range batch.Assign {
		if err := store.AssignRole(ctx, assignment.UserID, assignment.RoleName); err != nil {
			return err
		}
	}
	if len(batch.Delete) > 0 {
		deleter, ok := store.(RoleDeleter)
		if !ok {
			return ErrUnsupported
		}
		for _, name := range batch.Delete {
			if err := deleter.DeleteRole(ctx, name); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}

// ApplyPolicyBatch checks the actor's management capability and atomically
// changes this tenant's policy data. Unsupported stores return ErrUnsupported.
func (e *Enforcer) ApplyPolicyBatch(ctx context.Context, actorID string, batch PolicyBatch) error {
	if err := e.requireManagement(ctx, actorID); err != nil {
		return err
	}
	if err := validateBatch(batch); err != nil {
		return err
	}
	if len(batch.RuleUpdates) > 0 && !e.rulesEnabled {
		return ErrPolicyRulesDisabled
	}
	store, ok := e.store.(AtomicPolicyStore)
	if !ok {
		return ErrUnsupported
	}
	scoped := PolicyBatch{RuleUpdates: make(map[string][]PolicyRule), MetadataUpdates: make(map[string]map[string]string)}
	for _, role := range batch.Register {
		scoped.Register = append(scoped.Register, e.scopeRole(role))
	}
	for _, role := range batch.Update {
		scoped.Update = append(scoped.Update, e.scopeRole(role))
	}
	for name, rules := range batch.RuleUpdates {
		scoped.RuleUpdates[e.roleKey(name)] = rules
	}
	for name, metadata := range batch.MetadataUpdates {
		scoped.MetadataUpdates[e.roleKey(name)] = metadata
	}
	for _, assignment := range batch.Unassign {
		scoped.Unassign = append(scoped.Unassign, RoleAssignment{e.userKey(assignment.UserID), e.roleKey(assignment.RoleName)})
	}
	for _, assignment := range batch.Assign {
		scoped.Assign = append(scoped.Assign, RoleAssignment{e.userKey(assignment.UserID), e.roleKey(assignment.RoleName)})
	}
	for _, name := range batch.Delete {
		scoped.Delete = append(scoped.Delete, e.roleKey(name))
	}
	if err := store.ApplyPolicyBatch(ctx, scoped); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	e.flushCache()
	e.invalidateAll(ctx)
	return e.recordMutation(ctx, "apply_policy_batch", actorID, "", "")
}
