package rbacgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Attributes contains trusted facts, e.g. subject.department, resource.owner,
// and environment.hour. The engine always supplies subject.id and tenant.id.
// Do not mutate attributes or nested values during a decision.
type Attributes map[string]any

type Condition struct {
	Attribute      string
	Operator       string
	Value          any
	OtherAttribute string
}

// PolicyRule attaches an allow/deny decision and AND conditions to a role.
// Any matching deny wins across all direct and inherited roles.
// Missing/invalid facts never satisfy an allow and conservatively trigger a
// candidate deny unless another condition definitely rules that deny out.
type PolicyRule struct {
	Effect     string
	Resource   string
	Action     string
	Conditions []Condition
}

const (
	EffectAllow = "allow"
	EffectDeny  = "deny"
)

var ErrInvalidPolicy = errors.New("rbacgo: invalid policy rule")
var ErrPolicyRulesDisabled = errors.New("rbacgo: policy rules require WithPolicyRules")

// RoleRuleStore is an optional persistence capability for context-aware rules.
// It must clone inputs/outputs and atomically replace one role's rule list.
type RoleRuleStore interface {
	SetRoleRules(context.Context, string, []PolicyRule) error
	GetRoleRules(context.Context, string) ([]PolicyRule, error)
}

// RoleMetadataStore persists descriptive metadata independently of Role's
// original struct layout. Metadata never grants or denies access.
type RoleMetadataStore interface {
	SetRoleMetadata(context.Context, string, map[string]string) error
	GetRoleMetadata(context.Context, string) (map[string]string, error)
}

func WithWildcardPermissions() Option {
	return func(e *Enforcer) error { e.wildcards = true; return nil }
}

// WithPolicyRules opts every decision into persisted allow/deny rules.
// Enable it on every Enforcer sharing the policy dataset. Rule lists are
// evaluated per call, not cached as decisions, so attributes cannot leak
// between callers or resource contexts.
func WithPolicyRules() Option {
	return func(e *Enforcer) error { e.rulesEnabled = true; return nil }
}

type attributesContextKey struct{}

func WithAttributes(ctx context.Context, attrs Attributes) context.Context {
	copy := make(Attributes, len(attrs))
	for k, v := range attrs {
		copy[k] = v
	}
	return context.WithValue(ctx, attributesContextKey{}, copy)
}

func contextAttributes(ctx context.Context) Attributes {
	attrs, _ := ctx.Value(attributesContextKey{}).(Attributes)
	return attrs
}

func (e *Enforcer) matchPermission(ps permissionSet, resource, action string) bool {
	if ps[resource][action] {
		return true
	}
	return e.wildcards && (ps[resource]["*"] || ps["*"][action] || ps["*"]["*"])
}

func (e *Enforcer) ruleMatches(rule PolicyRule, resource, action string) bool {
	return (rule.Resource == resource || e.wildcards && rule.Resource == "*") &&
		(rule.Action == action || e.wildcards && rule.Action == "*")
}

func validateRules(rules []PolicyRule) error {
	for _, rule := range rules {
		if (rule.Effect != EffectAllow && rule.Effect != EffectDeny) ||
			strings.TrimSpace(rule.Resource) == "" || strings.TrimSpace(rule.Action) == "" {
			return ErrInvalidPolicy
		}
		for _, c := range rule.Conditions {
			if strings.TrimSpace(c.Attribute) == "" || (c.OtherAttribute != "" && c.Value != nil) {
				return ErrInvalidPolicy
			}
			switch c.Operator {
			case "eq", "ne", "gt", "ge", "lt", "le":
			case "in", "not_in":
				if c.OtherAttribute == "" {
					raw, err := json.Marshal(c.Value)
					if err != nil || len(raw) == 0 || raw[0] != '[' {
						return ErrInvalidPolicy
					}
				}
			case "exists", "not_exists":
				if c.Value != nil || c.OtherAttribute != "" {
					return ErrInvalidPolicy
				}
			default:
				return ErrInvalidPolicy
			}
			if _, err := json.Marshal(c.Value); err != nil {
				return ErrInvalidPolicy
			}
		}
	}
	return nil
}

func cloneRules(rules []PolicyRule) ([]PolicyRule, error) {
	if err := validateRules(rules); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return nil, err
	}
	var copy []PolicyRule
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	err = decoder.Decode(&copy)
	return copy, err
}

func numeric(value any) (*big.Rat, bool) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return nil, false
	}
	n, ok := new(big.Rat).SetString(string(raw))
	return n, ok
}

func equalAttribute(a, b any) bool {
	if x, ok := numeric(a); ok {
		y, ok := numeric(b)
		return ok && x.Cmp(y) == 0
	}
	x, err := json.Marshal(a)
	y, otherErr := json.Marshal(b)
	return err == nil && otherErr == nil && string(x) == string(y)
}

func conditionMatches(c Condition, attrs Attributes) (match, known bool) {
	value, exists := attrs[c.Attribute]
	// Presence is meaningful only for a valid JSON fact. Otherwise an exists
	// allow could succeed, or a not_exists deny could be ruled out, using a
	// malformed value. Missing facts retain normal presence semantics.
	if exists {
		if _, err := json.Marshal(value); err != nil {
			return false, false
		}
	}
	if c.Operator == "exists" {
		return exists, true
	}
	if c.Operator == "not_exists" {
		return !exists, true
	}
	if !exists {
		return false, false
	}
	expected := c.Value
	if c.OtherAttribute != "" {
		var ok bool
		expected, ok = attrs[c.OtherAttribute]
		if !ok {
			return false, false
		}
	}
	if _, err := json.Marshal(expected); err != nil {
		return false, false
	}
	switch c.Operator {
	case "eq":
		return equalAttribute(value, expected), true
	case "ne":
		return !equalAttribute(value, expected), true
	case "in", "not_in":
		raw, err := json.Marshal(expected)
		if err != nil || len(raw) == 0 || raw[0] != '[' {
			return false, false
		}
		var values []any
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.UseNumber()
		if decoder.Decode(&values) != nil {
			return false, false
		}
		found := false
		for _, candidate := range values {
			if equalAttribute(value, candidate) {
				found = true
				break
			}
		}
		if c.Operator == "not_in" {
			found = !found
		}
		return found, true
	case "gt", "ge", "lt", "le":
		x, xok := numeric(value)
		y, yok := numeric(expected)
		if !xok || !yok {
			return false, false
		}
		compared := x.Cmp(y)
		switch c.Operator {
		case "gt":
			return compared > 0, true
		case "ge":
			return compared >= 0, true
		case "lt":
			return compared < 0, true
		default:
			return compared <= 0, true
		}
	}
	return false, false
}

func conditionsMatch(conditions []Condition, attrs Attributes) (bool, bool) {
	known := true
	for _, condition := range conditions {
		match, certain := conditionMatches(condition, attrs)
		if certain && !match {
			return false, true
		}
		known = known && certain
	}
	return known, known
}

func (e *Enforcer) evaluateRules(ctx context.Context, userID, resource, action string, allowed bool, attrs Attributes) (bool, error) {
	if !e.rulesEnabled {
		return allowed, nil
	}
	store, ok := e.store.(RoleRuleStore)
	if !ok {
		return false, ErrUnsupported
	}
	facts := make(Attributes, len(attrs)+2)
	for k, v := range attrs {
		facts[k] = v
	}
	facts["subject.id"], facts["tenant.id"] = userID, e.tenant
	names, err := e.store.GetRoles(ctx, e.userKey(userID))
	if err != nil {
		return false, err
	}
	seen := make(map[string]bool)
	for _, name := range names {
		if err := e.collectRoleNames(ctx, name, seen); err != nil {
			return false, err
		}
	}
	for name := range seen {
		rules, err := store.GetRoleRules(ctx, name)
		if err != nil {
			return false, err
		}
		if err := validateRules(rules); err != nil {
			return false, err
		}
		for _, rule := range rules {
			if !e.ruleMatches(rule, resource, action) {
				continue
			}
			match, known := conditionsMatch(rule.Conditions, facts)
			if rule.Effect == EffectDeny && (match || !known) {
				return false, nil
			}
			if rule.Effect == EffectAllow && match {
				allowed = true
			}
		}
	}
	return allowed, nil
}

// EnforceAttributesCtx evaluates rules with explicit trusted attributes.
// WithPolicyRules must be configured; otherwise it returns an error.
func (e *Enforcer) EnforceAttributesCtx(ctx context.Context, userID, resource, action string, attrs Attributes) (bool, error) {
	if !e.rulesEnabled {
		return false, ErrPolicyRulesDisabled
	}
	return e.EnforceCtx(WithAttributes(ctx, attrs), userID, resource, action)
}

func (e *Enforcer) EnforceAttributes(ctx context.Context, userID, resource, action string, attrs Attributes) bool {
	ok, err := e.EnforceAttributesCtx(ctx, userID, resource, action, attrs)
	return err == nil && ok
}

func (e *Enforcer) SetRoleRules(ctx context.Context, actorID, roleName string, rules []PolicyRule) error {
	if !e.rulesEnabled {
		return ErrPolicyRulesDisabled
	}
	if err := e.requireManagement(ctx, actorID); err != nil {
		return err
	}
	if err := validateRules(rules); err != nil {
		return err
	}
	store, ok := e.store.(RoleRuleStore)
	if !ok {
		return ErrUnsupported
	}
	if err := store.SetRoleRules(ctx, e.roleKey(roleName), rules); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	e.flushCache()
	e.invalidateAll(ctx)
	return e.recordMutation(ctx, "set_role_rules", actorID, "", roleName)
}

func (e *Enforcer) RoleRules(ctx context.Context, actorID, roleName string) ([]PolicyRule, error) {
	if err := e.requireManagement(ctx, actorID); err != nil {
		return nil, err
	}
	store, ok := e.store.(RoleRuleStore)
	if !ok {
		return nil, ErrUnsupported
	}
	return store.GetRoleRules(ctx, e.roleKey(roleName))
}

func (e *Enforcer) SetRoleMetadata(ctx context.Context, actorID, roleName string, metadata map[string]string) error {
	if err := e.requireManagement(ctx, actorID); err != nil {
		return err
	}
	store, ok := e.store.(RoleMetadataStore)
	if !ok {
		return ErrUnsupported
	}
	if err := store.SetRoleMetadata(ctx, e.roleKey(roleName), metadata); err != nil {
		return err
	}
	e.bumpPolicyVersion(ctx)
	return e.recordMutation(ctx, "set_role_metadata", actorID, "", roleName)
}

func (e *Enforcer) RoleMetadata(ctx context.Context, actorID, roleName string) (map[string]string, error) {
	if err := e.requireManagement(ctx, actorID); err != nil {
		return nil, err
	}
	store, ok := e.store.(RoleMetadataStore)
	if !ok {
		return nil, ErrUnsupported
	}
	return store.GetRoleMetadata(ctx, e.roleKey(roleName))
}

func invalidPolicyf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPolicy, fmt.Sprintf(format, args...))
}
