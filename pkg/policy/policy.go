// Package policy provides a policy enforcement framework with rules,
// conditions, and decisions for controlling access and behavior.
package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Decision represents the outcome of a policy evaluation.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
	DecisionAudit Decision = "audit"
)

// Operator defines how a condition compares values.
type Operator string

const (
	OperatorEquals     Operator = "equals"
	OperatorNotEquals  Operator = "not_equals"
	OperatorContains   Operator = "contains"
	OperatorStartsWith Operator = "starts_with"
	OperatorEndsWith   Operator = "ends_with"
	OperatorIn         Operator = "in"
	OperatorNotIn      Operator = "not_in"
	OperatorExists     Operator = "exists"
	OperatorNotExists  Operator = "not_exists"
)

// Condition defines a single condition within a rule.
type Condition struct {
	Field    string   `json:"field"`
	Operator Operator `json:"operator"`
	Value    string   `json:"value,omitempty"`
	Values   []string `json:"values,omitempty"`
}

// Rule defines a policy rule with conditions.
type Rule struct {
	Name       string      `json:"name"`
	Conditions []Condition `json:"conditions"`
	Decision   Decision    `json:"decision"`
}

// Policy is a named collection of rules.
type Policy struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Rules       []Rule `json:"rules"`
	// DefaultDecision is applied when no rules match.
	DefaultDecision Decision `json:"default_decision"`
}

// EvaluationResult contains the result of evaluating a policy.
type EvaluationResult struct {
	Decision    Decision `json:"decision"`
	MatchedRule string   `json:"matched_rule,omitempty"`
	Reason      string   `json:"reason,omitempty"`
}

// EvaluationContext provides the data for policy evaluation.
type EvaluationContext struct {
	// Fields is a map of field names to values that conditions
	// are evaluated against.
	Fields map[string]string
}

// PolicyEvaluator is the function type for evaluating a single policy.
type PolicyEvaluator func(
	ctx context.Context,
	policy *Policy,
	evalCtx *EvaluationContext,
) (*EvaluationResult, error)

// Enforcer loads and evaluates policies.
type Enforcer struct {
	policies        map[string]*Policy
	mu              sync.RWMutex
	policyEvaluator PolicyEvaluator // allows injection for testing
}

// NewEnforcer creates a new Enforcer.
func NewEnforcer() *Enforcer {
	return &Enforcer{
		policies:        make(map[string]*Policy),
		policyEvaluator: evaluatePolicy,
	}
}

// SetPolicyEvaluator allows injecting a custom policy evaluator for testing.
func (e *Enforcer) SetPolicyEvaluator(eval PolicyEvaluator) {
	e.policyEvaluator = eval
}

// LoadPolicy adds a policy to the enforcer.
func (e *Enforcer) LoadPolicy(policy *Policy) error {
	if policy == nil {
		return fmt.Errorf("policy must not be nil")
	}
	if policy.Name == "" {
		return fmt.Errorf("policy name must not be empty")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies[policy.Name] = policy
	return nil
}

// LoadPolicies adds multiple policies to the enforcer.
func (e *Enforcer) LoadPolicies(policies []*Policy) error {
	for _, p := range policies {
		if err := e.LoadPolicy(p); err != nil {
			return fmt.Errorf("failed to load policy %q: %w",
				p.Name, err)
		}
	}
	return nil
}

// RemovePolicy removes a policy by name.
func (e *Enforcer) RemovePolicy(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.policies, name)
}

// GetPolicy returns a policy by name, or nil if not found.
func (e *Enforcer) GetPolicy(name string) *Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policies[name]
}

// Evaluate evaluates a specific policy against the given context.
func (e *Enforcer) Evaluate(
	ctx context.Context,
	policyName string,
	evalCtx *EvaluationContext,
) (*EvaluationResult, error) {
	e.mu.RLock()
	policy, exists := e.policies[policyName]
	e.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("policy %q not found", policyName)
	}

	// Use the (possibly injected) evaluator, mirroring EvaluateAll. Calling the
	// package-level evaluatePolicy directly here silently ignored an evaluator
	// installed via SetPolicyEvaluator, so a custom/stricter decision function
	// was bypassed on the single-policy path.
	return e.policyEvaluator(ctx, policy, evalCtx)
}

// EvaluateAll evaluates all loaded policies against the given context.
// Returns the most restrictive decision (Deny > Audit > Allow).
func (e *Enforcer) EvaluateAll(
	ctx context.Context,
	evalCtx *EvaluationContext,
) (*EvaluationResult, error) {
	e.mu.RLock()
	policies := make([]*Policy, 0, len(e.policies))
	for _, p := range e.policies {
		policies = append(policies, p)
	}
	e.mu.RUnlock()

	if len(policies) == 0 {
		return &EvaluationResult{
			Decision: DecisionAllow,
			Reason:   "no policies loaded",
		}, nil
	}

	mostRestrictive := &EvaluationResult{
		Decision: DecisionAllow,
		Reason:   "all policies passed",
	}

	for _, policy := range policies {
		result, err := e.policyEvaluator(ctx, policy, evalCtx)
		if err != nil {
			return nil, fmt.Errorf(
				"error evaluating policy %q: %w",
				policy.Name, err,
			)
		}

		if isMoreRestrictive(result.Decision, mostRestrictive.Decision) {
			mostRestrictive = result
		}
	}

	return mostRestrictive, nil
}

func evaluatePolicy(
	_ context.Context,
	policy *Policy,
	evalCtx *EvaluationContext,
) (*EvaluationResult, error) {
	for _, rule := range policy.Rules {
		allMatch := true
		for _, condition := range rule.Conditions {
			if !evaluateCondition(condition, evalCtx) {
				allMatch = false
				break
			}
		}
		if allMatch {
			return &EvaluationResult{
				Decision:    rule.Decision,
				MatchedRule: rule.Name,
				Reason: fmt.Sprintf(
					"matched rule %q in policy %q",
					rule.Name, policy.Name,
				),
			}, nil
		}
	}

	return &EvaluationResult{
		Decision: policy.DefaultDecision,
		Reason: fmt.Sprintf(
			"no rules matched in policy %q, using default",
			policy.Name,
		),
	}, nil
}

func evaluateCondition(
	condition Condition,
	evalCtx *EvaluationContext,
) bool {
	fieldValue, exists := evalCtx.Fields[condition.Field]

	switch condition.Operator {
	case OperatorExists:
		return exists
	case OperatorNotExists:
		return !exists
	case OperatorEquals:
		return exists && fieldValue == condition.Value
	case OperatorNotEquals:
		return !exists || fieldValue != condition.Value
	case OperatorContains:
		return exists && strings.Contains(fieldValue, condition.Value)
	case OperatorStartsWith:
		return exists && strings.HasPrefix(fieldValue, condition.Value)
	case OperatorEndsWith:
		return exists && strings.HasSuffix(fieldValue, condition.Value)
	case OperatorIn:
		if !exists {
			return false
		}
		for _, v := range condition.Values {
			if fieldValue == v {
				return true
			}
		}
		return false
	case OperatorNotIn:
		if !exists {
			return true
		}
		for _, v := range condition.Values {
			if fieldValue == v {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func isMoreRestrictive(a, b Decision) bool {
	order := map[Decision]int{
		DecisionAllow: 0,
		DecisionAudit: 1,
		DecisionDeny:  2,
	}
	return order[a] > order[b]
}
