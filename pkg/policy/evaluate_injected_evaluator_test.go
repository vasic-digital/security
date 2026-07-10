package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnforcer_Evaluate_UsesInjectedEvaluator proves that Enforcer.Evaluate
// honours the evaluator installed via SetPolicyEvaluator.
//
// Defect (RED): the single-policy Evaluate path called the package-level
// evaluatePolicy function directly instead of e.policyEvaluator, so an injected
// (possibly stricter / audit-wrapping) evaluator was silently bypassed — a
// policy engine that ignores its own configured decision function on one of its
// two public evaluate methods. EvaluateAll already honours the injected
// evaluator (see TestEnforcer_EvaluateAll_EvaluatorError); Evaluate must too.
func TestEnforcer_Evaluate_UsesInjectedEvaluator(t *testing.T) {
	enforcer := NewEnforcer()
	require.NoError(t, enforcer.LoadPolicy(&Policy{
		Name:            "p",
		Rules:           []Rule{},
		DefaultDecision: DecisionAllow, // the DEFAULT evaluator would return Allow
	}))

	const sentinel = "custom-evaluator-was-used"
	enforcer.SetPolicyEvaluator(func(
		_ context.Context, _ *Policy, _ *EvaluationContext,
	) (*EvaluationResult, error) {
		return &EvaluationResult{Decision: DecisionDeny, Reason: sentinel}, nil
	})

	res, err := enforcer.Evaluate(
		context.Background(), "p",
		&EvaluationContext{Fields: map[string]string{}},
	)
	require.NoError(t, err)

	// The injected evaluator returns Deny + sentinel; the default evaluatePolicy
	// would return Allow with a "no rules matched" reason. If Evaluate ignores
	// the injection these assertions fail.
	assert.Equal(t, DecisionDeny, res.Decision,
		"Evaluate ignored the injected PolicyEvaluator (used default evaluatePolicy)")
	assert.Equal(t, sentinel, res.Reason,
		"Evaluate ignored the injected PolicyEvaluator (used default evaluatePolicy)")
}
