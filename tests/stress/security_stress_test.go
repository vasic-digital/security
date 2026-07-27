package stress

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"digital.vasic.security/pkg/content"
	"digital.vasic.security/pkg/guardrails"
	"digital.vasic.security/pkg/pii"
	"digital.vasic.security/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuardrailsEngine_ConcurrentChecks_Stress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode") // SKIP-OK: #short-mode
	}

	engine := guardrails.NewEngine(guardrails.DefaultConfig())
	engine.AddRule(guardrails.NewMaxLengthRule(10000))
	patterns, err := guardrails.NewForbiddenPatternsRule(map[string]string{
		"script": `<script`,
	})
	require.NoError(t, err)
	engine.AddRule(patterns)

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			input := fmt.Sprintf("Content from goroutine %d with safe text", idx)
			result := engine.Check(input)
			assert.True(t, result.Passed,
				"safe content should pass in goroutine %d", idx)
		}(i)
	}
	wg.Wait()
}

func TestGuardrailsEngine_ConcurrentAddAndCheck_Stress(t *testing.T) {
	// bluff-scan: no-assert-ok (concurrency test — go test -race catches data races; absence of panic == correctness)
	if testing.Short() {
		t.Skip("skipping stress test in short mode") // SKIP-OK: #short-mode
	}

	engine := guardrails.NewEngine(guardrails.DefaultConfig())

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half add rules, half check content
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			engine.AddRule(guardrails.NewMaxLengthRule(1000 + idx))
		}(i)
		go func(idx int) {
			defer wg.Done()
			content := fmt.Sprintf("Check %d", idx)
			_ = engine.Check(content)
		}(i)
	}
	wg.Wait()
}

func TestPIIRedactor_ConcurrentRedaction_Stress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode") // SKIP-OK: #short-mode
	}

	redactor := pii.NewRedactor(pii.DefaultConfig())

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			input := fmt.Sprintf(
				"User %d email: user%d@test.com phone: (555) %03d-4567",
				idx, idx, idx%1000,
			)
			redacted, matches := redactor.Redact(input)
			assert.True(t, len(matches) > 0,
				"should detect PII in goroutine %d", idx)
			assert.NotContains(t, redacted,
				fmt.Sprintf("user%d@test.com", idx))
		}(i)
	}
	wg.Wait()
}

func TestContentFilterChain_ConcurrentChecks_Stress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode") // SKIP-OK: #short-mode
	}

	chain := content.NewChainFilter(
		content.NewLengthFilter(1, 10000),
		content.NewKeywordFilter([]string{"blocked"}, false),
	)

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			input := fmt.Sprintf("Message number %d from concurrent test", idx)
			result, err := chain.Check(input)
			assert.NoError(t, err)
			assert.True(t, result.Allowed,
				"safe content should pass in goroutine %d", idx)
		}(i)
	}
	wg.Wait()
}

func TestPolicyEnforcer_ConcurrentEvaluation_Stress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode") // SKIP-OK: #short-mode
	}

	enforcer := policy.NewEnforcer()
	err := enforcer.LoadPolicy(&policy.Policy{
		Name: "concurrent-test",
		Rules: []policy.Rule{
			{
				Name: "allow-internal",
				Conditions: []policy.Condition{
					{
						Field:    "source",
						Operator: policy.OperatorEquals,
						Value:    "internal",
					},
				},
				Decision: policy.DecisionAllow,
			},
		},
		DefaultDecision: policy.DecisionDeny,
	})
	require.NoError(t, err)

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			source := "internal"
			if idx%2 == 0 {
				source = "external"
			}
			result, err := enforcer.Evaluate(
				context.Background(),
				"concurrent-test",
				&policy.EvaluationContext{
					Fields: map[string]string{"source": source},
				},
			)
			assert.NoError(t, err)
			if source == "internal" {
				assert.Equal(t, policy.DecisionAllow, result.Decision)
			} else {
				assert.Equal(t, policy.DecisionDeny, result.Decision)
			}
		}(i)
	}
	wg.Wait()
}

func TestPolicyEnforcer_ConcurrentLoadAndEvaluate_Stress(t *testing.T) {
	// bluff-scan: no-assert-ok (concurrency test — go test -race catches data races; absence of panic == correctness)
	if testing.Short() {
		t.Skip("skipping stress test in short mode") // SKIP-OK: #short-mode
	}

	enforcer := policy.NewEnforcer()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half load policies, half evaluate
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			_ = enforcer.LoadPolicy(&policy.Policy{
				Name: fmt.Sprintf("policy-%d", idx),
				Rules: []policy.Rule{
					{
						Name: fmt.Sprintf("rule-%d", idx),
						Conditions: []policy.Condition{
							{
								Field:    "key",
								Operator: policy.OperatorEquals,
								Value:    fmt.Sprintf("val-%d", idx),
							},
						},
						Decision: policy.DecisionAllow,
					},
				},
				DefaultDecision: policy.DecisionDeny,
			})
		}(i)
		go func(idx int) {
			defer wg.Done()
			_, _ = enforcer.EvaluateAll(
				context.Background(),
				&policy.EvaluationContext{
					Fields: map[string]string{
						"key": fmt.Sprintf("val-%d", idx),
					},
				},
			)
		}(i)
	}
	wg.Wait()
}
