package rules

import (
	"github.com/rtvkiz/docker-sentinel/pkg/config"
	"github.com/rtvkiz/docker-sentinel/pkg/interceptor"
	"github.com/rtvkiz/docker-sentinel/pkg/policy"
)

// Engine is the rules validation engine
type Engine struct {
	cfg       *config.Config
	policyMgr *policy.Manager
	evaluator *policy.Evaluator
}

// ValidationResult contains the result of validating a Docker command
type ValidationResult struct {
	Allowed     bool
	Score       int
	Risks       []Risk
	Warnings    []Warning
	Mitigations []string
}

// Risk represents a security risk found during validation
type Risk struct {
	Level       string
	Category    string
	Description string
}

// Warning represents a non-blocking warning
type Warning struct {
	Message string
}

// NewEngine creates a new rules engine
func NewEngine(cfg *config.Config) *Engine {
	policyMgr := policy.NewManager(cfg.PoliciesDir)
	policyMgr.Init()

	// Set the active policy from config
	if cfg.ActivePolicy != "" {
		if err := policyMgr.SetActive(cfg.ActivePolicy); err != nil {
			// Fall back to default if the configured policy doesn't exist
			policyMgr.SetActive("default")
		}
	}

	return &Engine{
		cfg:       cfg,
		policyMgr: policyMgr,
	}
}

// Validate validates a Docker command against the security policy
func (e *Engine) Validate(cmd *interceptor.DockerCommand) *ValidationResult {
	// Load active policy
	pol, err := e.policyMgr.GetActive()
	if err != nil {
		pol = policy.Default()
	}

	// Create evaluator
	evaluator, err := policy.NewEvaluator(pol, "")
	if err != nil {
		return &ValidationResult{
			Allowed: false,
			Score:   100,
			Risks: []Risk{{
				Level:       "critical",
				Category:    "system",
				Description: "Failed to create policy evaluator: " + err.Error(),
			}},
		}
	}

	// Evaluate command
	evalResult, err := evaluator.Evaluate(cmd)
	if err != nil {
		return &ValidationResult{
			Allowed: false,
			Score:   100,
			Risks: []Risk{{
				Level:       "critical",
				Category:    "system",
				Description: "Failed to evaluate command: " + err.Error(),
			}},
		}
	}

	// Convert evaluation result to validation result
	result := &ValidationResult{
		Allowed:     evalResult.Allowed,
		Score:       evalResult.Score,
		Mitigations: evalResult.Mitigations,
	}

	// Convert violations to risks
	for _, v := range evalResult.Violations {
		result.Risks = append(result.Risks, Risk{
			Level:       v.Severity,
			Category:    v.Category,
			Description: v.Message,
		})
	}

	// Convert warnings
	for _, w := range evalResult.Warnings {
		result.Warnings = append(result.Warnings, Warning{
			Message: w.Message,
		})
	}

	return result
}
