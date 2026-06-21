package factory

import (
	"fmt"
	"strings"
)

const (
	PolicyEngineClaude = "claude"
	PolicyEngineCodex  = "codex"
	PolicyEnginePi     = "pi"

	CleanupBehaviorPreserve  = "preserve"
	CleanupBehaviorOnSuccess = "on_success"
	CleanupBehaviorAlways    = "always"
)

// FactoryPolicy captures durable autonomy boundaries for factory-created runs.
// A zero attempt limit means there is no policy cap for that attempt category.
type FactoryPolicy struct {
	SandboxRequired      bool     `json:"sandboxRequired" yaml:"sandboxRequired"`
	AllowedEngines       []string `json:"allowedEngines" yaml:"allowedEngines"`
	MaxRunAttempts       int      `json:"maxRunAttempts" yaml:"maxRunAttempts"`
	MaxReviewFixAttempts int      `json:"maxReviewFixAttempts" yaml:"maxReviewFixAttempts"`
	MaxCIFixAttempts     int      `json:"maxCiFixAttempts" yaml:"maxCiFixAttempts"`
	VerificationRequired bool     `json:"verificationRequired" yaml:"verificationRequired"`
	PRCreationAllowed    bool     `json:"prCreationAllowed" yaml:"prCreationAllowed"`
	MergeAllowed         bool     `json:"mergeAllowed" yaml:"mergeAllowed"`
	CleanupBehavior      string   `json:"cleanupBehavior" yaml:"cleanupBehavior"`
}

// SupportedPolicyEngines returns the engine identifiers policy validation accepts.
func SupportedPolicyEngines() []string {
	return []string{PolicyEngineClaude, PolicyEngineCodex, PolicyEnginePi}
}

// SupportedCleanupBehaviors returns the cleanup behavior identifiers policy
// validation accepts.
func SupportedCleanupBehaviors() []string {
	return []string{CleanupBehaviorPreserve, CleanupBehaviorOnSuccess, CleanupBehaviorAlways}
}

// DefaultFactoryPolicy returns conservative defaults that preserve current
// local-first factory behavior.
func DefaultFactoryPolicy() FactoryPolicy {
	return FactoryPolicy{
		SandboxRequired:      false,
		AllowedEngines:       SupportedPolicyEngines(),
		MaxRunAttempts:       0,
		MaxReviewFixAttempts: 0,
		MaxCIFixAttempts:     0,
		VerificationRequired: false,
		PRCreationAllowed:    true,
		MergeAllowed:         true,
		CleanupBehavior:      CleanupBehaviorPreserve,
	}
}

// Validate normalizes policy enum values and rejects unsupported boundaries.
func (p *FactoryPolicy) Validate() error {
	if p.MaxRunAttempts < 0 {
		return fmt.Errorf("factory.policy.maxRunAttempts must be greater than or equal to 0")
	}
	if p.MaxReviewFixAttempts < 0 {
		return fmt.Errorf("factory.policy.maxReviewFixAttempts must be greater than or equal to 0")
	}
	if p.MaxCIFixAttempts < 0 {
		return fmt.Errorf("factory.policy.maxCiFixAttempts must be greater than or equal to 0")
	}

	for i, engineName := range p.AllowedEngines {
		normalized := strings.ToLower(strings.TrimSpace(engineName))
		if normalized == "" {
			return fmt.Errorf("factory.policy.allowedEngines[%d] must not be empty", i)
		}
		if !containsString(SupportedPolicyEngines(), normalized) {
			return fmt.Errorf("factory.policy.allowedEngines[%d] must be one of %s (got %q)", i, strings.Join(SupportedPolicyEngines(), ", "), engineName)
		}
		p.AllowedEngines[i] = normalized
	}

	cleanupBehavior := strings.ToLower(strings.TrimSpace(p.CleanupBehavior))
	if !containsString(SupportedCleanupBehaviors(), cleanupBehavior) {
		return fmt.Errorf("factory.policy.cleanupBehavior must be one of %s", strings.Join(SupportedCleanupBehaviors(), ", "))
	}
	p.CleanupBehavior = cleanupBehavior

	return nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
