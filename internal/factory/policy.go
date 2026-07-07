package factory

import (
	"fmt"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
)

const (
	PolicyEngineClaude = "claude"
	PolicyEngineCodex  = "codex"
	PolicyEnginePi     = "pi"

	CleanupBehaviorPreserve  = "preserve"
	CleanupBehaviorOnSuccess = "on_success"
	CleanupBehaviorAlways    = "always"

	CIPolicyRequired          = "required"
	CIPolicySkipIfUnavailable = "skip-if-unavailable"
	CIPolicyDisabled          = "disabled"

	PublishPolicyNone = "none"
	PublishPolicyPush = "push"
	PublishPolicyPR   = "pr"
)

var supportedSecurityReadinessGatePolicyModes = []sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode{
	sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff,
	sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory,
	sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
}

// FactoryPolicy captures durable autonomy boundaries for factory-created runs.
// A zero attempt limit means there is no policy cap for that attempt category.
type FactoryPolicy struct {
	SandboxRequired                 bool                                                     `json:"sandboxRequired" yaml:"sandboxRequired"`
	AllowedEngines                  []string                                                 `json:"allowedEngines" yaml:"allowedEngines"`
	MaxRunAttempts                  int                                                      `json:"maxRunAttempts" yaml:"maxRunAttempts"`
	MaxReviewFixAttempts            int                                                      `json:"maxReviewFixAttempts" yaml:"maxReviewFixAttempts"`
	MaxCIFixAttempts                int                                                      `json:"maxCiFixAttempts" yaml:"maxCiFixAttempts"`
	VerificationRequired            bool                                                     `json:"verificationRequired" yaml:"verificationRequired"`
	PRCreationAllowed               bool                                                     `json:"prCreationAllowed" yaml:"prCreationAllowed"`
	MergeAllowed                    bool                                                     `json:"mergeAllowed" yaml:"mergeAllowed"` // gates non-dry-run merge automation
	CleanupBehavior                 string                                                   `json:"cleanupBehavior" yaml:"cleanupBehavior"`
	CIPolicy                        string                                                   `json:"ciPolicy" yaml:"ciPolicy"`
	PublishPolicy                   string                                                   `json:"publishPolicy" yaml:"publishPolicy"`
	SecurityReadinessGatePolicyMode sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode `json:"securityReadinessGatePolicyMode,omitempty" yaml:"securityReadinessGatePolicyMode,omitempty"`
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

// SupportedCIPolicies returns the CI policy identifiers policy validation
// accepts.
func SupportedCIPolicies() []string {
	return []string{CIPolicyRequired, CIPolicySkipIfUnavailable, CIPolicyDisabled}
}

// SupportedPublishPolicies returns the publish policy identifiers policy
// validation accepts.
func SupportedPublishPolicies() []string {
	return []string{PublishPolicyNone, PublishPolicyPush, PublishPolicyPR}
}

// SupportedSecurityReadinessGatePolicyModes returns the readiness gate mode
// identifiers policy validation accepts.
func SupportedSecurityReadinessGatePolicyModes() []sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode {
	return append([]sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode(nil), supportedSecurityReadinessGatePolicyModes...)
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
		CIPolicy:             CIPolicySkipIfUnavailable,
		PublishPolicy:        PublishPolicyNone,
	}
}

// EffectiveSecurityReadinessGatePolicyMode returns the mode later command
// wiring should use. Missing config is equivalent to the existing off behavior
// but remains empty on the durable policy snapshot for backwards-compatible
// omitempty persistence.
func (p FactoryPolicy) EffectiveSecurityReadinessGatePolicyMode() sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode {
	mode := strings.ToLower(strings.TrimSpace(string(p.SecurityReadinessGatePolicyMode)))
	if mode == "" {
		return sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff
	}
	for _, supported := range supportedSecurityReadinessGatePolicyModes {
		if mode == string(supported) {
			return supported
		}
	}
	return sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff
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

	ciPolicy := strings.ToLower(strings.TrimSpace(p.CIPolicy))
	if !containsString(SupportedCIPolicies(), ciPolicy) {
		return fmt.Errorf("factory.policy.ciPolicy must be one of %s", strings.Join(SupportedCIPolicies(), ", "))
	}
	p.CIPolicy = ciPolicy

	publishPolicy := strings.ToLower(strings.TrimSpace(p.PublishPolicy))
	if !containsString(SupportedPublishPolicies(), publishPolicy) {
		return fmt.Errorf("factory.policy.publishPolicy must be one of %s", strings.Join(SupportedPublishPolicies(), ", "))
	}
	p.PublishPolicy = publishPolicy

	readinessGateMode := strings.ToLower(strings.TrimSpace(string(p.SecurityReadinessGatePolicyMode)))
	if readinessGateMode != "" {
		if !containsSecurityReadinessGatePolicyMode(supportedSecurityReadinessGatePolicyModes, readinessGateMode) {
			return fmt.Errorf("factory.policy.securityReadinessGatePolicyMode must be one of %s", strings.Join(supportedSecurityReadinessGatePolicyModeStrings(), ", "))
		}
		p.SecurityReadinessGatePolicyMode = sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode(readinessGateMode)
	}

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

func containsSecurityReadinessGatePolicyMode(values []sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode, value string) bool {
	for _, candidate := range values {
		if string(candidate) == value {
			return true
		}
	}
	return false
}

func supportedSecurityReadinessGatePolicyModeStrings() []string {
	modes := SupportedSecurityReadinessGatePolicyModes()
	values := make([]string, len(modes))
	for i, mode := range modes {
		values[i] = string(mode)
	}
	return values
}
