package factory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestDefaultFactoryPolicy(t *testing.T) {
	policy := DefaultFactoryPolicy()

	if policy.SandboxRequired {
		t.Error("SandboxRequired = true, want false")
	}
	if !reflect.DeepEqual(policy.AllowedEngines, SupportedPolicyEngines()) {
		t.Errorf("AllowedEngines = %#v, want %#v", policy.AllowedEngines, SupportedPolicyEngines())
	}
	if policy.MaxRunAttempts != 0 {
		t.Errorf("MaxRunAttempts = %d, want 0", policy.MaxRunAttempts)
	}
	if policy.MaxReviewFixAttempts != 0 {
		t.Errorf("MaxReviewFixAttempts = %d, want 0", policy.MaxReviewFixAttempts)
	}
	if policy.MaxCIFixAttempts != 0 {
		t.Errorf("MaxCIFixAttempts = %d, want 0", policy.MaxCIFixAttempts)
	}
	if policy.VerificationRequired {
		t.Error("VerificationRequired = true, want false")
	}
	if !policy.PRCreationAllowed {
		t.Error("PRCreationAllowed = false, want true")
	}
	if !policy.MergeAllowed {
		t.Error("MergeAllowed = false, want true")
	}
	if policy.CleanupBehavior != CleanupBehaviorPreserve {
		t.Errorf("CleanupBehavior = %q, want %q", policy.CleanupBehavior, CleanupBehaviorPreserve)
	}
	if policy.CIPolicy != CIPolicySkipIfUnavailable {
		t.Errorf("CIPolicy = %q, want %q", policy.CIPolicy, CIPolicySkipIfUnavailable)
	}
	if policy.PublishPolicy != PublishPolicyNone {
		t.Errorf("PublishPolicy = %q, want %q", policy.PublishPolicy, PublishPolicyNone)
	}
	if policy.SecurityReadinessGatePolicyMode != "" {
		t.Errorf("SecurityReadinessGatePolicyMode = %q, want empty default", policy.SecurityReadinessGatePolicyMode)
	}
	if got := policy.EffectiveSecurityReadinessGatePolicyMode(); got != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff {
		t.Errorf("EffectiveSecurityReadinessGatePolicyMode() = %q, want %q", got, sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff)
	}
	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestFactoryPolicyValidateRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*FactoryPolicy)
		wantErr string
	}{
		{
			name: "negative max run attempts",
			mutate: func(policy *FactoryPolicy) {
				policy.MaxRunAttempts = -1
			},
			wantErr: "factory.policy.maxRunAttempts must be greater than or equal to 0",
		},
		{
			name: "negative max review fix attempts",
			mutate: func(policy *FactoryPolicy) {
				policy.MaxReviewFixAttempts = -1
			},
			wantErr: "factory.policy.maxReviewFixAttempts must be greater than or equal to 0",
		},
		{
			name: "negative max ci fix attempts",
			mutate: func(policy *FactoryPolicy) {
				policy.MaxCIFixAttempts = -1
			},
			wantErr: "factory.policy.maxCiFixAttempts must be greater than or equal to 0",
		},
		{
			name: "unsupported engine",
			mutate: func(policy *FactoryPolicy) {
				policy.AllowedEngines = []string{PolicyEngineCodex, "gpt"}
			},
			wantErr: `factory.policy.allowedEngines[1] must be one of claude, codex, pi (got "gpt")`,
		},
		{
			name: "empty engine",
			mutate: func(policy *FactoryPolicy) {
				policy.AllowedEngines = []string{""}
			},
			wantErr: "factory.policy.allowedEngines[0] must not be empty",
		},
		{
			name: "unknown cleanup behavior",
			mutate: func(policy *FactoryPolicy) {
				policy.CleanupBehavior = "delete"
			},
			wantErr: "factory.policy.cleanupBehavior must be one of preserve, on_success, always",
		},
		{
			name: "empty cleanup behavior",
			mutate: func(policy *FactoryPolicy) {
				policy.CleanupBehavior = ""
			},
			wantErr: "factory.policy.cleanupBehavior must be one of preserve, on_success, always",
		},
		{
			name: "unknown ci policy",
			mutate: func(policy *FactoryPolicy) {
				policy.CIPolicy = "best-effort"
			},
			wantErr: "factory.policy.ciPolicy must be one of required, skip-if-unavailable, disabled",
		},
		{
			name: "empty ci policy",
			mutate: func(policy *FactoryPolicy) {
				policy.CIPolicy = ""
			},
			wantErr: "factory.policy.ciPolicy must be one of required, skip-if-unavailable, disabled",
		},
		{
			name: "unknown publish policy",
			mutate: func(policy *FactoryPolicy) {
				policy.PublishPolicy = "release"
			},
			wantErr: "factory.policy.publishPolicy must be one of none, push, pr",
		},
		{
			name: "empty publish policy",
			mutate: func(policy *FactoryPolicy) {
				policy.PublishPolicy = ""
			},
			wantErr: "factory.policy.publishPolicy must be one of none, push, pr",
		},
		{
			name: "unknown security readiness gate policy mode",
			mutate: func(policy *FactoryPolicy) {
				policy.SecurityReadinessGatePolicyMode = sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode("enforce")
			},
			wantErr: "factory.policy.securityReadinessGatePolicyMode must be one of off, advisory, strict",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			policy := DefaultFactoryPolicy()
			tt.mutate(&policy)

			err := policy.Validate()
			if err == nil {
				t.Fatalf("Validate() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestFactoryPolicyValidateNormalizesEnums(t *testing.T) {
	policy := DefaultFactoryPolicy()
	policy.AllowedEngines = []string{" CODEX ", "Claude", "pi"}
	policy.CleanupBehavior = " ON_SUCCESS "
	policy.CIPolicy = " REQUIRED "
	policy.PublishPolicy = " PR "
	policy.SecurityReadinessGatePolicyMode = sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode(" STRICT ")

	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	if !reflect.DeepEqual(policy.AllowedEngines, []string{PolicyEngineCodex, PolicyEngineClaude, PolicyEnginePi}) {
		t.Fatalf("AllowedEngines = %#v, want normalized engine identifiers", policy.AllowedEngines)
	}
	if policy.CleanupBehavior != CleanupBehaviorOnSuccess {
		t.Fatalf("CleanupBehavior = %q, want %q", policy.CleanupBehavior, CleanupBehaviorOnSuccess)
	}
	if policy.CIPolicy != CIPolicyRequired {
		t.Fatalf("CIPolicy = %q, want %q", policy.CIPolicy, CIPolicyRequired)
	}
	if policy.PublishPolicy != PublishPolicyPR {
		t.Fatalf("PublishPolicy = %q, want %q", policy.PublishPolicy, PublishPolicyPR)
	}
	if policy.SecurityReadinessGatePolicyMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict {
		t.Fatalf("SecurityReadinessGatePolicyMode = %q, want %q", policy.SecurityReadinessGatePolicyMode, sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict)
	}
}

func TestFactoryPolicyCIPolicyAndPublishPolicyJSONFields(t *testing.T) {
	policy := DefaultFactoryPolicy()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal default policy: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal default policy: %v", err)
	}
	if got := raw["ciPolicy"]; got != CIPolicySkipIfUnavailable {
		t.Fatalf("ciPolicy = %#v, want %q in %s", got, CIPolicySkipIfUnavailable, data)
	}
	if got := raw["publishPolicy"]; got != PublishPolicyNone {
		t.Fatalf("publishPolicy = %#v, want %q in %s", got, PublishPolicyNone, data)
	}
}

func TestFactoryPolicySecurityReadinessGateModeJSONIsAdditive(t *testing.T) {
	defaultPolicy := DefaultFactoryPolicy()
	defaultData, err := json.Marshal(defaultPolicy)
	if err != nil {
		t.Fatalf("marshal default policy: %v", err)
	}
	var defaultObject map[string]any
	if err := json.Unmarshal(defaultData, &defaultObject); err != nil {
		t.Fatalf("unmarshal default policy: %v", err)
	}
	if _, ok := defaultObject["securityReadinessGatePolicyMode"]; ok {
		t.Fatalf("default policy JSON includes securityReadinessGatePolicyMode: %s", defaultData)
	}

	strictPolicy := DefaultFactoryPolicy()
	strictPolicy.SecurityReadinessGatePolicyMode = sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict
	strictData, err := json.Marshal(strictPolicy)
	if err != nil {
		t.Fatalf("marshal strict policy: %v", err)
	}
	var strictObject map[string]any
	if err := json.Unmarshal(strictData, &strictObject); err != nil {
		t.Fatalf("unmarshal strict policy: %v", err)
	}
	if got := strictObject["securityReadinessGatePolicyMode"]; got != string(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict) {
		t.Fatalf("securityReadinessGatePolicyMode = %#v, want %q in %s", got, sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict, strictData)
	}
}

func TestPhase32DefaultFactoryPolicyRemainsRuntimeAgnostic(t *testing.T) {
	policy := DefaultFactoryPolicy()
	if policy.SandboxRequired {
		t.Fatal("SandboxRequired = true, want Phase 32 Firecracker support to remain opt-in")
	}
	if policy.SecurityReadinessGatePolicyMode != "" {
		t.Fatalf("SecurityReadinessGatePolicyMode = %q, want empty default", policy.SecurityReadinessGatePolicyMode)
	}

	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("Marshal(DefaultFactoryPolicy()) error: %v", err)
	}
	lower := strings.ToLower(string(data))
	for _, marker := range []string{
		"firecracker",
		"microvm",
		"rootless_podman",
		"docker",
		"podman",
		"runtime",
		"isolation",
	} {
		if strings.Contains(lower, marker) {
			t.Fatalf("default factory policy JSON includes runtime-specific marker %q: %s", marker, data)
		}
	}
}

func TestLoadPolicyConfigMissingUsesDefaults(t *testing.T) {
	defaults := DefaultFactoryPolicy()

	t.Run("non-existent directory", func(t *testing.T) {
		got, err := LoadPolicyConfig(filepath.Join(t.TempDir(), "missing"))
		if err != nil {
			t.Fatalf("LoadPolicyConfig() unexpected error: %v", err)
		}
		assertFactoryPolicy(t, got, defaults)
	})

	t.Run("directory without config", func(t *testing.T) {
		got, err := LoadPolicyConfig(t.TempDir())
		if err != nil {
			t.Fatalf("LoadPolicyConfig() unexpected error: %v", err)
		}
		assertFactoryPolicy(t, got, defaults)
	})
}

func TestLoadPolicyConfigMergesMissingFieldsWithDefaults(t *testing.T) {
	dir := t.TempDir()
	writeFactoryConfig(t, dir, `factory:
  policy:
    sandboxRequired: true
    allowedEngines:
      - codex
`)

	got, err := LoadPolicyConfig(dir)
	if err != nil {
		t.Fatalf("LoadPolicyConfig() unexpected error: %v", err)
	}

	want := DefaultFactoryPolicy()
	want.SandboxRequired = true
	want.AllowedEngines = []string{PolicyEngineCodex}
	assertFactoryPolicy(t, got, want)
}

func TestLoadPolicyConfigPreservesExplicitStrictValues(t *testing.T) {
	dir := t.TempDir()
	writeFactoryConfig(t, dir, `factory:
  policy:
    sandboxRequired: true
    allowedEngines:
      - codex
    maxRunAttempts: 2
    maxReviewFixAttempts: 3
    maxCiFixAttempts: 4
    verificationRequired: true
    prCreationAllowed: false
    mergeAllowed: false
    cleanupBehavior: always
    ciPolicy: required
    publishPolicy: pr
    securityReadinessGatePolicyMode: strict
`)

	got, err := LoadPolicyConfig(dir)
	if err != nil {
		t.Fatalf("LoadPolicyConfig() unexpected error: %v", err)
	}

	want := FactoryPolicy{
		SandboxRequired:                 true,
		AllowedEngines:                  []string{PolicyEngineCodex},
		MaxRunAttempts:                  2,
		MaxReviewFixAttempts:            3,
		MaxCIFixAttempts:                4,
		VerificationRequired:            true,
		PRCreationAllowed:               false,
		MergeAllowed:                    false,
		CleanupBehavior:                 CleanupBehaviorAlways,
		CIPolicy:                        CIPolicyRequired,
		PublishPolicy:                   PublishPolicyPR,
		SecurityReadinessGatePolicyMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
	}
	assertFactoryPolicy(t, got, want)
}

func TestLoadPolicyConfigPreservesExplicitZeroAndEmptyValues(t *testing.T) {
	dir := t.TempDir()
	writeFactoryConfig(t, dir, `factory:
  policy:
    sandboxRequired: false
    allowedEngines: []
    maxRunAttempts: 0
    maxReviewFixAttempts: 0
    maxCiFixAttempts: 0
    verificationRequired: false
    prCreationAllowed: false
    mergeAllowed: false
    cleanupBehavior: preserve
    ciPolicy: disabled
    publishPolicy: none
    securityReadinessGatePolicyMode: ""
`)

	got, err := LoadPolicyConfig(dir)
	if err != nil {
		t.Fatalf("LoadPolicyConfig() unexpected error: %v", err)
	}

	want := FactoryPolicy{
		SandboxRequired:      false,
		AllowedEngines:       []string{},
		MaxRunAttempts:       0,
		MaxReviewFixAttempts: 0,
		MaxCIFixAttempts:     0,
		VerificationRequired: false,
		PRCreationAllowed:    false,
		MergeAllowed:         false,
		CleanupBehavior:      CleanupBehaviorPreserve,
		CIPolicy:             CIPolicyDisabled,
		PublishPolicy:        PublishPolicyNone,
	}
	assertFactoryPolicy(t, got, want)
}

func TestLoadPolicyConfigNormalizesCIPolicyAndPublishPolicy(t *testing.T) {
	dir := t.TempDir()
	writeFactoryConfig(t, dir, `factory:
  policy:
    ciPolicy: " Required "
    publishPolicy: " Push "
`)

	got, err := LoadPolicyConfig(dir)
	if err != nil {
		t.Fatalf("LoadPolicyConfig() unexpected error: %v", err)
	}

	if got.CIPolicy != CIPolicyRequired {
		t.Fatalf("CIPolicy = %q, want %q", got.CIPolicy, CIPolicyRequired)
	}
	if got.PublishPolicy != PublishPolicyPush {
		t.Fatalf("PublishPolicy = %q, want %q", got.PublishPolicy, PublishPolicyPush)
	}
}

func TestLoadPolicyConfigNormalizesSecurityReadinessGatePolicyMode(t *testing.T) {
	dir := t.TempDir()
	writeFactoryConfig(t, dir, `factory:
  policy:
    securityReadinessGatePolicyMode: " Advisory "
`)

	got, err := LoadPolicyConfig(dir)
	if err != nil {
		t.Fatalf("LoadPolicyConfig() unexpected error: %v", err)
	}

	if got.SecurityReadinessGatePolicyMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory {
		t.Fatalf("SecurityReadinessGatePolicyMode = %q, want %q", got.SecurityReadinessGatePolicyMode, sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory)
	}
	if got.EffectiveSecurityReadinessGatePolicyMode() != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory {
		t.Fatalf("EffectiveSecurityReadinessGatePolicyMode() = %q, want %q", got.EffectiveSecurityReadinessGatePolicyMode(), sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory)
	}
}

func TestLoadPolicyConfigRejectsInvalidConfiguredValues(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "negative attempt limit",
			yaml: `factory:
  policy:
    maxRunAttempts: -1
`,
			wantErr: "factory.policy.maxRunAttempts",
		},
		{
			name: "unsupported engine",
			yaml: `factory:
  policy:
    allowedEngines:
      - codex
      - gpt
`,
			wantErr: "factory.policy.allowedEngines[1]",
		},
		{
			name: "empty cleanup behavior",
			yaml: `factory:
  policy:
    cleanupBehavior: ""
`,
			wantErr: "factory.policy.cleanupBehavior",
		},
		{
			name: "unknown ci policy",
			yaml: `factory:
  policy:
    ciPolicy: optional
`,
			wantErr: "factory.policy.ciPolicy",
		},
		{
			name: "unknown publish policy",
			yaml: `factory:
  policy:
    publishPolicy: tag
`,
			wantErr: "factory.policy.publishPolicy",
		},
		{
			name: "unknown security readiness gate policy mode",
			yaml: `factory:
  policy:
    securityReadinessGatePolicyMode: enforcing
`,
			wantErr: "factory.policy.securityReadinessGatePolicyMode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			writeFactoryConfig(t, dir, tt.yaml)

			_, err := LoadPolicyConfig(dir)
			if err == nil {
				t.Fatal("LoadPolicyConfig() error = nil, want validation error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("LoadPolicyConfig() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func writeFactoryConfig(t *testing.T, dir, content string) {
	t.Helper()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(content), 0o644); err != nil {
		t.Fatalf("write config.yaml: %v", err)
	}
}

func assertFactoryPolicy(t *testing.T, got *FactoryPolicy, want FactoryPolicy) {
	t.Helper()
	if got == nil {
		t.Fatal("policy = nil, want non-nil")
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("policy = %#v, want %#v", *got, want)
	}
}
