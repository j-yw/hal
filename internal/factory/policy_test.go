package factory

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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

	if err := policy.Validate(); err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}

	if !reflect.DeepEqual(policy.AllowedEngines, []string{PolicyEngineCodex, PolicyEngineClaude, PolicyEnginePi}) {
		t.Fatalf("AllowedEngines = %#v, want normalized engine identifiers", policy.AllowedEngines)
	}
	if policy.CleanupBehavior != CleanupBehaviorOnSuccess {
		t.Fatalf("CleanupBehavior = %q, want %q", policy.CleanupBehavior, CleanupBehaviorOnSuccess)
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
`)

	got, err := LoadPolicyConfig(dir)
	if err != nil {
		t.Fatalf("LoadPolicyConfig() unexpected error: %v", err)
	}

	want := FactoryPolicy{
		SandboxRequired:      true,
		AllowedEngines:       []string{PolicyEngineCodex},
		MaxRunAttempts:       2,
		MaxReviewFixAttempts: 3,
		MaxCIFixAttempts:     4,
		VerificationRequired: true,
		PRCreationAllowed:    false,
		MergeAllowed:         false,
		CleanupBehavior:      CleanupBehaviorAlways,
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
	}
	assertFactoryPolicy(t, got, want)
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
