package factory

import (
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
