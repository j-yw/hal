package livegate

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestEvaluateGateMissingBuildTagReturnsSkipSafePreflightResult(t *testing.T) {
	result := EvaluateGate(GateEvaluationInput{
		Gate:                  firecrackerLiveGateForEvaluation(),
		PresentEnvVars:        []EnvVarName{EnvVarFirecrackerLive},
		AvailableCapabilities: []CapabilityID{CapabilityFirecrackerMicroVM},
	})

	if result.CanRunLiveAction() {
		t.Fatal("CanRunLiveAction() = true, want false when required build tag is absent")
	}
	if !result.ShouldSkipLiveAction() {
		t.Fatal("ShouldSkipLiveAction() = false, want true when required build tag is absent")
	}
	if result.Status != RequirementStatusSkipped {
		t.Fatalf("Status = %q, want %q", result.Status, RequirementStatusSkipped)
	}
	if result.SkipReason != SkipReasonMissingBuildTag {
		t.Fatalf("SkipReason = %q, want %q", result.SkipReason, SkipReasonMissingBuildTag)
	}

	requirement := requireRequirementForBuildTag(t, result.Requirements, BuildTagFirecrackerLive)
	if requirement.Status != RequirementStatusMissing || requirement.ReasonCode != SkipReasonMissingBuildTag {
		t.Fatalf("build tag requirement = %#v, want missing with missing_build_tag reason", requirement)
	}
	if result.Remediation == nil {
		t.Fatal("Remediation = nil, want safe build-tag remediation")
	}
	if !reflect.DeepEqual(result.Remediation.BuildTags, []BuildTagName{BuildTagFirecrackerLive}) {
		t.Fatalf("Remediation.BuildTags = %#v, want firecracker build tag", result.Remediation.BuildTags)
	}
	if !reflect.DeepEqual(result.Remediation.CommandTemplates, []RemediationCommandTemplate{RemediationTemplateGoTestBuildTags}) {
		t.Fatalf("Remediation.CommandTemplates = %#v, want build-tag go test template", result.Remediation.CommandTemplates)
	}
}

func TestEvaluateGateMissingEnvGateUsesExplicitEnvironmentPresenceOnly(t *testing.T) {
	t.Setenv(string(EnvVarFirecrackerLive), "secret-live-env-value")

	result := EvaluateGate(GateEvaluationInput{
		Gate:                  firecrackerLiveGateForEvaluation(),
		EnabledBuildTags:      []BuildTagName{BuildTagFirecrackerLive},
		AvailableCapabilities: []CapabilityID{CapabilityFirecrackerMicroVM},
	})

	if result.CanRunLiveAction() {
		t.Fatal("CanRunLiveAction() = true, want false when explicit env presence omits marker")
	}
	if result.SkipReason != SkipReasonMissingEnvVar {
		t.Fatalf("SkipReason = %q, want %q", result.SkipReason, SkipReasonMissingEnvVar)
	}
	requirement := requireRequirementForEnvVar(t, result.Requirements, EnvVarFirecrackerLive)
	if requirement.Status != RequirementStatusMissing || requirement.ReasonCode != SkipReasonMissingEnvVar {
		t.Fatalf("env requirement = %#v, want missing with missing_env_var reason", requirement)
	}
	if result.Remediation == nil {
		t.Fatal("Remediation = nil, want safe env remediation")
	}
	if !reflect.DeepEqual(result.Remediation.EnvVars, []EnvVarName{EnvVarFirecrackerLive}) {
		t.Fatalf("Remediation.EnvVars = %#v, want firecracker env var", result.Remediation.EnvVars)
	}
	if !reflect.DeepEqual(result.Remediation.CommandTemplates, []RemediationCommandTemplate{RemediationTemplateGoTestEnvVars}) {
		t.Fatalf("Remediation.CommandTemplates = %#v, want env go test template", result.Remediation.CommandTemplates)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error: %v", err)
	}
	if strings.Contains(string(encoded), "secret-live-env-value") {
		t.Fatalf("preflight result leaked real env value: %s", encoded)
	}
}

func TestEvaluateGateUnsupportedCapabilityReturnsUnavailablePreflightResult(t *testing.T) {
	result := EvaluateGate(GateEvaluationInput{
		Gate:             firecrackerLiveGateForEvaluation(),
		EnabledBuildTags: []BuildTagName{BuildTagFirecrackerLive},
		PresentEnvVars:   []EnvVarName{EnvVarFirecrackerLive},
	})

	if result.CanRunLiveAction() {
		t.Fatal("CanRunLiveAction() = true, want false when capability is unavailable")
	}
	if result.SkipReason != SkipReasonCapabilityUnavailable {
		t.Fatalf("SkipReason = %q, want %q", result.SkipReason, SkipReasonCapabilityUnavailable)
	}
	requirement := requireCapabilityRequirement(t, result.CapabilityRequirements, CapabilityFirecrackerMicroVM)
	if requirement.Status != RequirementStatusUnavailable || requirement.ReasonCode != SkipReasonCapabilityUnavailable {
		t.Fatalf("capability requirement = %#v, want unavailable with capability_unavailable reason", requirement)
	}
	if result.Remediation == nil {
		t.Fatal("Remediation = nil, want safe capability remediation")
	}
	if !reflect.DeepEqual(result.Remediation.Capabilities, []CapabilityID{CapabilityFirecrackerMicroVM}) {
		t.Fatalf("Remediation.Capabilities = %#v, want firecracker capability", result.Remediation.Capabilities)
	}
	if !reflect.DeepEqual(result.Remediation.CommandLabels, []RemediationCommandLabel{RemediationInstallCapability}) {
		t.Fatalf("Remediation.CommandLabels = %#v, want install capability label", result.Remediation.CommandLabels)
	}
}

func TestEvaluateGateSatisfiedPrerequisitesAllowLiveAction(t *testing.T) {
	result := PreflightGate(GateEvaluationInput{
		Gate:                  firecrackerLiveGateForEvaluation(),
		EnabledBuildTags:      []BuildTagName{BuildTagFirecrackerLive},
		PresentEnvVars:        []EnvVarName{EnvVarFirecrackerLive},
		AvailableCapabilities: []CapabilityID{CapabilityFirecrackerMicroVM},
	})

	if !result.CanRunLiveAction() {
		t.Fatal("CanRunLiveAction() = false, want true when prerequisites are satisfied")
	}
	if result.ShouldSkipLiveAction() {
		t.Fatal("ShouldSkipLiveAction() = true, want false when prerequisites are satisfied")
	}
	if result.Status != RequirementStatusSatisfied {
		t.Fatalf("Status = %q, want %q", result.Status, RequirementStatusSatisfied)
	}
	if result.SkipReason != "" {
		t.Fatalf("SkipReason = %q, want empty", result.SkipReason)
	}
	if result.Remediation != nil {
		t.Fatalf("Remediation = %#v, want nil for satisfied prerequisites", result.Remediation)
	}

	for _, requirement := range result.Requirements {
		if requirement.Status != RequirementStatusSatisfied || requirement.ReasonCode != "" {
			t.Fatalf("requirement = %#v, want satisfied without reason", requirement)
		}
	}
	for _, requirement := range result.CapabilityRequirements {
		if requirement.Status != RequirementStatusSatisfied || requirement.ReasonCode != "" {
			t.Fatalf("capability requirement = %#v, want satisfied without reason", requirement)
		}
	}
}

func TestGatePreflightResultJSONRedactsUnsafeDynamicValues(t *testing.T) {
	result := EvaluateGate(GateEvaluationInput{
		Gate: Gate{
			ID:       GateID("https://gate.internal.example.com/live?token=secret"),
			Category: GateCategory(" FIRECRACKER "),
			BuildTags: []BuildTagName{
				BuildTagFirecrackerLive,
				BuildTagName("-tags=firecracker_live"),
				BuildTagName("/Users/alice/.hal/tags"),
			},
			EnvVars: []EnvVarName{
				EnvVarFirecrackerLive,
				EnvVarName("HAL_FIRECRACKER_LIVE=secret-live-env-value"),
				EnvVarName("Authorization: Bearer ghp_secret"),
				EnvVarName("CREDENTIAL_VALUE=credential-value"),
				EnvVarName("HTTP_PROXY=http://proxy.internal:8080"),
			},
			Capabilities: []CapabilityID{
				CapabilityFirecrackerMicroVM,
				CapabilityID("http://127.0.0.1:8080/firecracker"),
				CapabilityID("/tmp/firecracker.sock"),
				CapabilityID("api.internal.example.com"),
				CapabilityID("providerConfig=/Users/alice/.hal/provider.json"),
				CapabilityID("iptables -A OUTPUT -j DROP"),
			},
			Remediation: &RemediationMetadata{
				CommandTemplates: []RemediationCommandTemplate{
					RemediationTemplateGoTestBuildTags,
					RemediationCommandTemplate("HAL_FIRECRACKER_LIVE=secret-live-env-value go test --api-sock /tmp/fc.sock"),
				},
			},
		},
		EnabledBuildTags: []BuildTagName{
			BuildTagName("-tags=firecracker_live"),
			BuildTagName("/tmp/build-tags"),
		},
		PresentEnvVars: []EnvVarName{
			EnvVarName("HAL_FIRECRACKER_LIVE=secret-live-env-value"),
		},
		AvailableCapabilities: []CapabilityID{
			CapabilityID("firecracker --api-sock /tmp/fc.sock"),
			CapabilityID("http://api.internal.example.com/firecracker"),
			CapabilityID("providerConfig=/Users/alice/.hal/provider.json"),
			CapabilityID("iptables -A OUTPUT -j DROP"),
		},
	})

	if result.CanRunLiveAction() {
		t.Fatal("CanRunLiveAction() = true, want unsafe explicit inputs to be ignored")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error: %v", err)
	}
	for _, unsafe := range []string{
		"secret-live-env-value",
		"ghp_",
		"Bearer",
		"Authorization",
		"http://",
		"https://",
		"127.0.0.1",
		"gate.internal.example.com",
		"api.internal.example.com",
		"/tmp",
		"/Users/alice",
		"firecracker.sock",
		"--api-sock",
		"providerConfig",
		"credential-value",
		"proxy.internal",
		"iptables",
	} {
		if strings.Contains(string(encoded), unsafe) {
			t.Fatalf("preflight result leaked unsafe fragment %q in %s", unsafe, encoded)
		}
	}

	got := mustMarshalLiveGateObject(t, result)
	assertLiveGateObjectKeys(t, got, []string{
		"actionAllowed",
		"capabilityRequirements",
		"category",
		"remediation",
		"requirements",
		"skipReason",
		"status",
	})
	remediation := requireLiveGateObject(t, got["remediation"])
	assertLiveGateObjectKeys(t, remediation, []string{"reasonCode", "buildTags", "envVars", "capabilities", "commandLabels", "commandTemplates"})
	assertLiveGateStringArray(t, remediation["commandTemplates"], []string{"env {{env_vars}}=<set> go test -tags={{build_tags}} ./..."})
}

func TestGatePreflightResultMarshalSanitizesCallerProvidedUnsafeMetadata(t *testing.T) {
	result := GatePreflightResult{
		GateID:        GateID("https://gate.internal.example.com/live?token=secret"),
		Category:      GateCategoryFirecracker,
		ActionAllowed: true,
		Status:        RequirementStatusSatisfied,
		SkipReason:    SkipReasonMissingEnvVar,
		Requirements: []Requirement{
			{
				Status:     RequirementStatusMissing,
				BuildTag:   BuildTagName("-tags=firecracker_live"),
				EnvVar:     EnvVarName("HAL_FIRECRACKER_LIVE=secret-live-env-value"),
				Capability: CapabilityID("http://api.internal.example.com/firecracker"),
				ReasonCode: SkipReasonMissingEnvVar,
			},
		},
		CapabilityRequirements: []CapabilityRequirement{
			{
				ID:         CapabilityID("providerConfig=/Users/alice/.hal/provider.json"),
				Status:     RequirementStatusUnavailable,
				ReasonCode: SkipReasonCapabilityUnavailable,
			},
		},
		Remediation: &RemediationMetadata{
			ReasonCode: SkipReasonMissingEnvVar,
			BuildTags: []BuildTagName{
				BuildTagFirecrackerLive,
				BuildTagName("/Users/alice/.hal/tags"),
			},
			EnvVars: []EnvVarName{
				EnvVarFirecrackerLive,
				EnvVarName("HTTP_PROXY=http://proxy.internal:8080"),
			},
			Capabilities: []CapabilityID{
				CapabilityFirecrackerMicroVM,
				CapabilityID("iptables -A OUTPUT -j DROP"),
			},
			CommandLabels: []RemediationCommandLabel{
				RemediationEnableBuildTag,
				RemediationCommandLabel("curl http://127.0.0.1:8080"),
			},
			CommandTemplates: []RemediationCommandTemplate{
				RemediationTemplateGoTestBuildTags,
				RemediationCommandTemplate("HAL_FIRECRACKER_LIVE=secret-live-env-value go test --api-sock /tmp/fc.sock"),
			},
		},
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error: %v", err)
	}
	if strings.Contains(string(encoded), `"actionAllowed":true`) {
		t.Fatalf("sanitized preflight result allowed action despite skip metadata: %s", encoded)
	}
	for _, unsafe := range []string{
		"secret-live-env-value",
		"http://",
		"https://",
		"127.0.0.1",
		"gate.internal.example.com",
		"api.internal.example.com",
		"/tmp",
		"/Users/alice",
		"--api-sock",
		"providerConfig",
		"proxy.internal",
		"iptables",
		"curl ",
	} {
		if strings.Contains(string(encoded), unsafe) {
			t.Fatalf("sanitized preflight result leaked unsafe fragment %q in %s", unsafe, encoded)
		}
	}
}

func firecrackerLiveGateForEvaluation() Gate {
	return Gate{
		ID:           GateID("firecracker-live"),
		Category:     GateCategoryFirecracker,
		BuildTags:    []BuildTagName{BuildTagFirecrackerLive},
		EnvVars:      []EnvVarName{EnvVarFirecrackerLive},
		Capabilities: []CapabilityID{CapabilityFirecrackerMicroVM},
	}
}

func requireRequirementForBuildTag(t *testing.T, requirements []Requirement, buildTag BuildTagName) Requirement {
	t.Helper()

	for _, requirement := range requirements {
		if requirement.BuildTag == buildTag {
			return requirement
		}
	}
	t.Fatalf("requirements = %#v, want build tag %q", requirements, buildTag)
	return Requirement{}
}

func requireRequirementForEnvVar(t *testing.T, requirements []Requirement, envVar EnvVarName) Requirement {
	t.Helper()

	for _, requirement := range requirements {
		if requirement.EnvVar == envVar {
			return requirement
		}
	}
	t.Fatalf("requirements = %#v, want env var %q", requirements, envVar)
	return Requirement{}
}

func requireCapabilityRequirement(t *testing.T, requirements []CapabilityRequirement, capability CapabilityID) CapabilityRequirement {
	t.Helper()

	for _, requirement := range requirements {
		if requirement.ID == capability {
			return requirement
		}
	}
	t.Fatalf("requirements = %#v, want capability %q", requirements, capability)
	return CapabilityRequirement{}
}
