package livegate

import (
	"reflect"
	"testing"
)

func TestMicroVME2ELiveGateComposesExistingLiveGateRequirements(t *testing.T) {
	gate := MicroVME2ELiveGate()

	if gate.ID != MicroVME2ELiveGateID {
		t.Fatalf("gate ID = %q, want %q", gate.ID, MicroVME2ELiveGateID)
	}
	if gate.Category != GateCategoryMicroVME2E {
		t.Fatalf("gate category = %q, want %q", gate.Category, GateCategoryMicroVME2E)
	}
	if !reflect.DeepEqual(gate.BuildTags, []BuildTagName{
		BuildTagMicroVME2ELive,
		BuildTagFirecrackerLive,
		BuildTagNetworkEnforcementLive,
		BuildTagCredentialDeliveryLive,
	}) {
		t.Fatalf("build tags = %#v, want dedicated E2E tag plus component live tags", gate.BuildTags)
	}
	if !reflect.DeepEqual(gate.EnvVars, []EnvVarName{
		EnvVarFirecrackerLive,
		EnvVarFirecrackerLiveFirecracker,
		EnvVarFirecrackerLiveKernel,
		EnvVarFirecrackerLiveRootfs,
		EnvVarNetworkEnforcementLive,
		EnvVarNetworkEnforcementLiveProxy,
		EnvVarNetworkEnforcementLiveFirewall,
		EnvVarCredentialDeliveryLive,
	}) {
		t.Fatalf("env vars = %#v, want existing component live markers", gate.EnvVars)
	}
	if !reflect.DeepEqual(gate.Capabilities, []CapabilityID{
		CapabilityFirecrackerMicroVM,
		CapabilityNetworkEnforcement,
		CapabilityCredentialDelivery,
	}) {
		t.Fatalf("capabilities = %#v, want existing component capabilities", gate.Capabilities)
	}
	if !reflect.DeepEqual(CredentialDeliveryLiveModeEnvVars(), []EnvVarName{
		EnvVarCredentialDeliveryLiveHTTPProxy,
		EnvVarCredentialDeliveryLiveFileTmpfs,
		EnvVarCredentialDeliveryLiveSSHAgent,
		EnvVarCredentialDeliveryLiveEnv,
	}) {
		t.Fatalf("credential delivery mode env vars = %#v, want existing any-mode markers", CredentialDeliveryLiveModeEnvVars())
	}
}

func TestMicroVME2ELiveGateSkipsUntilAllTagsEnvsAndCapabilitiesArePresent(t *testing.T) {
	gate := MicroVME2ELiveGate()

	missingTag := PreflightGate(GateEvaluationInput{
		Gate:                  gate,
		EnabledBuildTags:      []BuildTagName{BuildTagMicroVME2ELive},
		PresentEnvVars:        MicroVME2ERequiredEnvVars(),
		AvailableCapabilities: MicroVME2ERequiredCapabilities(),
	})
	if !missingTag.ShouldSkipLiveAction() {
		t.Fatal("missing component build tags allowed live action")
	}
	if missingTag.SkipReason != SkipReasonMissingBuildTag {
		t.Fatalf("missingTag.SkipReason = %q, want %q", missingTag.SkipReason, SkipReasonMissingBuildTag)
	}
	requirement := requireRequirementForBuildTag(t, missingTag.Requirements, BuildTagFirecrackerLive)
	if requirement.Status != RequirementStatusMissing || requirement.ReasonCode != SkipReasonMissingBuildTag {
		t.Fatalf("firecracker build-tag requirement = %#v, want missing", requirement)
	}

	missingEnv := PreflightGate(GateEvaluationInput{
		Gate:                  gate,
		EnabledBuildTags:      MicroVME2ERequiredBuildTags(),
		PresentEnvVars:        microVME2ERequiredEnvVarsExcept(EnvVarNetworkEnforcementLiveFirewall),
		AvailableCapabilities: MicroVME2ERequiredCapabilities(),
	})
	if !missingEnv.ShouldSkipLiveAction() {
		t.Fatal("missing component env marker allowed live action")
	}
	if missingEnv.SkipReason != SkipReasonMissingEnvVar {
		t.Fatalf("missingEnv.SkipReason = %q, want %q", missingEnv.SkipReason, SkipReasonMissingEnvVar)
	}
	envRequirement := requireRequirementForEnvVar(t, missingEnv.Requirements, EnvVarNetworkEnforcementLiveFirewall)
	if envRequirement.Status != RequirementStatusMissing || envRequirement.ReasonCode != SkipReasonMissingEnvVar {
		t.Fatalf("firewall env requirement = %#v, want missing", envRequirement)
	}

	missingCapability := PreflightGate(GateEvaluationInput{
		Gate:             gate,
		EnabledBuildTags: MicroVME2ERequiredBuildTags(),
		PresentEnvVars:   MicroVME2ERequiredEnvVars(),
		AvailableCapabilities: []CapabilityID{
			CapabilityFirecrackerMicroVM,
			CapabilityNetworkEnforcement,
		},
	})
	if !missingCapability.ShouldSkipLiveAction() {
		t.Fatal("missing credential delivery capability allowed live action")
	}
	if missingCapability.SkipReason != SkipReasonCapabilityUnavailable {
		t.Fatalf("missingCapability.SkipReason = %q, want %q", missingCapability.SkipReason, SkipReasonCapabilityUnavailable)
	}
	capabilityRequirement := requireCapabilityRequirement(t, missingCapability.CapabilityRequirements, CapabilityCredentialDelivery)
	if capabilityRequirement.Status != RequirementStatusUnavailable || capabilityRequirement.ReasonCode != SkipReasonCapabilityUnavailable {
		t.Fatalf("credential delivery capability requirement = %#v, want unavailable", capabilityRequirement)
	}

	allowed := PreflightGate(GateEvaluationInput{
		Gate:                  gate,
		EnabledBuildTags:      MicroVME2ERequiredBuildTags(),
		PresentEnvVars:        MicroVME2ERequiredEnvVars(),
		AvailableCapabilities: MicroVME2ERequiredCapabilities(),
	})
	if !allowed.CanRunLiveAction() {
		t.Fatalf("complete composed gate did not allow live action: %#v", allowed)
	}
}

func TestMicroVME2ELiveGateSkipsWhenOnlyOneNetworkEnforcementSideMarkerIsPresent(t *testing.T) {
	gate := MicroVME2ELiveGate()

	for _, tt := range []struct {
		name    string
		present EnvVarName
		missing EnvVarName
	}{
		{
			name:    "proxy marker without firewall marker",
			present: EnvVarNetworkEnforcementLiveProxy,
			missing: EnvVarNetworkEnforcementLiveFirewall,
		},
		{
			name:    "firewall marker without proxy marker",
			present: EnvVarNetworkEnforcementLiveFirewall,
			missing: EnvVarNetworkEnforcementLiveProxy,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := PreflightGate(GateEvaluationInput{
				Gate:                  gate,
				EnabledBuildTags:      MicroVME2ERequiredBuildTags(),
				PresentEnvVars:        microVME2ERequiredEnvVarsExcept(tt.missing),
				AvailableCapabilities: MicroVME2ERequiredCapabilities(),
			})
			if !result.ShouldSkipLiveAction() {
				t.Fatal("one-sided network enforcement marker allowed live action")
			}
			if result.SkipReason != SkipReasonMissingEnvVar {
				t.Fatalf("SkipReason = %q, want %q", result.SkipReason, SkipReasonMissingEnvVar)
			}
			presentRequirement := requireRequirementForEnvVar(t, result.Requirements, tt.present)
			if presentRequirement.Status != RequirementStatusSatisfied {
				t.Fatalf("present side requirement = %#v, want satisfied", presentRequirement)
			}
			missingRequirement := requireRequirementForEnvVar(t, result.Requirements, tt.missing)
			if missingRequirement.Status != RequirementStatusMissing ||
				missingRequirement.ReasonCode != SkipReasonMissingEnvVar {
				t.Fatalf("missing side requirement = %#v, want missing env var", missingRequirement)
			}
		})
	}
}

func microVME2ERequiredEnvVarsExcept(excluded EnvVarName) []EnvVarName {
	var out []EnvVarName
	for _, envVar := range MicroVME2ERequiredEnvVars() {
		if envVar != excluded {
			out = append(out, envVar)
		}
	}
	return out
}
