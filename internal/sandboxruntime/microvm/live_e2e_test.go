//go:build microvm_e2e_live

package microvm

import (
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/livegate"
)

func TestMicroVMLiveE2EHarnessRequiresComposedLiveGates(t *testing.T) {
	result := requireMicroVMLiveE2EGate(t, os.Getenv)
	if !result.CanRunLiveAction() {
		t.Fatalf("microVM live E2E gate result = %#v, want allowed or skipped before this point", result)
	}

	if modeEnv := microVMLiveE2ECredentialDeliveryModeEnv(os.Getenv); modeEnv == "" {
		message := microVMLiveE2ECredentialDeliveryModeSkipMessage()
		livegate.AssertLiveGateSkipMessageRedactionSafe(t, message)
		t.Skip(message)
	}

	preflight := requireMicroVMLiveE2EFirecrackerPreflight(t, os.Getenv)
	if !preflight.CanRunLiveAction() {
		t.Fatalf("microVM live E2E Firecracker preflight result = %#v, want allowed or skipped before this point", preflight)
	}

	t.Skip("microVM live E2E harness gates are satisfied; live actions are implemented by later stories")
}

func requireMicroVMLiveE2EGate(t *testing.T, getenv func(string) string) livegate.GatePreflightResult {
	t.Helper()
	return livegate.RequireLiveGate(t, livegate.TestGateInput{
		GateID:                livegate.MicroVME2ELiveGateID,
		Gate:                  livegate.MicroVME2ELiveGate(),
		ExpectedEnvVars:       livegate.MicroVME2ERequiredEnvVars(),
		EnabledBuildTags:      microVMLiveE2EEnabledBuildTags(),
		PresentEnvVars:        microVMLiveE2EPresentEnvVars(getenv),
		AvailableCapabilities: livegate.MicroVME2ERequiredCapabilities(),
	})
}

func microVMLiveE2EEnabledBuildTags() []livegate.BuildTagName {
	tags := []livegate.BuildTagName{livegate.BuildTagMicroVME2ELive}
	if microVMLiveE2EFirecrackerLiveBuildTagEnabled {
		tags = append(tags, livegate.BuildTagFirecrackerLive)
	}
	if microVMLiveE2ENetworkEnforcementLiveBuildTagEnabled {
		tags = append(tags, livegate.BuildTagNetworkEnforcementLive)
	}
	if microVMLiveE2ECredentialDeliveryLiveBuildTagEnabled {
		tags = append(tags, livegate.BuildTagCredentialDeliveryLive)
	}
	return tags
}

func microVMLiveE2EPresentEnvVars(getenv func(string) string) []livegate.EnvVarName {
	var present []livegate.EnvVarName
	for _, envVar := range livegate.MicroVME2ERequiredEnvVars() {
		if microVMLiveE2EEnvPresent(getenv, envVar) {
			present = append(present, envVar)
		}
	}
	return present
}

func microVMLiveE2EEnvPresent(getenv func(string) string, envVar livegate.EnvVarName) bool {
	value := strings.TrimSpace(getenv(string(envVar)))
	switch envVar {
	case livegate.EnvVarFirecrackerLiveFirecracker,
		livegate.EnvVarFirecrackerLiveKernel,
		livegate.EnvVarFirecrackerLiveRootfs:
		return value != ""
	default:
		return value == "1"
	}
}

func microVMLiveE2ECredentialDeliveryModeEnv(getenv func(string) string) livegate.EnvVarName {
	for _, envVar := range livegate.CredentialDeliveryLiveModeEnvVars() {
		if strings.TrimSpace(getenv(string(envVar))) == "1" {
			return envVar
		}
	}
	return ""
}

func microVMLiveE2ECredentialDeliveryModeSkipMessage() string {
	markers := make([]string, 0, len(livegate.CredentialDeliveryLiveModeEnvVars()))
	for _, envVar := range livegate.CredentialDeliveryLiveModeEnvVars() {
		markers = append(markers, string(envVar))
	}
	return "microVM live E2E credential delivery requires one credential delivery mode marker: " + strings.Join(markers, ", ")
}

func requireMicroVMLiveE2EFirecrackerPreflight(t *testing.T, getenv func(string) string) LiveE2EFirecrackerPreflightResult {
	t.Helper()
	result := PreflightLiveE2EFirecrackerRuntime(LiveE2EFirecrackerPreflightInput{
		FirecrackerLiveMarker:   microVMLiveE2EEnvPresent(getenv, livegate.EnvVarFirecrackerLive),
		FirecrackerBinaryMarker: getenv(string(livegate.EnvVarFirecrackerLiveFirecracker)),
		KernelMarker:            getenv(string(livegate.EnvVarFirecrackerLiveKernel)),
		RootfsMarker:            getenv(string(livegate.EnvVarFirecrackerLiveRootfs)),
	})
	if !result.ShouldSkipLiveAction() {
		return result
	}

	message := LiveE2EFirecrackerPreflightSkipMessage(result)
	livegate.AssertLiveGateSkipMessageRedactionSafe(t, message)
	t.Skip(message)
	return result
}
