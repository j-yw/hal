//go:build microvm_e2e_live && firecracker_live && network_enforcement_live && credential_delivery_live

package microvm_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/livegate"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

const microVMLiveE2EExecutionTimeout = 45 * time.Second

func TestMicroVMLiveE2EComposedLiveExecutionPath(t *testing.T) {
	getenv := os.Getenv
	_ = requireMicroVMLiveE2EGate(t, getenv)

	credentialDelivery := requireMicroVMLiveE2ECredentialDeliveryProjection(t, getenv)
	templateLock := microVMLiveE2ETemplateTrustLock()
	templateTrust := requireMicroVMLiveE2ETemplateTrustProjection(t, getenv, templateLock)
	preflight := requireMicroVMLiveE2EFirecrackerPreflight(t, getenv)

	config := microVMLiveE2EFirecrackerConfig(getenv)
	networkPlanning := microVMLiveE2ENetworkEnforcementPlanning()
	driver, err := firecrackerhost.NewLiveDriver(firecrackerhost.LiveDriverOptions{
		Config:               config,
		BaseStateDir:         filepath.Join(t.TempDir(), "firecracker-state"),
		CapabilityDetector:   microvm.HostCapabilityDetector{},
		NetworkEnforcement:   networkPlanning,
		HostProcessRunner:    firecrackerhost.NewOSExecProcessRunner(),
		BootAcceptancePoller: firecrackerhost.NewAPISocketBootAcceptancePoller(),
		BootTimeout:          microVMLiveE2EExecutionTimeout,
	})
	microVMLiveE2EFatalOnError(t, "driver construction", err, microVMLiveE2EForbiddenFragments(getenv)...)

	networkReadiness := requireMicroVMLiveE2ENetworkEnforcementReadiness(t, getenv, driver.Metadata().NetworkEnforcement)
	readinessMetadata := microvm.SanitizeLiveE2EMetadata(microvm.LiveE2EMetadata{
		ID:                 "microvm-live-e2e",
		Status:             microvm.LiveE2EReadinessReady,
		ReasonCode:         microvm.LiveE2EReasonReady,
		Message:            "microVM live E2E readiness composed before live execution.",
		Firecracker:        microVMLiveE2EReadyMetadata(microvm.LiveE2EComponentFirecracker, "firecracker"),
		KVM:                microVMLiveE2EReadyMetadata(microvm.LiveE2EComponentKVM, "kvm"),
		NetworkProxy:       networkReadiness.NetworkProxy,
		Firewall:           networkReadiness.Firewall,
		CredentialDelivery: credentialDelivery.Readiness,
		TemplateTrust:      templateTrust.Readiness,
	})
	assertMicroVMLiveE2ERedactionSafe(t, "readiness metadata", readinessMetadata, microVMLiveE2EForbiddenFragments(getenv)...)
	if !preflight.CanRunLiveAction() || !credentialDelivery.CanRunLiveAction() || !templateTrust.CanRunLiveAction() || !networkReadiness.CanRunLiveAction() {
		t.Fatalf("microVM live E2E readiness unexpectedly incomplete before live execution")
	}

	ctx, cancel := context.WithTimeout(context.Background(), microVMLiveE2EExecutionTimeout)
	defer cancel()

	created, err := driver.Create(ctx, sandboxruntime.CreateRequest{Name: "microvm-live-e2e"})
	microVMLiveE2EFatalOnError(t, "create", err, microVMLiveE2EForbiddenFragments(getenv)...)
	microVMLiveE2EAttachRuntimeMetadata(created, credentialDelivery, templateLock)
	assertMicroVMLiveE2ERedactionSafe(t, "created target", created, microVMLiveE2EForbiddenFragments(getenv)...)

	var started *sandboxruntime.Target
	t.Cleanup(func() {
		if started == nil {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		stopped, stopErr := driver.Stop(cleanupCtx, sandboxruntime.LifecycleRequest{Target: *started})
		if stopErr != nil {
			microVMLiveE2EReportSanitizedCleanupError(t, "stop", stopErr, getenv)
			return
		}
		if stopped != nil {
			started = stopped
		}
		if deleteErr := driver.Delete(cleanupCtx, sandboxruntime.LifecycleRequest{Target: *started}); deleteErr != nil {
			microVMLiveE2EReportSanitizedCleanupError(t, "delete", deleteErr, getenv)
		}
	})

	started, err = driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: *created})
	microVMLiveE2EFatalOnError(t, "start", err, microVMLiveE2EForbiddenFragments(getenv)...)
	microVMLiveE2EAssertStartedTarget(t, started)
	assertMicroVMLiveE2ERedactionSafe(t, "started target", started, microVMLiveE2EForbiddenFragments(getenv)...)
}

func requireMicroVMLiveE2EGate(t *testing.T, getenv func(string) string) livegate.GatePreflightResult {
	t.Helper()
	return livegate.RequireLiveGate(t, livegate.TestGateInput{
		GateID:                livegate.MicroVME2ELiveGateID,
		Gate:                  livegate.MicroVME2ELiveGate(),
		ExpectedEnvVars:       livegate.MicroVME2ERequiredEnvVars(),
		EnabledBuildTags:      livegate.MicroVME2ERequiredBuildTags(),
		PresentEnvVars:        microVMLiveE2EPresentEnvVars(getenv),
		AvailableCapabilities: livegate.MicroVME2ERequiredCapabilities(),
	})
}

func requireMicroVMLiveE2ECredentialDeliveryProjection(t *testing.T, getenv func(string) string) microvm.LiveE2ECredentialDeliveryProjectionResult {
	t.Helper()
	modeEnv := microVMLiveE2ECredentialDeliveryModeEnv(getenv)
	if modeEnv == "" {
		message := microVMLiveE2ECredentialDeliveryModeSkipMessage()
		livegate.AssertLiveGateSkipMessageRedactionSafe(t, message)
		t.Skip(message)
	}
	mode := microVMLiveE2ECredentialDeliveryModeForEnv(modeEnv)
	result := microvm.ProjectLiveE2ECredentialDeliveryMetadata(microvm.LiveE2ECredentialDeliveryProjectionInput{
		LiveMarker:        microVMLiveE2EEnvPresent(getenv, livegate.EnvVarCredentialDeliveryLive),
		EnvDeliveryMarker: microVMLiveE2EEnvPresent(getenv, livegate.EnvVarCredentialDeliveryLiveEnv),
		CredentialDelivery: microvm.LiveE2ECredentialDeliveryMetadata{
			ID:             "microvm-live-credential-delivery",
			RequestID:      "microvm-live-credential-request",
			PlanID:         "microvm-live-credential-plan",
			ActivationID:   "microvm-live-credential-activation",
			RequestedModes: []string{mode},
			ActiveModes:    []string{mode},
			Status:         "active",
			ReasonCode:     "requested",
		},
	})
	if result.CanRunLiveAction() {
		return result
	}
	message := microvm.LiveE2ECredentialDeliveryProjectionSkipMessage(result)
	livegate.AssertLiveGateSkipMessageRedactionSafe(t, message)
	t.Skip(message)
	return result
}

func requireMicroVMLiveE2ETemplateTrustProjection(t *testing.T, getenv func(string) string, lock *sandboxruntime.RuntimeTemplateLockMetadata) microvm.LiveE2ETemplateTrustProjectionResult {
	t.Helper()
	result := microvm.ProjectLiveE2ETemplateTrustMetadata(microvm.LiveE2ETemplateTrustProjectionInput{
		LiveMarker:    microVMLiveE2EEnvPresent(getenv, livegate.EnvVarTemplateTrustLive),
		TemplateID:    "microvm-live-template",
		TrustPolicyID: "microvm-live-template-trust-policy",
		TemplateLock:  lock,
	})
	if result.CanRunLiveAction() {
		return result
	}
	message := microvm.LiveE2ETemplateTrustProjectionSkipMessage(result)
	livegate.AssertLiveGateSkipMessageRedactionSafe(t, message)
	t.Skip(message)
	return result
}

func requireMicroVMLiveE2EFirecrackerPreflight(t *testing.T, getenv func(string) string) microvm.LiveE2EFirecrackerPreflightResult {
	t.Helper()
	result := microvm.PreflightLiveE2EFirecrackerRuntime(microvm.LiveE2EFirecrackerPreflightInput{
		FirecrackerLiveMarker:   microVMLiveE2EEnvPresent(getenv, livegate.EnvVarFirecrackerLive),
		FirecrackerBinaryMarker: getenv(string(livegate.EnvVarFirecrackerLiveFirecracker)),
		KernelMarker:            getenv(string(livegate.EnvVarFirecrackerLiveKernel)),
		RootfsMarker:            getenv(string(livegate.EnvVarFirecrackerLiveRootfs)),
	})
	if result.CanRunLiveAction() {
		return result
	}
	message := microvm.LiveE2EFirecrackerPreflightSkipMessage(result)
	livegate.AssertLiveGateSkipMessageRedactionSafe(t, message, microVMLiveE2EForbiddenFragments(getenv)...)
	t.Skip(message)
	return result
}

func requireMicroVMLiveE2ENetworkEnforcementReadiness(t *testing.T, getenv func(string) string, metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) microvm.LiveE2ENetworkEnforcementReadinessResult {
	t.Helper()
	result := microvm.ProjectLiveE2ENetworkEnforcementReadiness(microvm.LiveE2ENetworkEnforcementReadinessInput{
		LiveMarker:         microVMLiveE2EEnvPresent(getenv, livegate.EnvVarNetworkEnforcementLive),
		ProxyMarker:        microVMLiveE2EEnvPresent(getenv, livegate.EnvVarNetworkEnforcementLiveProxy),
		FirewallMarker:     microVMLiveE2EEnvPresent(getenv, livegate.EnvVarNetworkEnforcementLiveFirewall),
		NetworkEnforcement: metadata,
	})
	if result.CanRunLiveAction() {
		return result
	}
	if result.ShouldSkipLiveAction() {
		message := microvm.LiveE2ENetworkEnforcementReadinessSkipMessage(result)
		livegate.AssertLiveGateSkipMessageRedactionSafe(t, message, microVMLiveE2EForbiddenFragments(getenv)...)
		t.Skip(message)
	}
	message := microvm.LiveE2ENetworkEnforcementReadinessFailureMessage(result)
	livegate.AssertLiveGateSkipMessageRedactionSafe(t, message, microVMLiveE2EForbiddenFragments(getenv)...)
	t.Fatalf("%s", message)
	return result
}

func microVMLiveE2EFirecrackerConfig(getenv func(string) string) microvm.Config {
	config := microvm.DefaultConfig()
	config.HypervisorPath = strings.TrimSpace(getenv(string(livegate.EnvVarFirecrackerLiveFirecracker)))
	config.KernelImagePath = strings.TrimSpace(getenv(string(livegate.EnvVarFirecrackerLiveKernel)))
	config.RootfsPath = strings.TrimSpace(getenv(string(livegate.EnvVarFirecrackerLiveRootfs)))
	config.CPUCount = 1
	config.MemoryMiB = 256
	config.GuestWorkDir = "/"
	return config
}

func microVMLiveE2ENetworkEnforcementPlanning() *microvm.NetworkEnforcementPlanning {
	policy := &networkenforcement.PolicySnapshotIdentity{
		ID:        "microvm-live-e2e-policy",
		Version:   "v1",
		Preset:    networkenforcement.PolicyPresetDenyByDefault,
		RuleSetID: "microvm-live-e2e-rules",
	}
	return &microvm.NetworkEnforcementPlanning{
		Request: networkenforcement.PlanRequest{
			ID:             "microvm-live-e2e-network-plan",
			Source:         networkenforcement.PlanSourceMicroVM,
			Operation:      "live_e2e",
			PolicySnapshot: policy,
			RequestedPolicy: networkenforcement.RequestedNetworkPosture{
				Preset:            networkenforcement.PolicyPresetDenyByDefault,
				DefaultPosture:    networkenforcement.DefaultPostureDenyByDefault,
				HTTP:              networkenforcement.ProxyRoutingModeRouteViaProxy,
				HTTPS:             networkenforcement.ProxyRoutingModeRouteViaProxy,
				ProxyMechanism:    networkenforcement.EnforcementMechanismProxy,
				FirewallMode:      networkenforcement.FirewallIntentModeApply,
				FirewallMechanism: networkenforcement.EnforcementMechanismFirewall,
				PrivateNetwork:    networkenforcement.PostureBlock,
				MetadataEndpoint:  networkenforcement.PostureBlock,
			},
		},
		Adapter:       microVMLiveE2ENetworkAdapter{},
		Orchestration: microVMLiveE2ENetworkOrchestration(policy),
	}
}

type microVMLiveE2ENetworkAdapter struct{}

func (microVMLiveE2ENetworkAdapter) EnforceNetwork(_ context.Context, plan networkenforcement.SanitizedPlan) networkenforcement.Result {
	sanitizedPlan := plan.Plan()
	return networkenforcement.Result{
		PlanID:          sanitizedPlan.ID,
		AdapterID:       "microvm-live-e2e-network-adapter",
		Outcome:         networkenforcement.ResultOutcomeSuccess,
		EnforcementMode: networkenforcement.ResultModeProxyFirewall,
		Mechanisms: []networkenforcement.EnforcementMechanism{
			networkenforcement.EnforcementMechanismProxy,
			networkenforcement.EnforcementMechanismFirewall,
		},
		Operations:     []string{"proxy_route", "firewall_apply"},
		PolicySnapshot: sanitizedPlan.PolicySnapshot,
		Capability: &networkenforcement.ResultCapability{
			Supported:                  true,
			Modes:                      []networkenforcement.ResultMode{networkenforcement.ResultModeProxyFirewall},
			SupportsDomainRules:        true,
			SupportsEndpointRules:      true,
			SupportsPrivateRangeRules:  true,
			SupportsMetadataEndpoint:   true,
			SupportsDefaultDenyPosture: true,
		},
		ReasonCode: networkenforcement.ResultReasonApplied,
	}
}

func microVMLiveE2ENetworkOrchestration(policy *networkenforcement.PolicySnapshotIdentity) *networkenforcement.LiveLifecycleMetadata {
	return &networkenforcement.LiveLifecycleMetadata{
		PlanID:    "microvm-live-e2e-network-plan",
		AdapterID: "microvm-live-e2e-network-adapter",
		Status:    networkenforcement.LifecycleStatusActive,
		Mechanisms: []networkenforcement.EnforcementMechanism{
			networkenforcement.EnforcementMechanismProxy,
			networkenforcement.EnforcementMechanismFirewall,
		},
		Operations:     []string{"start_proxy", "apply_rules"},
		PolicySnapshot: policy,
		Proxy: &networkenforcement.ProxyListenerLifecycleMetadata{
			ID:               "microvm-live-e2e-proxy",
			PlanID:           "microvm-live-e2e-network-plan",
			AdapterID:        "microvm-live-e2e-network-adapter",
			Status:           networkenforcement.LifecycleStatusActive,
			Mechanisms:       []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismProxy},
			Operations:       []string{"start_proxy"},
			PolicySnapshot:   policy,
			CapabilityLabels: []string{"http_proxy"},
			ReasonCode:       networkenforcement.LifecycleReasonActive,
		},
		Rules: []networkenforcement.RuleLifecycleMetadata{
			{
				ID:               "microvm-live-e2e-firewall-rules",
				PlanID:           "microvm-live-e2e-network-plan",
				AdapterID:        "microvm-live-e2e-network-adapter",
				Status:           networkenforcement.LifecycleStatusActive,
				Mechanisms:       []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismFirewall},
				Operations:       []string{"apply_rules"},
				PolicySnapshot:   policy,
				CapabilityLabels: []string{"default_deny"},
				ReasonCode:       networkenforcement.LifecycleReasonApplied,
			},
		},
		CapabilityLabels: []string{"proxy_active", "rules_active"},
		ReasonCode:       networkenforcement.LifecycleReasonActive,
	}
}

func microVMLiveE2EAttachRuntimeMetadata(target *sandboxruntime.Target, credential microvm.LiveE2ECredentialDeliveryProjectionResult, templateLock *sandboxruntime.RuntimeTemplateLockMetadata) {
	if target == nil {
		return
	}
	if target.Runtime.Metadata == nil {
		target.Runtime.Metadata = &sandboxruntime.RuntimeMetadata{}
	}
	if credential.CredentialDelivery != nil {
		target.Runtime.Metadata.CredentialDelivery = sandboxruntime.SanitizeRuntimeCredentialDeliveryMetadata(&sandboxruntime.RuntimeCredentialDeliveryMetadata{
			ID:             credential.CredentialDelivery.ID,
			RequestID:      credential.CredentialDelivery.RequestID,
			PlanID:         credential.CredentialDelivery.PlanID,
			ActivationID:   credential.CredentialDelivery.ActivationID,
			RequestedModes: credential.CredentialDelivery.RequestedModes,
			ActiveModes:    credential.CredentialDelivery.ActiveModes,
			Status:         credential.CredentialDelivery.Status,
			ReasonCode:     credential.CredentialDelivery.ReasonCode,
		})
	}
	target.Runtime.Metadata.TemplateLock = sandboxruntime.SanitizeRuntimeTemplateLockMetadata(templateLock)
}

func microVMLiveE2EAssertStartedTarget(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()
	if target == nil || target.Runtime.Metadata == nil || target.Runtime.Metadata.ProcessLaunch == nil {
		t.Fatalf("started target = %#v, want process launch metadata", target)
	}
	if target.Runtime.Metadata.ProcessLaunch.State != string(firecracker.ProcessLaunchStateAccepted) {
		t.Fatalf("process launch state = %q, want %q", target.Runtime.Metadata.ProcessLaunch.State, firecracker.ProcessLaunchStateAccepted)
	}
	if target.Runtime.Metadata.NetworkEnforcement == nil {
		t.Fatal("started target missing network enforcement metadata")
	}
	if target.Runtime.Metadata.CredentialDelivery == nil || target.Runtime.Metadata.CredentialDelivery.Status != "active" {
		t.Fatalf("started credential delivery metadata = %#v, want active", target.Runtime.Metadata.CredentialDelivery)
	}
	if target.Runtime.Metadata.TemplateLock == nil || target.Runtime.Metadata.TemplateLock.TrustPolicy == nil || target.Runtime.Metadata.TemplateLock.TrustPolicy.Decision != "trusted" {
		t.Fatalf("started template lock metadata = %#v, want trusted template policy", target.Runtime.Metadata.TemplateLock)
	}
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

func microVMLiveE2ECredentialDeliveryModeForEnv(envVar livegate.EnvVarName) string {
	switch envVar {
	case livegate.EnvVarCredentialDeliveryLiveHTTPProxy:
		return "http_proxy"
	case livegate.EnvVarCredentialDeliveryLiveFileTmpfs:
		return "file_tmpfs"
	case livegate.EnvVarCredentialDeliveryLiveSSHAgent:
		return "ssh_agent"
	case livegate.EnvVarCredentialDeliveryLiveEnv:
		return "env"
	default:
		return ""
	}
}

func microVMLiveE2ECredentialDeliveryModeSkipMessage() string {
	markers := make([]string, 0, len(livegate.CredentialDeliveryLiveModeEnvVars()))
	for _, envVar := range livegate.CredentialDeliveryLiveModeEnvVars() {
		markers = append(markers, string(envVar))
	}
	return "microVM live E2E credential delivery requires one credential delivery mode marker: " + strings.Join(markers, ", ")
}

func microVMLiveE2ETemplateTrustLock() *sandboxruntime.RuntimeTemplateLockMetadata {
	return &sandboxruntime.RuntimeTemplateLockMetadata{
		Document: &sandboxruntime.RuntimeTemplateLockEntryMetadata{
			SourceKind:      "oci_artifact",
			ReferenceKind:   "oci_artifact",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("a", 64),
			ReasonCode:      "document_digest",
		},
		TemplateReference: &sandboxruntime.RuntimeTemplateLockEntryMetadata{
			SourceKind:      "template_reference",
			ReferenceKind:   "oci_artifact",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("b", 64),
			ReasonCode:      "template_reference_digest",
		},
		RuntimeImage: &sandboxruntime.RuntimeTemplateLockEntryMetadata{
			SourceKind:      "runtime_image",
			ReferenceKind:   "oci_image",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("c", 64),
			ReasonCode:      "runtime_image_digest",
		},
		SourceArtifact: &sandboxruntime.RuntimeTemplateLockEntryMetadata{
			SourceKind:      "source_artifact",
			ReferenceKind:   "git",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("d", 64),
			ReasonCode:      "source_artifact_digest",
		},
		TrustPolicy: &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{
			Mode:            "strict",
			Decision:        "trusted",
			SourceKind:      "oci_artifact",
			ReferenceKind:   "oci_artifact",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("a", 64),
		},
	}
}

func microVMLiveE2EReadyMetadata(component microvm.LiveE2EReadinessComponent, id string) *microvm.LiveE2EReadinessMetadata {
	return microvm.NewLiveE2EReadinessMetadata(component, id, microvm.LiveE2EReadinessReady, microvm.LiveE2EReasonReady, "live E2E prerequisite ready")
}

func microVMLiveE2EFatalOnError(t *testing.T, operation string, err error, forbiddenFragments ...string) {
	t.Helper()
	if err == nil {
		return
	}
	message := fmt.Sprintf("microVM live E2E %s failed: %v", operation, err)
	livegate.AssertLiveGateSkipMessageRedactionSafe(t, message, forbiddenFragments...)
	t.Fatalf("%s", message)
}

func microVMLiveE2EReportSanitizedCleanupError(t *testing.T, operation string, err error, getenv func(string) string) {
	t.Helper()
	message := fmt.Sprintf("microVM live E2E cleanup %s failed: %v", operation, err)
	livegate.AssertLiveGateSkipMessageRedactionSafe(t, message, microVMLiveE2EForbiddenFragments(getenv)...)
	t.Errorf("%s", message)
}

func assertMicroVMLiveE2ERedactionSafe(t *testing.T, label string, value any, forbiddenFragments ...string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error: %v", label, err)
	}
	publicText := string(encoded)
	livegate.AssertLiveGateSkipMessageRedactionSafe(t, publicText, forbiddenFragments...)
}

func microVMLiveE2EForbiddenFragments(getenv func(string) string) []string {
	var fragments []string
	for _, envVar := range []livegate.EnvVarName{
		livegate.EnvVarFirecrackerLiveFirecracker,
		livegate.EnvVarFirecrackerLiveKernel,
		livegate.EnvVarFirecrackerLiveRootfs,
	} {
		value := strings.TrimSpace(getenv(string(envVar)))
		if microVMLiveE2EValueLooksRaw(value) {
			fragments = append(fragments, value)
		}
	}
	return fragments
}

func microVMLiveE2EValueLooksRaw(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	lower := strings.ToLower(value)
	return strings.ContainsAny(value, `/\:`) ||
		strings.Contains(lower, ".sock") ||
		strings.Contains(lower, "token") ||
		strings.Contains(lower, "secret")
}
