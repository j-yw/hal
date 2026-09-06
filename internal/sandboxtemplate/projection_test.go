package sandboxtemplate

import (
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	launchassets "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

func TestProjectRuntimeStatePreservesBaseAndLaunchDigests(t *testing.T) {
	tmpl := validTemplateForValidation()
	tmpl.Runtime.Image.Digest = &DigestMetadata{Algorithm: DigestAlgorithmSHA256, Value: strings.Repeat("b", 64)}
	tmpl.Runtime.Launch = &LaunchRequirements{
		Descriptor: &launchassets.LaunchDescriptor{
			Assets: []launchassets.LaunchAsset{{
				ID:     "kernel",
				Role:   launchassets.AssetRoleKernel,
				Labels: []launchassets.SafeLabel{"boot"},
				Lock: launchassets.LockMetadata{Digest: launchassets.DigestMetadata{
					Algorithm: launchassets.DigestAlgorithmSHA256,
					Value:     strings.Repeat("c", 64),
				}},
			}},
		},
	}
	base := sandboxruntime.RuntimeState{
		RuntimeID: "runtime-01",
		WorkerID:  "worker-01",
		Metadata:  &sandboxruntime.RuntimeMetadata{CapabilityLabels: []string{"existing"}},
	}

	got := ProjectRuntimeState(tmpl, base)
	if got.RuntimeID != "runtime-01" || got.WorkerID != "worker-01" {
		t.Fatalf("runtime base fields = %#v, want preserved", got)
	}
	if got.Driver != sandboxruntime.DriverMicroVM || got.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("runtime projection = %#v", got)
	}
	wantImage := "ghcr.io/acme/go-agent:1.2.0@sha256:" + strings.Repeat("b", 64)
	if got.Image != wantImage {
		t.Fatalf("image = %q, want %q", got.Image, wantImage)
	}
	if got.Metadata == nil || got.Metadata.OperationPlan == nil || len(got.Metadata.OperationPlan.Payloads) != 1 {
		t.Fatalf("operation plan = %#v", got.Metadata)
	}
	asset := got.Metadata.OperationPlan.Payloads[0].Assets[0]
	if asset.AssetRole != "kernel" || asset.ID != "kernel" || asset.Digest == nil || asset.Digest.Value != strings.Repeat("c", 64) {
		t.Fatalf("projected launch asset = %#v", asset)
	}
	if got.Metadata.CapabilityLabels[0] != "existing" {
		t.Fatalf("metadata capability labels = %#v, want existing preserved", got.Metadata.CapabilityLabels)
	}
}

func TestProjectRuntimeStateRepresentsUnresolvedLaunchReferenceWithoutDigest(t *testing.T) {
	tmpl := validTemplateForValidation()
	tmpl.Runtime.Launch = &LaunchRequirements{
		DescriptorRef: &ImmutableRef{Kind: ReferenceKindOCIArtifact, Ref: "ghcr.io/acme/launch:latest"},
	}
	got := ProjectRuntimeState(tmpl, sandboxruntime.RuntimeState{})
	if got.Metadata == nil || got.Metadata.OperationPlan == nil || len(got.Metadata.OperationPlan.Payloads) != 1 {
		t.Fatalf("operation plan = %#v", got.Metadata)
	}
	payload := got.Metadata.OperationPlan.Payloads[0]
	if payload.Role != "launch_descriptor_ref" {
		t.Fatalf("payload role = %q, want launch_descriptor_ref", payload.Role)
	}
	if len(payload.Assets) != 0 {
		t.Fatalf("unresolved descriptor ref assets = %#v, want no digest asset", payload.Assets)
	}
}

func TestProjectWorkspacePreservesModesAndTrustMetadata(t *testing.T) {
	tmpl := validTemplateForValidation()
	tmpl.Workspace = &WorkspaceRequirements{Mode: WorkspaceModeCopy, InputSource: WorkspaceInputCopy}
	workspace, trust := ProjectWorkspace(tmpl, sandbox.SandboxWorkspace{Branch: "existing"})
	if workspace.Mode != sandbox.SandboxWorkspaceModeCopy || workspace.InputSource != sandbox.SandboxWorkspaceInputSourceCopy || workspace.Branch != "existing" {
		t.Fatalf("workspace projection = %#v", workspace)
	}
	if trust.Unsafe {
		t.Fatalf("copy workspace trust = %#v, want not unsafe", trust)
	}

	tmpl.Workspace = &WorkspaceRequirements{Mode: WorkspaceModeDirect, InputSource: WorkspaceInputCopy}
	workspace, trust = ProjectWorkspace(tmpl, sandbox.SandboxWorkspace{})
	if workspace.Mode != sandbox.SandboxWorkspaceModeDirect || !trust.Unsafe {
		t.Fatalf("direct workspace projection = %#v trust=%#v", workspace, trust)
	}
}

func TestProjectNetworkPolicyDoesNotClaimEnforcement(t *testing.T) {
	tmpl := validTemplateForValidation()
	got := ProjectTemplate(tmpl, Projection{Security: sandbox.SandboxSecurity{
		CapabilityReadiness: &sandbox.SandboxSecurityCapabilityReadinessOutput{
			Results: []sandbox.SandboxSecurityCapabilityReadinessResult{{
				State: sandbox.SandboxSecurityCapabilityReadinessReady,
			}},
		},
	}})
	if got.NetworkPolicy == nil || got.NetworkPolicy.Preset != sandbox.SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("network policy = %#v", got.NetworkPolicy)
	}
	if len(got.NetworkPolicy.Rules) != 1 || got.NetworkPolicy.Rules[0].Kind != sandbox.SandboxNetworkPolicyRuleKindDomain {
		t.Fatalf("network rules = %#v", got.NetworkPolicy.Rules)
	}
	if got.Security.Network == nil || got.Security.Network.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("security network = %#v, want no enforcement claim", got.Security.Network)
	}
	if got.Security.Network.PolicyEnforced != "" {
		t.Fatalf("policy enforced = %q, want empty enforcement claim", got.Security.Network.PolicyEnforced)
	}
	if got.Security.CapabilityReadiness == nil || len(got.Security.CapabilityReadiness.Results) != 1 ||
		got.Security.CapabilityReadiness.Results[0].State != sandbox.SandboxSecurityCapabilityReadinessReady {
		t.Fatalf("unrelated security readiness not preserved: %#v", got.Security)
	}
}

func TestProjectCredentialRequirementsRequestedOnly(t *testing.T) {
	tmpl := validTemplateForValidation()
	tmpl.Credentials.DeliveryModes = append(tmpl.Credentials.DeliveryModes, CredentialDeliveryModeSSHAgent)
	got := ProjectTemplate(tmpl, Projection{})
	if got.SecretDelivery == nil {
		t.Fatal("secret delivery = nil")
	}
	if len(got.SecretDelivery.ActiveModes) != 0 {
		t.Fatalf("active modes = %#v, want requested-only projection", got.SecretDelivery.ActiveModes)
	}
	if !containsProjectionString(got.SecretDelivery.RequestedModes, sandbox.SandboxSecretModeHTTPProxy) ||
		!containsProjectionString(got.SecretDelivery.RequestedModes, sandbox.SandboxSecretModeSSHAgent) {
		t.Fatalf("requested modes = %#v", got.SecretDelivery.RequestedModes)
	}
	if got.Security.Secrets == nil || len(got.Security.Secrets.ActiveModes) != 0 {
		t.Fatalf("security secrets = %#v, want requested-only", got.Security.Secrets)
	}
}

func TestProjectTemplateSanitizesUnsafeInputBeforeProjection(t *testing.T) {
	tmpl := validTemplateForValidation()
	tmpl.Network.Allow = append(tmpl.Network.Allow, NetworkRule{ID: "bad", Kind: NetworkRuleCategoryDomain, Value: "169.254.169.254"})
	tmpl.Credentials.Services = append(tmpl.Credentials.Services, CredentialService{ID: "sk-secret", DeliveryModes: []CredentialDeliveryMode{CredentialDeliveryModeEnv}})
	validation := ValidateTemplate(tmpl)
	if validation.Valid {
		t.Fatal("ValidateTemplate() valid, want unsafe template rejected before projection")
	}
	got := ProjectTemplate(tmpl, Projection{})
	if len(got.NetworkPolicy.Rules) != 1 || got.NetworkPolicy.Rules[0].Value != "api.github.com" {
		t.Fatalf("network policy = %#v, want unsafe rule omitted", got.NetworkPolicy)
	}
	if containsProjectionString(got.SecretDelivery.RequestedModes, sandbox.SandboxSecretModeEnv) {
		t.Fatalf("secret delivery requested modes = %#v, unsafe service mode should be omitted", got.SecretDelivery.RequestedModes)
	}
}

func containsProjectionString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
