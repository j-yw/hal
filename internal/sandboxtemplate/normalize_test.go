package sandboxtemplate

import (
	"reflect"
	"testing"

	launchassets "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

func TestNormalizeTemplateTrimsSafeFieldsAndNormalizesEnums(t *testing.T) {
	yes := true
	tmpl := Template{
		APIVersion: " sandbox-template.hal.dev/v1 ",
		Kind:       " SandboxTemplate ",
		Metadata: TemplateMetadata{
			ID:          " codex-go ",
			Name:        " Codex Go ",
			Version:     " 1.2.0 ",
			Description: " Go sandbox ",
			Labels:      map[string]string{" team ": " agents "},
			Reference: &ImmutableRef{
				Kind: " OCI-Artifact ",
				Ref:  " ghcr.io/acme/template:1.2.0 ",
				Digest: &DigestMetadata{
					Algorithm: " SHA-256 ",
					Value:     " ABCDEF ",
				},
			},
			Annotations: map[string]string{" owner ": " platform "},
			Digest:      &DigestMetadata{Algorithm: " SHA 512 ", Value: " FEDCBA "},
		},
		Runtime: &RuntimeRequirements{
			Driver:         " Rootless-Podman ",
			IsolationLevel: " VM ",
			Image:          &ImmutableRef{Kind: " OCI Image ", Ref: " ghcr.io/acme/image:latest "},
			Launch:         &LaunchRequirements{DescriptorRef: &ImmutableRef{Kind: " Git ", Ref: " https://example.test/repo.git "}},
			Resources:      &ResourceHints{CPUCores: 4, MemoryMB: 8192, DiskGB: 64},
			Labels:         map[string]string{" runtime ": " podman "},
		},
		Workspace: &WorkspaceRequirements{
			Mode:        " Direct ",
			InputSource: " Remote-Ref ",
			Ref:         &ImmutableRef{Kind: " Local ", Ref: " ./workspace "},
			ReadOnly:    true,
			Trusted:     true,
			Unsafe:      true,
		},
		Network: &NetworkRequirements{
			Profile:                " Allow Listed ",
			Allow:                  []NetworkRule{{ID: " github ", Kind: " Package Mirror ", Value: " proxy.golang.org "}},
			BlockPrivateNetworks:   &yes,
			BlockMetadataEndpoints: &yes,
			RouteHTTPSThroughProxy: &yes,
			RequireFirewallSupport: &yes,
			PolicySnapshotReference: &ImmutableRef{
				Kind: " Inline ",
				Ref:  " policy-v1 ",
			},
		},
		Credentials: &CredentialRequirements{
			DeliveryModes: []CredentialDeliveryMode{" HTTP Proxy ", " SSH-Agent ", " File Tmpfs ", " ENV ", " Legacy Auth Sync "},
			Services: []CredentialService{{
				ID:            " openai ",
				Domains:       []string{" api.openai.com "},
				DeliveryModes: []CredentialDeliveryMode{" HTTP-Proxy "},
				Required:      true,
			}},
		},
		Setup: []SetupCommandMetadata{{
			ID:              " setup ",
			DisplayName:     " Setup ",
			Description:     " install tools ",
			Tools:           []string{" go ", " bash "},
			Command:         []string{" sh ", "-c", " echo unchanged "},
			WorkDir:         " /work ",
			RequiresNetwork: true,
			TimeoutSeconds:  30,
		}},
	}

	normalized := NormalizeTemplate(tmpl)

	if normalized.APIVersion != TemplateAPIVersionV1 {
		t.Fatalf("APIVersion = %q, want %q", normalized.APIVersion, TemplateAPIVersionV1)
	}
	if normalized.Kind != TemplateKindSandbox {
		t.Fatalf("Kind = %q, want %q", normalized.Kind, TemplateKindSandbox)
	}
	if normalized.Metadata.ID != "codex-go" || normalized.Metadata.Name != "Codex Go" || normalized.Metadata.Description != "Go sandbox" {
		t.Fatalf("metadata strings were not trimmed: %#v", normalized.Metadata)
	}
	if got := normalized.Metadata.Labels["team"]; got != "agents" {
		t.Fatalf("metadata label = %q, want agents", got)
	}
	if normalized.Metadata.Reference.Kind != ReferenceKindOCIArtifact {
		t.Fatalf("reference kind = %q, want %q", normalized.Metadata.Reference.Kind, ReferenceKindOCIArtifact)
	}
	if normalized.Metadata.Reference.Ref != "ghcr.io/acme/template:1.2.0" {
		t.Fatalf("reference ref = %q", normalized.Metadata.Reference.Ref)
	}
	if normalized.Metadata.Reference.Digest.Algorithm != DigestAlgorithmSHA256 || normalized.Metadata.Reference.Digest.Value != "abcdef" {
		t.Fatalf("reference digest = %#v", normalized.Metadata.Reference.Digest)
	}
	if normalized.Metadata.Digest.Algorithm != DigestAlgorithmSHA512 || normalized.Metadata.Digest.Value != "fedcba" {
		t.Fatalf("metadata digest = %#v", normalized.Metadata.Digest)
	}
	if normalized.Runtime.Driver != RuntimeDriverRootlessPodman || normalized.Runtime.IsolationLevel != IsolationLevelVM {
		t.Fatalf("runtime = %#v", normalized.Runtime)
	}
	if normalized.Workspace.Mode != WorkspaceModeDirect || normalized.Workspace.InputSource != WorkspaceInputRemoteRef || !normalized.Workspace.Trusted || !normalized.Workspace.Unsafe {
		t.Fatalf("workspace = %#v", normalized.Workspace)
	}
	if normalized.Network.Profile != NetworkProfileAllowListed || normalized.Network.Allow[0].Kind != NetworkRuleCategoryPackageMirror {
		t.Fatalf("network = %#v", normalized.Network)
	}
	wantModes := []CredentialDeliveryMode{
		CredentialDeliveryModeHTTPProxy,
		CredentialDeliveryModeSSHAgent,
		CredentialDeliveryModeFileTmpfs,
		CredentialDeliveryModeEnv,
		CredentialDeliveryModeLegacyAuthSync,
	}
	if !reflect.DeepEqual(normalized.Credentials.DeliveryModes, wantModes) {
		t.Fatalf("delivery modes = %#v, want %#v", normalized.Credentials.DeliveryModes, wantModes)
	}
	if normalized.Credentials.Services[0].ID != "openai" || normalized.Credentials.Services[0].Domains[0] != "api.openai.com" {
		t.Fatalf("credential service = %#v", normalized.Credentials.Services[0])
	}
	if !reflect.DeepEqual(normalized.Setup[0].Command, []string{" sh ", "-c", " echo unchanged "}) {
		t.Fatalf("setup command = %#v, want command arguments preserved", normalized.Setup[0].Command)
	}
	if normalized.Setup[0].DisplayName != "Setup" || !reflect.DeepEqual(normalized.Setup[0].Tools, []string{"go", "bash"}) {
		t.Fatalf("setup metadata = %#v", normalized.Setup[0])
	}
}

func TestNormalizeTemplatePreservesNilAndEmptyOptionalSlices(t *testing.T) {
	normalizedNil := NormalizeTemplate(Template{
		Network:     &NetworkRequirements{},
		Credentials: &CredentialRequirements{},
	})
	if normalizedNil.Setup != nil {
		t.Fatalf("nil setup became %#v", normalizedNil.Setup)
	}
	if normalizedNil.Network.Allow != nil {
		t.Fatalf("nil network allow became %#v", normalizedNil.Network.Allow)
	}
	if normalizedNil.Credentials.DeliveryModes != nil || normalizedNil.Credentials.Services != nil {
		t.Fatalf("nil credential slices became %#v", normalizedNil.Credentials)
	}

	normalizedEmpty := NormalizeTemplate(Template{
		Network:     &NetworkRequirements{Allow: []NetworkRule{}},
		Credentials: &CredentialRequirements{DeliveryModes: []CredentialDeliveryMode{}, Services: []CredentialService{}},
		Setup:       []SetupCommandMetadata{},
	})
	if normalizedEmpty.Setup == nil || len(normalizedEmpty.Setup) != 0 {
		t.Fatalf("empty setup = %#v, want non-nil empty", normalizedEmpty.Setup)
	}
	if normalizedEmpty.Network.Allow == nil || len(normalizedEmpty.Network.Allow) != 0 {
		t.Fatalf("empty network allow = %#v, want non-nil empty", normalizedEmpty.Network.Allow)
	}
	if normalizedEmpty.Credentials.DeliveryModes == nil || len(normalizedEmpty.Credentials.DeliveryModes) != 0 {
		t.Fatalf("empty delivery modes = %#v, want non-nil empty", normalizedEmpty.Credentials.DeliveryModes)
	}
	if normalizedEmpty.Credentials.Services == nil || len(normalizedEmpty.Credentials.Services) != 0 {
		t.Fatalf("empty services = %#v, want non-nil empty", normalizedEmpty.Credentials.Services)
	}
}

func TestNormalizeTemplateIsStable(t *testing.T) {
	tmpl := Template{
		Metadata: TemplateMetadata{
			Labels: map[string]string{
				" b ": " second ",
				" a ": " first ",
			},
		},
		Runtime: &RuntimeRequirements{Driver: " MICROVM "},
	}
	first := NormalizeTemplate(tmpl)
	for i := 0; i < 25; i++ {
		if got := NormalizeTemplate(tmpl); !reflect.DeepEqual(got, first) {
			t.Fatalf("NormalizeTemplate run %d = %#v, want %#v", i, got, first)
		}
	}
	if got := NormalizeTemplate(first); !reflect.DeepEqual(got, first) {
		t.Fatalf("NormalizeTemplate is not idempotent: got %#v, want %#v", got, first)
	}
}

func TestNormalizeTemplateDoesNotMutateOrAliasInput(t *testing.T) {
	yes := true
	tmpl := Template{
		Metadata: TemplateMetadata{
			ID:          " original ",
			Labels:      map[string]string{" key ": " value "},
			Reference:   &ImmutableRef{Kind: " Git ", Ref: " ref ", Digest: &DigestMetadata{Algorithm: " SHA-384 ", Value: " ABC "}},
			Annotations: map[string]string{" note ": " original "},
			Digest:      &DigestMetadata{Algorithm: " SHA-256 ", Value: " DEF "},
		},
		Runtime: &RuntimeRequirements{
			Image: &ImmutableRef{Kind: " OCI-Image ", Ref: " image "},
			Launch: &LaunchRequirements{
				Descriptor: &launchassets.LaunchDescriptor{
					ID:     "launch",
					Labels: []launchassets.SafeLabel{"fast"},
					Assets: []launchassets.LaunchAsset{{
						ID:     "kernel",
						Labels: []launchassets.SafeLabel{"boot"},
						Source: launchassets.AssetSource{HostPath: &launchassets.HostPathMetadata{
							Path: "/tmp/kernel",
						}},
						InitConfig:  &launchassets.InitConfigMetadata{Labels: []launchassets.SafeLabel{"init"}},
						AgentConfig: &launchassets.AgentConfigMetadata{Features: []launchassets.SafeLabel{"rpc"}},
						Resources:   []launchassets.ResourceMetadata{{Labels: []launchassets.SafeLabel{"small"}}},
					}},
				},
				DescriptorRef: &ImmutableRef{Kind: " Local ", Ref: " descriptor "},
			},
			Resources: &ResourceHints{CPUCores: 2},
			Labels:    map[string]string{" runtime ": " label "},
		},
		Workspace: &WorkspaceRequirements{Ref: &ImmutableRef{Kind: " Inline ", Ref: " workspace "}},
		Network: &NetworkRequirements{
			Allow:                   []NetworkRule{{ID: " rule ", Kind: " Domain ", Value: " example.test "}},
			BlockPrivateNetworks:    &yes,
			PolicySnapshotReference: &ImmutableRef{Kind: " OCI-Artifact ", Ref: " policy "},
		},
		Credentials: &CredentialRequirements{
			DeliveryModes: []CredentialDeliveryMode{" HTTP-Proxy "},
			Services:      []CredentialService{{ID: " svc ", Domains: []string{" example.test "}, DeliveryModes: []CredentialDeliveryMode{" Env "}}},
		},
		Setup: []SetupCommandMetadata{{ID: " setup ", Command: []string{"echo", "ok"}}},
	}
	original := tmpl

	normalized := NormalizeTemplate(tmpl)

	if !reflect.DeepEqual(tmpl, original) {
		t.Fatalf("NormalizeTemplate mutated input: got %#v, want %#v", tmpl, original)
	}

	tmpl.Metadata.Labels[" key "] = "changed"
	tmpl.Metadata.Reference.Ref = "changed"
	tmpl.Metadata.Reference.Digest.Value = "changed"
	tmpl.Runtime.Image.Ref = "changed"
	tmpl.Runtime.Launch.Descriptor.Labels[0] = "changed"
	tmpl.Runtime.Launch.Descriptor.Assets[0].Labels[0] = "changed"
	tmpl.Runtime.Launch.Descriptor.Assets[0].Source.HostPath.Path = "changed"
	tmpl.Runtime.Launch.Descriptor.Assets[0].InitConfig.Labels[0] = "changed"
	tmpl.Runtime.Launch.Descriptor.Assets[0].AgentConfig.Features[0] = "changed"
	tmpl.Runtime.Launch.Descriptor.Assets[0].Resources[0].Labels[0] = "changed"
	tmpl.Runtime.Labels[" runtime "] = "changed"
	tmpl.Network.Allow[0].Value = "changed"
	*tmpl.Network.BlockPrivateNetworks = false
	tmpl.Credentials.DeliveryModes[0] = "changed"
	tmpl.Credentials.Services[0].Domains[0] = "changed"
	tmpl.Credentials.Services[0].DeliveryModes[0] = "changed"
	tmpl.Setup[0].Command[0] = "changed"

	if normalized.Metadata.Labels["key"] != "value" {
		t.Fatalf("normalized metadata labels aliased input: %#v", normalized.Metadata.Labels)
	}
	if normalized.Metadata.Reference.Ref != "ref" || normalized.Metadata.Reference.Digest.Value != "abc" {
		t.Fatalf("normalized reference aliased input: %#v", normalized.Metadata.Reference)
	}
	if normalized.Runtime.Image.Ref != "image" {
		t.Fatalf("normalized runtime image aliased input: %#v", normalized.Runtime.Image)
	}
	if normalized.Runtime.Launch.Descriptor.Labels[0] != "fast" ||
		normalized.Runtime.Launch.Descriptor.Assets[0].Labels[0] != "boot" ||
		normalized.Runtime.Launch.Descriptor.Assets[0].Source.HostPath.Path != "/tmp/kernel" ||
		normalized.Runtime.Launch.Descriptor.Assets[0].InitConfig.Labels[0] != "init" ||
		normalized.Runtime.Launch.Descriptor.Assets[0].AgentConfig.Features[0] != "rpc" ||
		normalized.Runtime.Launch.Descriptor.Assets[0].Resources[0].Labels[0] != "small" {
		t.Fatalf("normalized launch descriptor aliased input: %#v", normalized.Runtime.Launch.Descriptor)
	}
	if normalized.Runtime.Labels["runtime"] != "label" {
		t.Fatalf("normalized runtime labels aliased input: %#v", normalized.Runtime.Labels)
	}
	if normalized.Network.Allow[0].Value != "example.test" || !*normalized.Network.BlockPrivateNetworks {
		t.Fatalf("normalized network aliased input: %#v", normalized.Network)
	}
	if normalized.Credentials.DeliveryModes[0] != CredentialDeliveryModeHTTPProxy ||
		normalized.Credentials.Services[0].Domains[0] != "example.test" ||
		normalized.Credentials.Services[0].DeliveryModes[0] != CredentialDeliveryModeEnv {
		t.Fatalf("normalized credentials aliased input: %#v", normalized.Credentials)
	}
	if normalized.Setup[0].Command[0] != "echo" {
		t.Fatalf("normalized setup command aliased input: %#v", normalized.Setup)
	}
}
