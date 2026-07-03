package sandboxtemplate

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	launchassets "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

func TestSandboxTemplateContractConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "api version", got: string(TemplateAPIVersionV1), want: "sandbox-template.hal.dev/v1"},
		{name: "kind", got: string(TemplateKindSandbox), want: "SandboxTemplate"},
		{name: "microvm driver", got: string(RuntimeDriverMicroVM), want: "microvm"},
		{name: "rootless podman driver", got: string(RuntimeDriverRootlessPodman), want: "rootless_podman"},
		{name: "ssh machine driver", got: string(RuntimeDriverSSHMachine), want: "ssh_machine"},
		{name: "vm isolation", got: string(IsolationLevelVM), want: "vm"},
		{name: "clone workspace", got: string(WorkspaceModeClone), want: "clone"},
		{name: "deny by default network", got: string(NetworkProfileDenyByDefault), want: "deny_by_default"},
		{name: "http proxy credentials", got: string(CredentialDeliveryModeHTTPProxy), want: "http_proxy"},
		{name: "oci artifact reference", got: string(ReferenceKindOCIArtifact), want: "oci_artifact"},
		{name: "sha256 digest", got: string(DigestAlgorithmSHA256), want: "sha256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("constant = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestSandboxTemplateContractFieldsAndJSONTags(t *testing.T) {
	templateType := reflect.TypeOf(Template{})
	assertTemplateField(t, templateType, "APIVersion", reflect.TypeOf(TemplateAPIVersion("")), `json:"apiVersion,omitempty" yaml:"apiVersion,omitempty"`)
	assertTemplateField(t, templateType, "Kind", reflect.TypeOf(TemplateKind("")), `json:"kind,omitempty" yaml:"kind,omitempty"`)
	assertTemplateField(t, templateType, "Metadata", reflect.TypeOf(TemplateMetadata{}), `json:"metadata" yaml:"metadata"`)
	assertTemplateField(t, templateType, "Runtime", reflect.TypeOf((*RuntimeRequirements)(nil)), `json:"runtime,omitempty" yaml:"runtime,omitempty"`)
	assertTemplateField(t, templateType, "Workspace", reflect.TypeOf((*WorkspaceRequirements)(nil)), `json:"workspace,omitempty" yaml:"workspace,omitempty"`)
	assertTemplateField(t, templateType, "Network", reflect.TypeOf((*NetworkRequirements)(nil)), `json:"network,omitempty" yaml:"network,omitempty"`)
	assertTemplateField(t, templateType, "Credentials", reflect.TypeOf((*CredentialRequirements)(nil)), `json:"credentials,omitempty" yaml:"credentials,omitempty"`)
	assertTemplateField(t, templateType, "Setup", reflect.TypeOf([]SetupCommandMetadata{}), `json:"setup,omitempty" yaml:"setup,omitempty"`)

	metadataType := reflect.TypeOf(TemplateMetadata{})
	assertTemplateField(t, metadataType, "ID", reflect.TypeOf(""), `json:"id" yaml:"id"`)
	assertTemplateField(t, metadataType, "Name", reflect.TypeOf(""), `json:"name,omitempty" yaml:"name,omitempty"`)
	assertTemplateField(t, metadataType, "Version", reflect.TypeOf(""), `json:"version,omitempty" yaml:"version,omitempty"`)
	assertTemplateField(t, metadataType, "Description", reflect.TypeOf(""), `json:"description,omitempty" yaml:"description,omitempty"`)
	assertTemplateField(t, metadataType, "Labels", reflect.TypeOf(map[string]string{}), `json:"labels,omitempty" yaml:"labels,omitempty"`)
	assertTemplateField(t, metadataType, "Reference", reflect.TypeOf((*ImmutableRef)(nil)), `json:"reference,omitempty" yaml:"reference,omitempty"`)
	assertTemplateField(t, metadataType, "Annotations", reflect.TypeOf(map[string]string{}), `json:"annotations,omitempty" yaml:"annotations,omitempty"`)
	assertTemplateField(t, metadataType, "Digest", reflect.TypeOf((*DigestMetadata)(nil)), `json:"digest,omitempty" yaml:"digest,omitempty"`)

	runtimeType := reflect.TypeOf(RuntimeRequirements{})
	assertTemplateField(t, runtimeType, "Driver", reflect.TypeOf(RuntimeDriver("")), `json:"driver,omitempty" yaml:"driver,omitempty"`)
	assertTemplateField(t, runtimeType, "IsolationLevel", reflect.TypeOf(IsolationLevel("")), `json:"isolationLevel,omitempty" yaml:"isolationLevel,omitempty"`)
	assertTemplateField(t, runtimeType, "Image", reflect.TypeOf((*ImmutableRef)(nil)), `json:"image,omitempty" yaml:"image,omitempty"`)
	assertTemplateField(t, runtimeType, "Launch", reflect.TypeOf((*LaunchRequirements)(nil)), `json:"launch,omitempty" yaml:"launch,omitempty"`)
	assertTemplateField(t, runtimeType, "Resources", reflect.TypeOf((*ResourceHints)(nil)), `json:"resources,omitempty" yaml:"resources,omitempty"`)
	assertTemplateField(t, runtimeType, "Labels", reflect.TypeOf(map[string]string{}), `json:"labels,omitempty" yaml:"labels,omitempty"`)

	launchType := reflect.TypeOf(LaunchRequirements{})
	assertTemplateField(t, launchType, "Descriptor", reflect.TypeOf((*launchassets.LaunchDescriptor)(nil)), `json:"descriptor,omitempty" yaml:"descriptor,omitempty"`)
	assertTemplateField(t, launchType, "DescriptorRef", reflect.TypeOf((*ImmutableRef)(nil)), `json:"descriptorRef,omitempty" yaml:"descriptorRef,omitempty"`)

	workspaceType := reflect.TypeOf(WorkspaceRequirements{})
	assertTemplateField(t, workspaceType, "Mode", reflect.TypeOf(WorkspaceMode("")), `json:"mode,omitempty" yaml:"mode,omitempty"`)
	assertTemplateField(t, workspaceType, "InputSource", reflect.TypeOf(WorkspaceInputSource("")), `json:"inputSource,omitempty" yaml:"inputSource,omitempty"`)
	assertTemplateField(t, workspaceType, "Ref", reflect.TypeOf((*ImmutableRef)(nil)), `json:"ref,omitempty" yaml:"ref,omitempty"`)
	assertTemplateField(t, workspaceType, "ReadOnly", reflect.TypeOf(false), `json:"readOnly,omitempty" yaml:"readOnly,omitempty"`)
	assertTemplateField(t, workspaceType, "Trusted", reflect.TypeOf(false), `json:"trusted,omitempty" yaml:"trusted,omitempty"`)
	assertTemplateField(t, workspaceType, "Unsafe", reflect.TypeOf(false), `json:"unsafe,omitempty" yaml:"unsafe,omitempty"`)

	networkType := reflect.TypeOf(NetworkRequirements{})
	assertTemplateField(t, networkType, "Profile", reflect.TypeOf(NetworkPolicyProfile("")), `json:"profile,omitempty" yaml:"profile,omitempty"`)
	assertTemplateField(t, networkType, "Allow", reflect.TypeOf([]NetworkRule{}), `json:"allow,omitempty" yaml:"allow,omitempty"`)
	assertTemplateField(t, networkType, "BlockPrivateNetworks", reflect.TypeOf((*bool)(nil)), `json:"blockPrivateNetworks,omitempty" yaml:"blockPrivateNetworks,omitempty"`)
	assertTemplateField(t, networkType, "BlockMetadataEndpoints", reflect.TypeOf((*bool)(nil)), `json:"blockMetadataEndpoints,omitempty" yaml:"blockMetadataEndpoints,omitempty"`)
	assertTemplateField(t, networkType, "RouteHTTPSThroughProxy", reflect.TypeOf((*bool)(nil)), `json:"routeHttpsThroughProxy,omitempty" yaml:"routeHttpsThroughProxy,omitempty"`)
	assertTemplateField(t, networkType, "RequireFirewallSupport", reflect.TypeOf((*bool)(nil)), `json:"requireFirewallSupport,omitempty" yaml:"requireFirewallSupport,omitempty"`)
	assertTemplateField(t, networkType, "PolicySnapshotReference", reflect.TypeOf((*ImmutableRef)(nil)), `json:"policySnapshotReference,omitempty" yaml:"policySnapshotReference,omitempty"`)

	credentialsType := reflect.TypeOf(CredentialRequirements{})
	assertTemplateField(t, credentialsType, "DeliveryModes", reflect.TypeOf([]CredentialDeliveryMode{}), `json:"deliveryModes,omitempty" yaml:"deliveryModes,omitempty"`)
	assertTemplateField(t, credentialsType, "Services", reflect.TypeOf([]CredentialService{}), `json:"services,omitempty" yaml:"services,omitempty"`)

	setupType := reflect.TypeOf(SetupCommandMetadata{})
	assertTemplateField(t, setupType, "ID", reflect.TypeOf(""), `json:"id" yaml:"id"`)
	assertTemplateField(t, setupType, "DisplayName", reflect.TypeOf(""), `json:"displayName,omitempty" yaml:"displayName,omitempty"`)
	assertTemplateField(t, setupType, "Description", reflect.TypeOf(""), `json:"description,omitempty" yaml:"description,omitempty"`)
	assertTemplateField(t, setupType, "Tools", reflect.TypeOf([]string{}), `json:"tools,omitempty" yaml:"tools,omitempty"`)
	assertTemplateField(t, setupType, "Command", reflect.TypeOf([]string{}), `json:"command,omitempty" yaml:"command,omitempty"`)
	assertTemplateField(t, setupType, "WorkDir", reflect.TypeOf(""), `json:"workDir,omitempty" yaml:"workDir,omitempty"`)
	assertTemplateField(t, setupType, "RequiresNetwork", reflect.TypeOf(false), `json:"requiresNetwork,omitempty" yaml:"requiresNetwork,omitempty"`)
	assertTemplateField(t, setupType, "TimeoutSeconds", reflect.TypeOf(0), `json:"timeoutSeconds,omitempty" yaml:"timeoutSeconds,omitempty"`)
}

func TestSandboxTemplateJSONShapeIncludesCoreContractMetadata(t *testing.T) {
	yes := true
	tmpl := Template{
		APIVersion: TemplateAPIVersionV1,
		Kind:       TemplateKindSandbox,
		Metadata: TemplateMetadata{
			ID:      "codex-go",
			Name:    "Codex Go",
			Version: "1.2.0",
			Reference: &ImmutableRef{
				Kind: ReferenceKindOCIArtifact,
				Ref:  "ghcr.io/acme/hal-template-go-codex:1.2.0",
				Digest: &DigestMetadata{
					Algorithm: DigestAlgorithmSHA256,
					Value:     strings.Repeat("a", 64),
				},
			},
		},
		Runtime: &RuntimeRequirements{
			Driver:         RuntimeDriverMicroVM,
			IsolationLevel: IsolationLevelVM,
			Image:          &ImmutableRef{Kind: ReferenceKindOCIImage, Ref: "ghcr.io/acme/go-agent:1.2.0"},
			Launch: &LaunchRequirements{
				Descriptor: &launchassets.LaunchDescriptor{
					ID: "go-agent-launch",
				},
			},
		},
		Workspace: &WorkspaceRequirements{
			Mode:        WorkspaceModeClone,
			InputSource: WorkspaceInputRemoteRef,
			ReadOnly:    true,
		},
		Network: &NetworkRequirements{
			Profile:                NetworkProfileDenyByDefault,
			BlockPrivateNetworks:   &yes,
			BlockMetadataEndpoints: &yes,
			RouteHTTPSThroughProxy: &yes,
			Allow: []NetworkRule{{
				ID:    "github-api",
				Kind:  NetworkRuleCategoryDomain,
				Value: "api.github.com",
			}},
		},
		Credentials: &CredentialRequirements{
			DeliveryModes: []CredentialDeliveryMode{CredentialDeliveryModeHTTPProxy},
			Services: []CredentialService{{
				ID:            "openai",
				Domains:       []string{"api.openai.com"},
				DeliveryModes: []CredentialDeliveryMode{CredentialDeliveryModeHTTPProxy},
				Required:      true,
			}},
		},
		Setup: []SetupCommandMetadata{{
			ID:              "go-version",
			Command:         []string{"go", "version"},
			RequiresNetwork: false,
			TimeoutSeconds:  30,
		}},
	}

	raw := mustTemplateObject(t, tmpl)
	assertTemplateObjectKeys(t, raw, []string{"apiVersion", "kind", "metadata", "runtime", "workspace", "network", "credentials", "setup"})
	assertNestedTemplateKeys(t, raw, "metadata", []string{"id", "name", "version", "reference"})
	assertNestedTemplateKeys(t, raw, "runtime", []string{"driver", "isolationLevel", "image", "launch"})
	assertNestedTemplateKeys(t, raw, "workspace", []string{"mode", "inputSource", "readOnly"})
	assertNestedTemplateKeys(t, raw, "network", []string{"profile", "allow", "blockPrivateNetworks", "blockMetadataEndpoints", "routeHttpsThroughProxy"})
	assertNestedTemplateKeys(t, raw, "credentials", []string{"deliveryModes", "services"})

	runtime := raw["runtime"].(map[string]any)
	launch := runtime["launch"].(map[string]any)
	if _, ok := launch["descriptor"].(map[string]any); !ok {
		t.Fatalf("runtime.launch.descriptor = %#v, want embedded Phase 41 launch descriptor object", launch["descriptor"])
	}
}

func TestSandboxTemplateJSONOmitsOptionalMetadata(t *testing.T) {
	raw := mustTemplateObject(t, Template{Metadata: TemplateMetadata{ID: "minimal"}})
	assertTemplateObjectKeys(t, raw, []string{"metadata"})
	assertNestedTemplateKeys(t, raw, "metadata", []string{"id"})
}

func assertTemplateField(t *testing.T, typ reflect.Type, fieldName string, wantType reflect.Type, wantTag string) {
	t.Helper()
	field, ok := typ.FieldByName(fieldName)
	if !ok {
		t.Fatalf("%s missing field %s", typ.Name(), fieldName)
	}
	if field.Type != wantType {
		t.Fatalf("%s.%s type = %v, want %v", typ.Name(), fieldName, field.Type, wantType)
	}
	if got := string(field.Tag); got != wantTag {
		t.Fatalf("%s.%s tag = %q, want %q", typ.Name(), fieldName, got, wantTag)
	}
}

func mustTemplateObject(t *testing.T, value any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	return raw
}

func assertTemplateObjectKeys(t *testing.T, raw any, keys []string) {
	t.Helper()
	object, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("object = %T, want map", raw)
	}
	if len(object) != len(keys) {
		t.Fatalf("keys = %#v, want %#v", sortedTemplateKeys(object), keys)
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			t.Fatalf("keys = %#v, missing %q", sortedTemplateKeys(object), key)
		}
	}
}

func assertNestedTemplateKeys(t *testing.T, raw map[string]any, key string, keys []string) {
	t.Helper()
	nested, ok := raw[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object", key, raw[key])
	}
	assertTemplateObjectKeys(t, nested, keys)
}

func sortedTemplateKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
