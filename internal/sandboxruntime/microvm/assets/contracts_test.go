package assets

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestLaunchAssetContractConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "kernel role", got: string(AssetRoleKernel), want: "kernel"},
		{name: "rootfs role", got: string(AssetRoleRootfs), want: "rootfs"},
		{name: "initrd role", got: string(AssetRoleInitrd), want: "initrd"},
		{name: "guest init config role", got: string(AssetRoleGuestInitConfig), want: "guest_init_config"},
		{name: "guest agent config role", got: string(AssetRoleGuestAgentConfig), want: "guest_agent_config"},
		{name: "kernel image kind", got: string(AssetKindKernelImage), want: "kernel_image"},
		{name: "rootfs image kind", got: string(AssetKindRootfsImage), want: "rootfs_image"},
		{name: "initrd image kind", got: string(AssetKindInitrdImage), want: "initrd_image"},
		{name: "guest config kind", got: string(AssetKindGuestConfig), want: "guest_config"},
		{name: "agent config kind", got: string(AssetKindAgentConfig), want: "agent_config"},
		{name: "local file source", got: string(SourceTypeLocalFile), want: "local_file"},
		{name: "generated source", got: string(SourceTypeGenerated), want: "generated"},
		{name: "embedded source", got: string(SourceTypeEmbedded), want: "embedded"},
		{name: "sha256 algorithm", got: string(DigestAlgorithmSHA256), want: "sha256"},
		{name: "sha384 algorithm", got: string(DigestAlgorithmSHA384), want: "sha384"},
		{name: "sha512 algorithm", got: string(DigestAlgorithmSHA512), want: "sha512"},
		{name: "launch input host path role", got: string(HostPathRoleLaunchInput), want: "launch_input"},
		{name: "resolved local host path role", got: string(HostPathRoleResolvedLocalAsset), want: "resolved_local_asset"},
		{name: "unsafe id code", got: string(ValidationUnsafeID), want: "unsafe_id"},
		{name: "unsafe label code", got: string(ValidationUnsafeLabel), want: "unsafe_label"},
		{name: "malformed digest value code", got: string(ValidationMalformedDigestValue), want: "malformed_digest_value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("constant = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestLaunchAssetContractFieldsAndJSONNames(t *testing.T) {
	descriptorType := reflect.TypeOf(LaunchDescriptor{})
	assertAssetField(t, descriptorType, "ID", reflect.TypeOf(SafeID("")), `json:"id,omitempty"`)
	assertAssetField(t, descriptorType, "Labels", reflect.TypeOf([]SafeLabel{}), `json:"labels,omitempty"`)
	assertAssetField(t, descriptorType, "Assets", reflect.TypeOf([]LaunchAsset{}), `json:"assets,omitempty"`)

	assetType := reflect.TypeOf(LaunchAsset{})
	assertAssetField(t, assetType, "ID", reflect.TypeOf(SafeID("")), `json:"id"`)
	assertAssetField(t, assetType, "Role", reflect.TypeOf(AssetRole("")), `json:"role"`)
	assertAssetField(t, assetType, "Kind", reflect.TypeOf(AssetKind("")), `json:"kind"`)
	assertAssetField(t, assetType, "Labels", reflect.TypeOf([]SafeLabel{}), `json:"labels,omitempty"`)
	assertAssetField(t, assetType, "Source", reflect.TypeOf(AssetSource{}), `json:"source"`)
	assertAssetField(t, assetType, "Lock", reflect.TypeOf(LockMetadata{}), `json:"lock"`)
	assertAssetField(t, assetType, "InitConfig", reflect.TypeOf((*InitConfigMetadata)(nil)), `json:"initConfig,omitempty"`)
	assertAssetField(t, assetType, "AgentConfig", reflect.TypeOf((*AgentConfigMetadata)(nil)), `json:"agentConfig,omitempty"`)
	assertAssetField(t, assetType, "Resources", reflect.TypeOf([]ResourceMetadata{}), `json:"resources,omitempty"`)

	sourceType := reflect.TypeOf(AssetSource{})
	assertAssetField(t, sourceType, "Type", reflect.TypeOf(SourceType("")), `json:"type"`)
	assertAssetField(t, sourceType, "HostPath", reflect.TypeOf((*HostPathMetadata)(nil)), `json:"hostPath,omitempty"`)

	hostPathType := reflect.TypeOf(HostPathMetadata{})
	assertAssetField(t, hostPathType, "Path", reflect.TypeOf(""), `json:"path,omitempty"`)
	assertAssetField(t, hostPathType, "Role", reflect.TypeOf(HostPathRole("")), `json:"role"`)

	lockType := reflect.TypeOf(LockMetadata{})
	assertAssetField(t, lockType, "Digest", reflect.TypeOf(DigestMetadata{}), `json:"digest"`)
	assertAssetField(t, lockType, "SizeBytes", reflect.TypeOf(int64(0)), `json:"sizeBytes,omitempty"`)
	assertAssetField(t, lockType, "LockedAtUnixMillis", reflect.TypeOf(int64(0)), `json:"lockedAtUnixMillis,omitempty"`)

	digestType := reflect.TypeOf(DigestMetadata{})
	assertAssetField(t, digestType, "Algorithm", reflect.TypeOf(DigestAlgorithm("")), `json:"algorithm"`)
	assertAssetField(t, digestType, "Value", reflect.TypeOf(""), `json:"value"`)

	initType := reflect.TypeOf(InitConfigMetadata{})
	assertAssetField(t, initType, "Format", reflect.TypeOf(SafeLabel("")), `json:"format,omitempty"`)
	assertAssetField(t, initType, "EntryPoint", reflect.TypeOf(SafeLabel("")), `json:"entryPoint,omitempty"`)
	assertAssetField(t, initType, "Labels", reflect.TypeOf([]SafeLabel{}), `json:"labels,omitempty"`)

	agentType := reflect.TypeOf(AgentConfigMetadata{})
	assertAssetField(t, agentType, "Protocol", reflect.TypeOf(SafeLabel("")), `json:"protocol,omitempty"`)
	assertAssetField(t, agentType, "Version", reflect.TypeOf(SafeLabel("")), `json:"version,omitempty"`)
	assertAssetField(t, agentType, "Features", reflect.TypeOf([]SafeLabel{}), `json:"features,omitempty"`)

	resourceType := reflect.TypeOf(ResourceMetadata{})
	assertAssetField(t, resourceType, "ID", reflect.TypeOf(SafeID("")), `json:"id,omitempty"`)
	assertAssetField(t, resourceType, "Kind", reflect.TypeOf(SafeLabel("")), `json:"kind,omitempty"`)
	assertAssetField(t, resourceType, "SizeBytes", reflect.TypeOf(int64(0)), `json:"sizeBytes,omitempty"`)
	assertAssetField(t, resourceType, "Labels", reflect.TypeOf([]SafeLabel{}), `json:"labels,omitempty"`)
}

func TestLaunchDescriptorJSONShapeIncludesSafeMetadata(t *testing.T) {
	descriptor := validLaunchDescriptorForTest()
	descriptor.Labels = []SafeLabel{"ubuntu-24.04", "phase41"}
	descriptor.Assets[0].InitConfig = &InitConfigMetadata{
		Format:     "cloud-init",
		EntryPoint: "init-v1",
		Labels:     []SafeLabel{"boot"},
	}
	descriptor.Assets[1].AgentConfig = &AgentConfigMetadata{
		Protocol: "guest-agent-v1",
		Version:  "v1.2.3",
		Features: []SafeLabel{
			"readiness",
			"exec",
		},
	}
	descriptor.Assets[1].Resources = []ResourceMetadata{
		{ID: "rootfs-metadata", Kind: "ext4", SizeBytes: 4096, Labels: []SafeLabel{"root"}},
	}

	object := mustMarshalAssetObject(t, descriptor)
	assertExactAssetObjectKeys(t, object, []string{"id", "labels", "assets"})

	assetObjects, ok := object["assets"].([]any)
	if !ok || len(assetObjects) != 2 {
		t.Fatalf("assets = %#v, want two asset objects", object["assets"])
	}
	kernel := assetObjects[0]
	assertExactAssetObjectKeys(t, kernel, []string{"id", "role", "kind", "source", "lock", "initConfig"})
	assertNestedAssetObjectKeys(t, kernel, "source", []string{"type", "hostPath"})
	sourceObject := kernel.(map[string]any)["source"].(map[string]any)
	assertNestedAssetObjectKeys(t, sourceObject, "hostPath", []string{"path", "role"})
	assertNestedAssetObjectKeys(t, kernel, "lock", []string{"digest", "sizeBytes", "lockedAtUnixMillis"})
	lockObject := kernel.(map[string]any)["lock"].(map[string]any)
	assertNestedAssetObjectKeys(t, lockObject, "digest", []string{"algorithm", "value"})
	assertNestedAssetObjectKeys(t, kernel, "initConfig", []string{"format", "entryPoint", "labels"})

	rootfs := assetObjects[1]
	assertExactAssetObjectKeys(t, rootfs, []string{"id", "role", "kind", "source", "lock", "agentConfig", "resources"})
	assertNestedAssetObjectKeys(t, rootfs, "agentConfig", []string{"protocol", "version", "features"})
	resources, ok := rootfs.(map[string]any)["resources"].([]any)
	if !ok || len(resources) != 1 {
		t.Fatalf("resources = %#v, want one resource object", rootfs.(map[string]any)["resources"])
	}
	assertExactAssetObjectKeys(t, resources[0], []string{"id", "kind", "sizeBytes", "labels"})
}

func TestLaunchDescriptorJSONOmitsAbsentOptionalMetadata(t *testing.T) {
	descriptor := validLaunchDescriptorForTest()

	object := mustMarshalAssetObject(t, descriptor)
	assertExactAssetObjectKeys(t, object, []string{"id", "assets"})

	assetObjects := object["assets"].([]any)
	for _, asset := range assetObjects {
		assetObject := asset.(map[string]any)
		assertExactAssetObjectKeys(t, assetObject, []string{"id", "role", "kind", "source", "lock"})
		if _, ok := assetObject["labels"]; ok {
			t.Fatal("empty asset labels should be omitted")
		}
		if _, ok := assetObject["initConfig"]; ok {
			t.Fatal("nil init config should be omitted")
		}
		if _, ok := assetObject["agentConfig"]; ok {
			t.Fatal("nil agent config should be omitted")
		}
		if _, ok := assetObject["resources"]; ok {
			t.Fatal("nil resources should be omitted")
		}
	}
}

func assertAssetField(t *testing.T, typ reflect.Type, fieldName string, wantType reflect.Type, wantTag string) {
	t.Helper()

	field, ok := typ.FieldByName(fieldName)
	if !ok {
		t.Fatalf("%s field missing from %s", fieldName, typ.Name())
	}
	if field.Type != wantType {
		t.Fatalf("%s.%s type = %v, want %v", typ.Name(), fieldName, field.Type, wantType)
	}
	if got := string(field.Tag); got != wantTag {
		t.Fatalf("%s.%s tag = %q, want %q", typ.Name(), fieldName, got, wantTag)
	}
}

func mustMarshalAssetObject(t *testing.T, value any) map[string]any {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", value, err)
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatalf("Unmarshal(%s) error: %v", encoded, err)
	}
	return out
}

func assertNestedAssetObjectKeys(t *testing.T, value any, key string, want []string) {
	t.Helper()

	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value = %#v, want object", value)
	}
	nested, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want nested object", key, object[key])
	}
	assertExactAssetObjectKeys(t, nested, want)
}

func assertExactAssetObjectKeys(t *testing.T, value any, want []string) {
	t.Helper()

	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value = %#v, want object", value)
	}
	got := make(map[string]bool, len(object))
	for key := range object {
		got[key] = true
	}
	if len(got) != len(want) {
		t.Fatalf("keys = %#v, want %v", got, want)
	}
	for _, key := range want {
		if !got[key] {
			t.Fatalf("keys = %#v, missing %q", got, key)
		}
	}
}
