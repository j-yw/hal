package livegate

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestGateCategoryConstantsAreStable(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "firecracker", got: string(GateCategoryFirecracker), want: "firecracker"},
		{name: "network enforcement", got: string(GateCategoryNetworkEnforcement), want: "network_enforcement"},
		{name: "credential delivery", got: string(GateCategoryCredentialDelivery), want: "credential_delivery"},
		{name: "worker integration", got: string(GateCategoryWorkerIntegration), want: "worker_integration"},
		{name: "podman integration", got: string(GateCategoryPodmanIntegration), want: "podman_integration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestLiveGateContractConstantsAreStable(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "build tag firecracker", got: string(BuildTagFirecrackerLive), want: "firecracker_live"},
		{name: "build tag network", got: string(BuildTagNetworkEnforcementLive), want: "network_enforcement_live"},
		{name: "build tag credential", got: string(BuildTagCredentialDeliveryLive), want: "credential_delivery_live"},
		{name: "build tag worker", got: string(BuildTagWorkerIntegrationLive), want: "worker_integration"},
		{name: "build tag podman", got: string(BuildTagPodmanIntegrationLive), want: "podman_integration"},
		{name: "env firecracker", got: string(EnvVarFirecrackerLive), want: "HAL_FIRECRACKER_LIVE"},
		{name: "env network", got: string(EnvVarNetworkEnforcementLive), want: "HAL_NETWORK_ENFORCEMENT_LIVE"},
		{name: "env credential", got: string(EnvVarCredentialDeliveryLive), want: "HAL_CREDENTIAL_DELIVERY_LIVE"},
		{name: "env worker", got: string(EnvVarWorkerIntegrationLive), want: "HAL_WORKER_INTEGRATION_LIVE"},
		{name: "env podman", got: string(EnvVarPodmanIntegrationLive), want: "HAL_PODMAN_INTEGRATION_LIVE"},
		{name: "capability firecracker", got: string(CapabilityFirecrackerMicroVM), want: "firecracker_microvm"},
		{name: "capability network", got: string(CapabilityNetworkEnforcement), want: "network_enforcement"},
		{name: "capability credential", got: string(CapabilityCredentialDelivery), want: "credential_delivery"},
		{name: "capability worker", got: string(CapabilityWorkerIntegration), want: "worker_integration"},
		{name: "capability podman", got: string(CapabilityPodmanIntegration), want: "podman_integration"},
		{name: "status satisfied", got: string(RequirementStatusSatisfied), want: "satisfied"},
		{name: "status missing", got: string(RequirementStatusMissing), want: "missing"},
		{name: "status unavailable", got: string(RequirementStatusUnavailable), want: "unavailable"},
		{name: "status skipped", got: string(RequirementStatusSkipped), want: "skipped"},
		{name: "reason missing build tag", got: string(SkipReasonMissingBuildTag), want: "missing_build_tag"},
		{name: "reason missing env", got: string(SkipReasonMissingEnvVar), want: "missing_env_var"},
		{name: "reason capability unavailable", got: string(SkipReasonCapabilityUnavailable), want: "capability_unavailable"},
		{name: "reason gate disabled", got: string(SkipReasonGateDisabled), want: "gate_disabled"},
		{name: "reason unsupported platform", got: string(SkipReasonUnsupportedPlatform), want: "unsupported_platform"},
		{name: "remediation enable build tag", got: string(RemediationEnableBuildTag), want: "enable_build_tag"},
		{name: "remediation set env var", got: string(RemediationSetEnvVar), want: "set_env_var"},
		{name: "remediation install capability", got: string(RemediationInstallCapability), want: "install_capability"},
		{name: "remediation template build tags", got: string(RemediationTemplateGoTestBuildTags), want: "go test -tags={{build_tags}} ./..."},
		{name: "remediation template env vars", got: string(RemediationTemplateGoTestEnvVars), want: "env {{env_vars}}=<set> go test ./..."},
		{name: "remediation template build tags and env vars", got: string(RemediationTemplateGoTestBuildTagsEnvVars), want: "env {{env_vars}}=<set> go test -tags={{build_tags}} ./..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestLiveGateJSONContainsOnlySafeContractFields(t *testing.T) {
	got := mustMarshalLiveGateObject(t, Gate{
		ID:       GateID("firecracker-live-gate"),
		Category: GateCategoryFirecracker,
		BuildTags: []BuildTagName{
			BuildTagFirecrackerLive,
			BuildTagNetworkEnforcementLive,
		},
		EnvVars: []EnvVarName{
			EnvVarFirecrackerLive,
		},
		Capabilities: []CapabilityID{
			CapabilityFirecrackerMicroVM,
			CapabilityNetworkEnforcement,
		},
		Requirements: []Requirement{
			{
				Status:     RequirementStatusMissing,
				BuildTag:   BuildTagFirecrackerLive,
				ReasonCode: SkipReasonMissingBuildTag,
				Remediation: &RemediationMetadata{
					ReasonCode:    SkipReasonMissingBuildTag,
					BuildTags:     []BuildTagName{BuildTagFirecrackerLive},
					CommandLabels: []RemediationCommandLabel{RemediationEnableBuildTag},
				},
			},
			{
				Status:     RequirementStatusSatisfied,
				EnvVar:     EnvVarFirecrackerLive,
				Capability: CapabilityFirecrackerMicroVM,
			},
		},
		Remediation: &RemediationMetadata{
			ReasonCode:       SkipReasonMissingEnvVar,
			BuildTags:        []BuildTagName{BuildTagFirecrackerLive},
			EnvVars:          []EnvVarName{EnvVarFirecrackerLive},
			Capabilities:     []CapabilityID{CapabilityFirecrackerMicroVM},
			CommandLabels:    []RemediationCommandLabel{RemediationEnableBuildTag, RemediationSetEnvVar},
			CommandTemplates: []RemediationCommandTemplate{RemediationTemplateGoTestBuildTagsEnvVars},
		},
	})

	assertLiveGateObjectKeys(t, got, []string{
		"gateId",
		"category",
		"buildTags",
		"envVars",
		"capabilities",
		"requirements",
		"remediation",
	})
	assertLiveGateStringArray(t, got["buildTags"], []string{"firecracker_live", "network_enforcement_live"})
	assertLiveGateStringArray(t, got["envVars"], []string{"HAL_FIRECRACKER_LIVE"})
	assertLiveGateStringArray(t, got["capabilities"], []string{"firecracker_microvm", "network_enforcement"})

	requirements, ok := got["requirements"].([]any)
	if !ok || len(requirements) != 2 {
		t.Fatalf("requirements = %#v, want two requirement objects", got["requirements"])
	}
	requirement := requireLiveGateObject(t, requirements[0])
	assertLiveGateObjectKeys(t, requirement, []string{"status", "buildTag", "reasonCode", "remediation"})
	remediation := requireLiveGateObject(t, got["remediation"])
	assertLiveGateObjectKeys(t, remediation, []string{"reasonCode", "buildTags", "envVars", "capabilities", "commandLabels", "commandTemplates"})
	assertLiveGateStringArray(t, remediation["commandLabels"], []string{"enable_build_tag", "set_env_var"})
	assertLiveGateStringArray(t, remediation["commandTemplates"], []string{"env {{env_vars}}=<set> go test -tags={{build_tags}} ./..."})
}

func TestLiveGateJSONRedactsUnsafeDynamicValues(t *testing.T) {
	got := mustMarshalLiveGateObject(t, Gate{
		ID:       GateID("https://gate.internal.example.com/live?token=secret"),
		Category: GateCategory(" FIRECRACKER "),
		BuildTags: []BuildTagName{
			BuildTagFirecrackerLive,
			BuildTagName("-tags=firecracker_live"),
			BuildTagName("http://tags.internal.example.com/live"),
		},
		EnvVars: []EnvVarName{
			EnvVarFirecrackerLive,
			EnvVarName("HAL_FIRECRACKER_LIVE=1"),
			EnvVarName("https://env.internal.example.com"),
		},
		Capabilities: []CapabilityID{
			CapabilityFirecrackerMicroVM,
			CapabilityID("/tmp/firecracker.sock"),
			CapabilityID("api.internal.example.com"),
		},
		Requirements: []Requirement{
			{
				Status:     RequirementStatus(" MISSING "),
				BuildTag:   BuildTagName("firecracker_live --run /tmp/socket"),
				EnvVar:     EnvVarName("HAL_FIRECRACKER_LIVE"),
				Capability: CapabilityID("firecracker_microvm"),
				ReasonCode: SkipReasonCode(" MISSING_ENV_VAR "),
				Remediation: &RemediationMetadata{
					ReasonCode:       SkipReasonCode(" MISSING_BUILD_TAG "),
					BuildTags:        []BuildTagName{BuildTagFirecrackerLive, BuildTagName("-tags=firecracker_live")},
					EnvVars:          []EnvVarName{EnvVarFirecrackerLive, EnvVarName("HAL_FIRECRACKER_LIVE=1")},
					Capabilities:     []CapabilityID{CapabilityFirecrackerMicroVM, CapabilityID("firecracker --api-sock /tmp/fc.sock")},
					CommandLabels:    []RemediationCommandLabel{RemediationEnableBuildTag, RemediationCommandLabel("go test -tags firecracker_live ./...")},
					CommandTemplates: []RemediationCommandTemplate{RemediationTemplateGoTestBuildTagsEnvVars, RemediationCommandTemplate("HAL_FIRECRACKER_LIVE=1 go test --api-sock /tmp/fc.sock")},
				},
			},
		},
		Remediation: &RemediationMetadata{
			ReasonCode: SkipReasonCode(" CAPABILITY_UNAVAILABLE "),
			BuildTags: []BuildTagName{
				BuildTagFirecrackerLive,
				BuildTagName("/Users/alice/.hal/tags"),
			},
			EnvVars: []EnvVarName{
				EnvVarFirecrackerLive,
				EnvVarName("Authorization: Bearer ghp_secret"),
			},
			Capabilities: []CapabilityID{
				CapabilityFirecrackerMicroVM,
				CapabilityID("http://127.0.0.1:8080/firecracker"),
			},
			CommandLabels: []RemediationCommandLabel{
				RemediationInstallCapability,
				RemediationCommandLabel("curl http://127.0.0.1:8080"),
			},
			CommandTemplates: []RemediationCommandTemplate{
				RemediationTemplateGoTestEnvVars,
				RemediationCommandTemplate("curl http://127.0.0.1:8080"),
			},
		},
	})

	assertLiveGateObjectKeys(t, got, []string{
		"category",
		"buildTags",
		"envVars",
		"capabilities",
		"requirements",
		"remediation",
	})
	if _, ok := got["gateId"]; ok {
		t.Fatalf("unsafe gate ID survived redaction: %#v", got)
	}
	assertLiveGateStringArray(t, got["buildTags"], []string{"firecracker_live"})
	assertLiveGateStringArray(t, got["envVars"], []string{"HAL_FIRECRACKER_LIVE"})
	assertLiveGateStringArray(t, got["capabilities"], []string{"firecracker_microvm"})

	requirements := got["requirements"].([]any)
	requirement := requireLiveGateObject(t, requirements[0])
	assertLiveGateObjectKeys(t, requirement, []string{"status", "envVar", "capability", "reasonCode", "remediation"})
	if _, ok := requirement["buildTag"]; ok {
		t.Fatalf("unsafe requirement build tag survived redaction: %#v", requirement)
	}
	if got := requirement["status"]; got != "missing" {
		t.Fatalf("requirement status = %#v, want missing", got)
	}
	if got := requirement["reasonCode"]; got != "missing_env_var" {
		t.Fatalf("requirement reasonCode = %#v, want missing_env_var", got)
	}

	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal sanitized object error: %v", err)
	}
	for _, unsafe := range []string{
		"secret",
		"ghp_",
		"http://",
		"https://",
		"127.0.0.1",
		"api.internal.example.com",
		"/tmp",
		"/Users/alice",
		"--api-sock",
		"Authorization",
		"Bearer",
		"HAL_FIRECRACKER_LIVE=1",
		"-tags=firecracker_live",
		"curl ",
		"--api-sock",
	} {
		if strings.Contains(string(encoded), unsafe) {
			t.Fatalf("sanitized gate JSON leaked unsafe fragment %q in %s", unsafe, encoded)
		}
	}
}

func TestLiveGateJSONOmitsSectionsEmptiedByRedaction(t *testing.T) {
	got := mustMarshalLiveGateObject(t, Gate{
		ID:           GateID("https://gate.internal.example.com/live?token=secret"),
		Category:     GateCategory("https://category.internal.example.com"),
		BuildTags:    []BuildTagName{BuildTagName("-tags=firecracker_live")},
		EnvVars:      []EnvVarName{EnvVarName("HAL_FIRECRACKER_LIVE=1")},
		Capabilities: []CapabilityID{CapabilityID("/tmp/firecracker.sock")},
		Requirements: []Requirement{
			{
				Status:     RequirementStatus("https://status.internal.example.com"),
				BuildTag:   BuildTagName("/tmp/buildtag"),
				EnvVar:     EnvVarName("Authorization: Bearer ghp_secret"),
				Capability: CapabilityID("api.internal.example.com"),
				ReasonCode: SkipReasonCode("http://reason.internal.example.com"),
				Remediation: &RemediationMetadata{
					CommandLabels: []RemediationCommandLabel{RemediationCommandLabel("go test -tags firecracker_live ./...")},
				},
			},
		},
		Remediation: &RemediationMetadata{
			CommandLabels:    []RemediationCommandLabel{RemediationCommandLabel("curl http://127.0.0.1:8080")},
			CommandTemplates: []RemediationCommandTemplate{RemediationCommandTemplate("curl http://127.0.0.1:8080")},
		},
	})

	assertLiveGateObjectKeys(t, got, []string{})
}

func TestLiveGatePublicSchemaContainsNoUnsafeFields(t *testing.T) {
	contractTypes := []reflect.Type{
		reflect.TypeOf(Gate{}),
		reflect.TypeOf(Requirement{}),
		reflect.TypeOf(CapabilityRequirement{}),
		reflect.TypeOf(RemediationMetadata{}),
		reflect.TypeOf(GatePreflightResult{}),
	}

	for _, typ := range contractTypes {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.PkgPath != "" {
					continue
				}
				jsonName := liveGateJSONName(t, typ.Name(), field)
				assertSafeLiveGateFieldName(t, typ.Name(), field.Name, jsonName)
				assertSafeLiveGateFieldType(t, typ.Name(), field)
			}
		})
	}
}

func mustMarshalLiveGateObject(t *testing.T, value any) map[string]any {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", value, err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("Unmarshal(%s) error: %v", data, err)
	}
	return object
}

func requireLiveGateObject(t *testing.T, value any) map[string]any {
	t.Helper()

	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value = %#v, want object", value)
	}
	return object
}

func assertLiveGateObjectKeys(t *testing.T, object map[string]any, want []string) {
	t.Helper()

	got := make([]string, 0, len(object))
	for key := range object {
		got = append(got, key)
	}
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("object keys = %#v, want %#v in object %#v", got, want, object)
	}
}

func assertLiveGateStringArray(t *testing.T, value any, want []string) {
	t.Helper()

	raw, ok := value.([]any)
	if !ok {
		t.Fatalf("value = %#v, want string array", value)
	}
	got := make([]string, 0, len(raw))
	for _, item := range raw {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("array item = %#v, want string", item)
		}
		got = append(got, text)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("string array = %#v, want %#v", got, want)
	}
}

func liveGateJSONName(t *testing.T, typeName string, field reflect.StructField) string {
	t.Helper()

	tag := field.Tag.Get("json")
	if tag == "" || tag == "-" {
		t.Fatalf("%s.%s missing public json tag", typeName, field.Name)
	}
	name := strings.Split(tag, ",")[0]
	if name == "" {
		t.Fatalf("%s.%s has empty json field name in tag %q", typeName, field.Name, tag)
	}
	return name
}

func assertSafeLiveGateFieldName(t *testing.T, typeName, fieldName, jsonName string) {
	t.Helper()

	lowerField := strings.ToLower(fieldName)
	lowerJSON := strings.ToLower(jsonName)
	for _, unsafe := range []string{
		"value",
		"path",
		"hostname",
		"host",
		"url",
		"uri",
		"socket",
		"token",
		"secret",
		"credentialvalue",
		"providerconfig",
		"processarg",
		"firewalldetail",
		"proxydetail",
		"endpoint",
		"address",
		"port",
	} {
		if strings.Contains(lowerField, unsafe) || strings.Contains(lowerJSON, unsafe) {
			t.Fatalf("%s.%s json %q exposes unsafe field category %q", typeName, fieldName, jsonName, unsafe)
		}
	}
}

func assertSafeLiveGateFieldType(t *testing.T, typeName string, field reflect.StructField) {
	t.Helper()

	typeText := field.Type.String()
	for _, unsafe := range []string{
		"net.",
		"http.",
		"url.",
		"os.File",
		"exec.",
		"cobra.",
		"sandboxworker.",
		"sandboxruntime.",
	} {
		if strings.Contains(typeText, unsafe) {
			t.Fatalf("%s.%s type %s exposes unsafe dependency marker %q", typeName, field.Name, typeText, unsafe)
		}
	}
}
