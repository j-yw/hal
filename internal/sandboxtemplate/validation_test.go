package sandboxtemplate

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateTemplateAcceptsSafeMetadataAndNormalizesDirectWorkspace(t *testing.T) {
	tmpl := validTemplateForValidation()
	tmpl.Workspace = &WorkspaceRequirements{Mode: WorkspaceMode(" DIRECT "), InputSource: WorkspaceInputCopy}

	result := ValidateTemplate(tmpl)
	if !result.Valid {
		t.Fatalf("ValidateTemplate() errors = %#v, want valid", result.Errors)
	}
	if result.Normalized == nil || result.Normalized.Workspace == nil {
		t.Fatalf("normalized workspace = %#v", result.Normalized)
	}
	if result.Normalized.Workspace.Mode != WorkspaceModeDirect {
		t.Fatalf("workspace mode = %q, want direct", result.Normalized.Workspace.Mode)
	}
	if !result.Normalized.Workspace.Unsafe {
		t.Fatalf("direct workspace should be marked unsafe when not trusted: %#v", result.Normalized.Workspace)
	}

	tmpl.Workspace = &WorkspaceRequirements{Mode: WorkspaceModeClone}
	result = ValidateTemplate(tmpl)
	if !result.Valid {
		t.Fatalf("clone ValidateTemplate() errors = %#v, want valid", result.Errors)
	}
	if result.Normalized.Workspace.Unsafe {
		t.Fatalf("clone workspace must not be unsafe by default: %#v", result.Normalized.Workspace)
	}
}

func TestValidateTemplateRejectsUnsafeCoreReferencesAndDigestValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Template)
		want   ValidationCode
		field  string
	}{
		{
			name: "unsafe template id",
			mutate: func(tmpl *Template) {
				tmpl.Metadata.ID = "https://token@example.invalid/template"
			},
			want:  ValidationUnsafeID,
			field: "metadata.id",
		},
		{
			name: "credential bearing image reference",
			mutate: func(tmpl *Template) {
				tmpl.Runtime.Image.Ref = "https://user:token@example.invalid/image"
			},
			want:  ValidationUnsafeReference,
			field: "runtime.image.ref",
		},
		{
			name: "raw host path launch descriptor reference",
			mutate: func(tmpl *Template) {
				tmpl.Runtime.Launch = &LaunchRequirements{DescriptorRef: &ImmutableRef{Kind: ReferenceKindLocal, Ref: "/Users/v/kernel"}}
			},
			want:  ValidationUnsafeReference,
			field: "runtime.launch.descriptorRef.ref",
		},
		{
			name: "malformed digest",
			mutate: func(tmpl *Template) {
				tmpl.Metadata.Reference.Digest.Value = "not-a-digest"
			},
			want:  ValidationMalformedDigest,
			field: "metadata.reference.digest.value",
		},
		{
			name: "unsafe credential domain",
			mutate: func(tmpl *Template) {
				tmpl.Credentials.Services[0].Domains = []string{"https://api.openai.com?token=secret"}
			},
			want:  ValidationUnsafeDomain,
			field: "credentials.services.domains",
		},
		{
			name: "unsafe setup id",
			mutate: func(tmpl *Template) {
				tmpl.Setup[0].ID = "../setup"
			},
			want:  ValidationUnsafeID,
			field: "setup.id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := validTemplateForValidation()
			tt.mutate(&tmpl)
			result := ValidateTemplate(tmpl)
			assertTemplateInvalid(t, result, tt.want, tt.field)
			assertValidationDoesNotLeak(t, result, "token", "/Users/v", "example.invalid", "not-a-digest")
		})
	}
}

func TestValidateTemplateRejectsUnsafeURLsPathsSecretsAndCommands(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Template)
		want   ValidationCode
	}{
		{
			name: "query reference",
			mutate: func(tmpl *Template) {
				tmpl.Metadata.Reference.Ref = "ghcr.io/acme/template:1.0?token=secret"
			},
			want: ValidationUnsafeReference,
		},
		{
			name: "fragment reference",
			mutate: func(tmpl *Template) {
				tmpl.Metadata.Reference.Ref = "ghcr.io/acme/template:1.0#secret"
			},
			want: ValidationUnsafeReference,
		},
		{
			name: "unsafe scheme",
			mutate: func(tmpl *Template) {
				tmpl.Metadata.Reference.Ref = "ftp://example.invalid/template"
			},
			want: ValidationUnsafeReference,
		},
		{
			name: "bearer setup command",
			mutate: func(tmpl *Template) {
				tmpl.Setup[0].Command = []string{"curl", "-H", "Authorization: Bearer secret"}
			},
			want: ValidationUnsafeCommand,
		},
		{
			name: "shell payload",
			mutate: func(tmpl *Template) {
				tmpl.Setup[0].Command = []string{"sh", "-c", "echo secret"}
			},
			want: ValidationUnsafeCommand,
		},
		{
			name: "raw setup path",
			mutate: func(tmpl *Template) {
				tmpl.Setup[0].WorkDir = "/tmp/project"
			},
			want: ValidationUnsafePath,
		},
		{
			name: "raw network IP",
			mutate: func(tmpl *Template) {
				tmpl.Network.Allow[0].Value = "169.254.169.254"
			},
			want: ValidationUnsafeDomain,
		},
		{
			name: "secret looking credential service",
			mutate: func(tmpl *Template) {
				tmpl.Credentials.Services[0].ID = "sk-secret"
			},
			want: ValidationUnsafeID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := validTemplateForValidation()
			tt.mutate(&tmpl)
			result := ValidateTemplate(tmpl)
			if result.Valid {
				t.Fatalf("ValidateTemplate() valid, want %s error", tt.want)
			}
			assertValidationHasCode(t, result, tt.want)
			assertValidationDoesNotLeak(t, result, "secret", "/tmp/project", "169.254.169.254", "example.invalid")
		})
	}
}

func TestReferenceDigestPinnedDoesNotInferMissingDigests(t *testing.T) {
	pinned := &ImmutableRef{
		Kind: ReferenceKindOCIArtifact,
		Ref:  "ghcr.io/acme/template:1.0",
		Digest: &DigestMetadata{
			Algorithm: DigestAlgorithmSHA256,
			Value:     strings.Repeat("a", 64),
		},
	}
	if !ReferenceDigestPinned(pinned) {
		t.Fatal("ReferenceDigestPinned(pinned) = false, want true")
	}
	if ReferenceDigestPinned(&ImmutableRef{Kind: ReferenceKindOCIArtifact, Ref: "ghcr.io/acme/template:1.0"}) {
		t.Fatal("ReferenceDigestPinned(unpinned) = true, want false")
	}
	if ReferenceDigestPinned(&ImmutableRef{Kind: ReferenceKindOCIArtifact, Digest: &DigestMetadata{Algorithm: DigestAlgorithmSHA256, Value: "bad"}}) {
		t.Fatal("ReferenceDigestPinned(malformed) = true, want false")
	}
}

func TestValidateTemplateDoesNotMutateCallerInput(t *testing.T) {
	tmpl := validTemplateForValidation()
	originalID := tmpl.Metadata.ID
	result := ValidateTemplate(tmpl)
	if !result.Valid {
		t.Fatalf("ValidateTemplate() errors = %#v, want valid", result.Errors)
	}
	result.Normalized.Metadata.ID = "changed"
	if tmpl.Metadata.ID != originalID {
		t.Fatalf("caller metadata id mutated to %q", tmpl.Metadata.ID)
	}
}

func validTemplateForValidation() Template {
	return Template{
		APIVersion: TemplateAPIVersionV1,
		Kind:       TemplateKindSandbox,
		Metadata: TemplateMetadata{
			ID:      "codex-go",
			Version: "1.2.0",
			Reference: &ImmutableRef{
				Kind: ReferenceKindOCIArtifact,
				Ref:  "ghcr.io/acme/template:1.2.0",
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
		},
		Workspace: &WorkspaceRequirements{Mode: WorkspaceModeClone, InputSource: WorkspaceInputRemoteRef},
		Network: &NetworkRequirements{
			Profile: NetworkProfileDenyByDefault,
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
			DisplayName:     "Go version",
			Tools:           []string{"go"},
			Command:         []string{"go", "version"},
			WorkDir:         ".",
			RequiresNetwork: false,
			TimeoutSeconds:  30,
		}},
	}
}

func assertTemplateInvalid(t *testing.T, result ValidationResult, code ValidationCode, field string) {
	t.Helper()
	if result.Valid {
		t.Fatalf("ValidateTemplate() valid, want invalid")
	}
	for _, err := range result.Errors {
		if err.Code == code && err.Field == field {
			return
		}
	}
	t.Fatalf("errors = %#v, want code %q field %q", result.Errors, code, field)
}

func assertValidationHasCode(t *testing.T, result ValidationResult, code ValidationCode) {
	t.Helper()
	for _, err := range result.Errors {
		if err.Code == code {
			return
		}
	}
	t.Fatalf("errors = %#v, want code %q", result.Errors, code)
}

func assertValidationDoesNotLeak(t *testing.T, result ValidationResult, values ...string) {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(ValidationResult) error = %v", err)
	}
	payload := string(data)
	for _, value := range values {
		if strings.Contains(payload, value) {
			t.Fatalf("validation result leaked %q in %s", value, payload)
		}
	}
}
