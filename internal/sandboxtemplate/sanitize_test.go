package sandboxtemplate

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSanitizeTemplatePreservesSafeMetadata(t *testing.T) {
	tmpl := validTemplateForValidation()
	tmpl.Setup[0].Tools = []string{"go", "make"}

	got := SanitizeTemplate(tmpl)
	if got.Metadata.ID != "codex-go" {
		t.Fatalf("metadata id = %q, want codex-go", got.Metadata.ID)
	}
	if got.Metadata.Reference == nil || !ReferenceDigestPinned(got.Metadata.Reference) {
		t.Fatalf("metadata reference = %#v, want digest-pinned reference", got.Metadata.Reference)
	}
	if got.Runtime == nil || got.Runtime.Driver != RuntimeDriverMicroVM {
		t.Fatalf("runtime = %#v, want microvm", got.Runtime)
	}
	if got.Network == nil || len(got.Network.Allow) != 1 || got.Network.Allow[0].Value != "api.github.com" {
		t.Fatalf("network allow = %#v", got.Network)
	}
	if got.Credentials == nil || got.Credentials.Services[0].ID != "openai" {
		t.Fatalf("credentials = %#v", got.Credentials)
	}
	if !reflect.DeepEqual(got.Setup[0].Tools, []string{"go", "make"}) {
		t.Fatalf("setup tools = %#v", got.Setup[0].Tools)
	}
}

func TestSanitizeTemplateRemovesUnsafeOptionalMetadata(t *testing.T) {
	tmpl := validTemplateForValidation()
	tmpl.Metadata.Reference.Ref = "https://user:token@example.invalid/template"
	tmpl.Metadata.Reference.Digest.Value = "bad"
	tmpl.Metadata.Labels = map[string]string{
		"safe": "value",
		"bad":  "Authorization: Bearer secret",
	}
	tmpl.Runtime.Image.Ref = "/Users/v/raw-image"
	tmpl.Network.Allow = append(tmpl.Network.Allow, NetworkRule{ID: "bad-rule", Kind: NetworkRuleCategoryDomain, Value: "169.254.169.254"})
	tmpl.Credentials.Services[0].Domains = append(tmpl.Credentials.Services[0].Domains, "https://api.openai.com?token=secret")
	tmpl.Setup[0].Command = append(tmpl.Setup[0].Command, "Authorization: Bearer secret")

	got := SanitizeTemplate(tmpl)
	if got.Metadata.Reference == nil || got.Metadata.Reference.Ref != "" || got.Metadata.Reference.Digest != nil {
		t.Fatalf("unsafe metadata reference = %#v, want unsafe ref and digest removed", got.Metadata.Reference)
	}
	if got.Metadata.Labels["bad"] != "" {
		t.Fatalf("unsafe label preserved: %#v", got.Metadata.Labels)
	}
	if got.Runtime.Image != nil && got.Runtime.Image.Ref != "" {
		t.Fatalf("unsafe runtime image ref preserved: %#v", got.Runtime.Image)
	}
	if len(got.Network.Allow) != 1 || got.Network.Allow[0].ID != "github-api" {
		t.Fatalf("network rules = %#v, want unsafe rule omitted", got.Network.Allow)
	}
	if len(got.Credentials.Services[0].Domains) != 1 || got.Credentials.Services[0].Domains[0] != "api.openai.com" {
		t.Fatalf("credential domains = %#v", got.Credentials.Services[0].Domains)
	}
	if !reflect.DeepEqual(got.Setup[0].Command, []string{"go", "version"}) {
		t.Fatalf("setup command = %#v, want unsafe command part removed", got.Setup[0].Command)
	}
}

func TestSanitizeTemplateOmitsUnsafeRequiredRecords(t *testing.T) {
	tmpl := validTemplateForValidation()
	tmpl.Metadata.ID = "sk-secret-template"
	if got := SanitizeTemplate(tmpl); got.Metadata.ID != "" {
		t.Fatalf("unsafe required template id produced %#v, want zero template", got)
	}

	tmpl = validTemplateForValidation()
	tmpl.Credentials.Services = append(tmpl.Credentials.Services, CredentialService{ID: "https://secret.example.invalid", Domains: []string{"api.example.com"}})
	tmpl.Setup = append(tmpl.Setup, SetupCommandMetadata{ID: "../unsafe", Command: []string{"go", "version"}})
	got := SanitizeTemplate(tmpl)
	if len(got.Credentials.Services) != 1 || got.Credentials.Services[0].ID != "openai" {
		t.Fatalf("credential services = %#v, want unsafe required service omitted", got.Credentials.Services)
	}
	if len(got.Setup) != 1 || got.Setup[0].ID != "go-version" {
		t.Fatalf("setup = %#v, want unsafe required setup omitted", got.Setup)
	}
}

func TestSanitizeTemplateReturnsCopiesAndPreservesNilAndEmptySlices(t *testing.T) {
	tmpl := validTemplateForValidation()
	got := SanitizeTemplate(tmpl)
	tmpl.Credentials.Services[0].Domains[0] = "changed.example.com"
	tmpl.Setup[0].Command[0] = "changed"
	if got.Credentials.Services[0].Domains[0] != "api.openai.com" {
		t.Fatalf("sanitized credentials aliased input: %#v", got.Credentials.Services[0].Domains)
	}
	if got.Setup[0].Command[0] != "go" {
		t.Fatalf("sanitized setup aliased input: %#v", got.Setup[0].Command)
	}

	empty := SanitizeTemplate(Template{
		Metadata:    TemplateMetadata{ID: "empty"},
		Network:     &NetworkRequirements{Allow: []NetworkRule{}},
		Credentials: &CredentialRequirements{DeliveryModes: []CredentialDeliveryMode{}, Services: []CredentialService{}},
		Setup:       []SetupCommandMetadata{},
	})
	if empty.Network.Allow == nil || len(empty.Network.Allow) != 0 {
		t.Fatalf("empty network allow = %#v, want non-nil empty", empty.Network.Allow)
	}
	if empty.Credentials.DeliveryModes == nil || empty.Credentials.Services == nil {
		t.Fatalf("empty credential slices = %#v, want non-nil empty", empty.Credentials)
	}
	if empty.Setup == nil || len(empty.Setup) != 0 {
		t.Fatalf("empty setup = %#v, want non-nil empty", empty.Setup)
	}

	nilSlices := SanitizeTemplate(Template{Metadata: TemplateMetadata{ID: "nil-slices"}, Network: &NetworkRequirements{}, Credentials: &CredentialRequirements{}})
	if nilSlices.Network.Allow != nil {
		t.Fatalf("nil network allow became %#v", nilSlices.Network.Allow)
	}
	if nilSlices.Credentials.DeliveryModes != nil || nilSlices.Credentials.Services != nil {
		t.Fatalf("nil credential slices became %#v", nilSlices.Credentials)
	}
}

func TestSanitizeTemplateDoesNotInsertRedactionPlaceholders(t *testing.T) {
	tmpl := validTemplateForValidation()
	tmpl.Metadata.Description = "Bearer secret"
	got := SanitizeTemplate(tmpl)
	payload := strings.ToLower(mustTemplateJSON(t, got))
	for _, forbidden := range []string{"redacted", "***", "bearer secret"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("sanitized template contains forbidden marker %q in %s", forbidden, payload)
		}
	}
}

func mustTemplateJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return string(data)
}
