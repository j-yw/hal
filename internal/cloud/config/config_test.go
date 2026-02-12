package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParse_ValidMinimal(t *testing.T) {
	data := []byte(`
defaultProfile: default
profiles:
  default:
    endpoint: https://cloud.example.com
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DefaultProfile != "default" {
		t.Errorf("DefaultProfile = %q, want %q", cfg.DefaultProfile, "default")
	}
	p := cfg.GetProfile("")
	if p == nil {
		t.Fatal("default profile not found")
	}
	if p.Endpoint != "https://cloud.example.com" {
		t.Errorf("Endpoint = %q, want %q", p.Endpoint, "https://cloud.example.com")
	}
}

func TestParse_ValidFullProfile(t *testing.T) {
	wait := true
	data := []byte(`
defaultProfile: prod
profiles:
  prod:
    mode: until_complete
    endpoint: https://cloud.example.com
    repo: org/repo
    base: main
    engine: claude
    authProfile: ap-123
    scope: prd-001
    wait: true
    pullPolicy: all
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	p := cfg.GetProfile("prod")
	if p == nil {
		t.Fatal("prod profile not found")
	}
	if p.Mode != ModeUntilComplete {
		t.Errorf("Mode = %q, want %q", p.Mode, ModeUntilComplete)
	}
	if p.Endpoint != "https://cloud.example.com" {
		t.Errorf("Endpoint = %q", p.Endpoint)
	}
	if p.Repo != "org/repo" {
		t.Errorf("Repo = %q", p.Repo)
	}
	if p.Base != "main" {
		t.Errorf("Base = %q", p.Base)
	}
	if p.Engine != "claude" {
		t.Errorf("Engine = %q", p.Engine)
	}
	if p.AuthProfile != "ap-123" {
		t.Errorf("AuthProfile = %q", p.AuthProfile)
	}
	if p.Scope != "prd-001" {
		t.Errorf("Scope = %q", p.Scope)
	}
	if p.Wait == nil || *p.Wait != wait {
		t.Errorf("Wait = %v, want %v", p.Wait, &wait)
	}
	if p.PullPolicy != PullPolicyAll {
		t.Errorf("PullPolicy = %q, want %q", p.PullPolicy, PullPolicyAll)
	}
}

func TestParse_MultipleProfiles(t *testing.T) {
	data := []byte(`
defaultProfile: dev
profiles:
  dev:
    mode: bounded_batch
    endpoint: https://dev.example.com
  prod:
    mode: until_complete
    endpoint: https://prod.example.com
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Profiles) != 2 {
		t.Errorf("got %d profiles, want 2", len(cfg.Profiles))
	}
	dev := cfg.GetProfile("dev")
	if dev == nil || dev.Mode != ModeBoundedBatch {
		t.Errorf("dev profile mode = %v", dev)
	}
	prod := cfg.GetProfile("prod")
	if prod == nil || prod.Mode != ModeUntilComplete {
		t.Errorf("prod profile mode = %v", prod)
	}
}

func TestParse_EmptyProfiles(t *testing.T) {
	data := []byte(`
defaultProfile: ""
profiles: {}
`)
	cfg, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Profiles) != 0 {
		t.Errorf("expected empty profiles, got %d", len(cfg.Profiles))
	}
}

func TestParse_NullProfileEntry(t *testing.T) {
	data := []byte(`
profiles:
  default: null
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected validation error for null profile entry")
	}
	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T: %v", err, err)
	}
	found := false
	for _, e := range verrs {
		if e.Field == "profiles.default" && e.Rule == "invalid_value" {
			found = true
			if !strings.Contains(e.Remediation, "not null") {
				t.Errorf("expected remediation to mention null profile value: %q", e.Remediation)
			}
			break
		}
	}
	if !found {
		t.Errorf("expected invalid_value error for null profile, got: %v", verrs)
	}
}

func TestParse_InvalidMode(t *testing.T) {
	data := []byte(`
profiles:
  default:
    mode: invalid_mode
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected validation error for invalid mode")
	}
	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T: %v", err, err)
	}
	if len(verrs) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(verrs), verrs)
	}
	e := verrs[0]
	if e.Field != "profiles.default.mode" {
		t.Errorf("Field = %q", e.Field)
	}
	if e.Rule != "invalid_value" {
		t.Errorf("Rule = %q", e.Rule)
	}
	if !strings.Contains(e.Remediation, "until_complete") {
		t.Errorf("Remediation should list valid values: %q", e.Remediation)
	}
}

func TestParse_InvalidPullPolicy(t *testing.T) {
	data := []byte(`
profiles:
  default:
    pullPolicy: none
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected validation error for invalid pullPolicy")
	}
	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}
	if len(verrs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(verrs))
	}
	if verrs[0].Field != "profiles.default.pullPolicy" {
		t.Errorf("Field = %q", verrs[0].Field)
	}
	if verrs[0].Rule != "invalid_value" {
		t.Errorf("Rule = %q", verrs[0].Rule)
	}
}

func TestParse_InvalidEndpoint(t *testing.T) {
	data := []byte(`
profiles:
  default:
    endpoint: "not a url"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected validation error for invalid endpoint")
	}
	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}
	found := false
	for _, e := range verrs {
		if e.Field == "profiles.default.endpoint" && e.Rule == "invalid_url" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected invalid_url error for endpoint, got: %v", verrs)
	}
}

func TestParse_EndpointWithSecretQuery(t *testing.T) {
	data := []byte(`
profiles:
  default:
    endpoint: "https://cloud.example.com?authToken=secret123"
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected validation error for endpoint with secret query")
	}
	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}
	found := false
	for _, e := range verrs {
		if e.Field == "profiles.default.endpoint" && e.Rule == "secret_in_url" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected secret_in_url error, got: %v", verrs)
	}
}

func TestParse_UnknownDefaultProfile(t *testing.T) {
	data := []byte(`
defaultProfile: nonexistent
profiles:
  default:
    mode: until_complete
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected validation error for unknown defaultProfile")
	}
	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}
	found := false
	for _, e := range verrs {
		if e.Field == "defaultProfile" && e.Rule == "unknown_profile" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected unknown_profile error, got: %v", verrs)
	}
}

func TestParse_SecretFieldRejection(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantField string
	}{
		{
			name: "top-level token",
			yaml: `
token: "my-secret-token"
profiles: {}
`,
			wantField: "token",
		},
		{
			name: "top-level password",
			yaml: `
password: "hunter2"
profiles: {}
`,
			wantField: "password",
		},
		{
			name: "top-level secret",
			yaml: `
secret: "shhh"
profiles: {}
`,
			wantField: "secret",
		},
		{
			name: "top-level api_key",
			yaml: `
api_key: "key-123"
profiles: {}
`,
			wantField: "api_key",
		},
		{
			name: "top-level dsn",
			yaml: `
dsn: "postgres://user:pass@host/db"
profiles: {}
`,
			wantField: "dsn",
		},
		{
			name: "top-level credentials",
			yaml: `
credentials: "cred-value"
profiles: {}
`,
			wantField: "credentials",
		},
		{
			name: "nested secret in profile",
			yaml: `
profiles:
  default:
    token: "nested-secret"
`,
			wantField: "profiles.default.token",
		},
		{
			name: "deeply nested private_key",
			yaml: `
profiles:
  prod:
    private_key: "-----BEGIN RSA-----"
`,
			wantField: "profiles.prod.private_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected secret rejection error")
			}
			verrs, ok := err.(ValidationErrors)
			if !ok {
				t.Fatalf("expected ValidationErrors, got %T: %v", err, err)
			}
			found := false
			for _, e := range verrs {
				if e.Field == tt.wantField && e.Rule == "secret_field" {
					found = true
					if !strings.Contains(e.Remediation, "environment variables") {
						t.Errorf("Remediation should suggest environment variables: %q", e.Remediation)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected secret_field error for %q, got: %v", tt.wantField, verrs)
			}
		})
	}
}

func TestParse_MultipleErrors(t *testing.T) {
	data := []byte(`
defaultProfile: nonexistent
profiles:
  default:
    mode: bad_mode
    pullPolicy: bad_policy
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected multiple validation errors")
	}
	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}
	if len(verrs) < 2 {
		t.Errorf("expected at least 2 errors, got %d: %v", len(verrs), verrs)
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	data := []byte(`{{{invalid yaml}}}`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected parse error")
	}
	if strings.Contains(err.Error(), "secret_field") {
		t.Errorf("should be a parse error, not a secret error: %v", err)
	}
}

func TestGetProfile_Empty(t *testing.T) {
	cfg := &CloudConfig{
		Profiles: map[string]*Profile{},
	}
	if p := cfg.GetProfile(""); p != nil {
		t.Errorf("expected nil for empty name with no default, got %v", p)
	}
	if p := cfg.GetProfile("nonexistent"); p != nil {
		t.Errorf("expected nil for nonexistent profile, got %v", p)
	}
}

func TestGetProfile_UsesDefault(t *testing.T) {
	cfg := &CloudConfig{
		DefaultProfile: "myprofile",
		Profiles: map[string]*Profile{
			"myprofile": {Mode: ModeUntilComplete},
		},
	}
	p := cfg.GetProfile("")
	if p == nil {
		t.Fatal("expected default profile")
	}
	if p.Mode != ModeUntilComplete {
		t.Errorf("Mode = %q, want %q", p.Mode, ModeUntilComplete)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/cloud.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cloud.yaml")

	content := `
defaultProfile: test
profiles:
  test:
    mode: bounded_batch
    endpoint: https://test.example.com
    repo: owner/repo
    base: main
    engine: claude
    authProfile: ap-test
    wait: false
    pullPolicy: state
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p := cfg.GetProfile("test")
	if p == nil {
		t.Fatal("test profile not found")
	}
	if p.Mode != ModeBoundedBatch {
		t.Errorf("Mode = %q", p.Mode)
	}
	if p.Repo != "owner/repo" {
		t.Errorf("Repo = %q", p.Repo)
	}
	if p.Wait == nil || *p.Wait != false {
		t.Errorf("Wait = %v", p.Wait)
	}
	if p.PullPolicy != PullPolicyState {
		t.Errorf("PullPolicy = %q", p.PullPolicy)
	}
}

func TestValidate_EmptyConfig(t *testing.T) {
	cfg := &CloudConfig{
		Profiles: map[string]*Profile{},
	}
	errs := cfg.Validate()
	if errs != nil {
		t.Errorf("expected nil for empty config, got: %v", errs)
	}
}

func TestValidate_ValidEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{"https", "https://cloud.example.com", false},
		{"http", "http://localhost:8080", false},
		{"with path", "https://cloud.example.com/api/v1", false},
		{"missing scheme", "cloud.example.com", true},
		{"empty", "", false}, // empty is allowed (optional)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &CloudConfig{
				Profiles: map[string]*Profile{
					"test": {Endpoint: tt.endpoint},
				},
			}
			errs := cfg.Validate()
			if tt.wantErr && errs == nil {
				t.Error("expected validation error")
			}
			if !tt.wantErr && errs != nil {
				t.Errorf("unexpected error: %v", errs)
			}
		})
	}
}

func TestValidationError_ErrorFormat(t *testing.T) {
	e := &ValidationError{
		Field:       "profiles.default.mode",
		Rule:        "invalid_value",
		Remediation: "mode must be one of: bounded_batch, until_complete; got \"bad\"",
	}
	got := e.Error()
	if !strings.Contains(got, "profiles.default.mode") {
		t.Errorf("missing field path in error: %q", got)
	}
	if !strings.Contains(got, "invalid_value") {
		t.Errorf("missing rule in error: %q", got)
	}
	if !strings.Contains(got, "mode must be") {
		t.Errorf("missing remediation in error: %q", got)
	}
}

func TestValidationErrors_MultipleError(t *testing.T) {
	errs := ValidationErrors{
		{Field: "a", Rule: "r1", Remediation: "fix a"},
		{Field: "b", Rule: "r2", Remediation: "fix b"},
	}
	got := errs.Error()
	if !strings.Contains(got, "a: r1") || !strings.Contains(got, "b: r2") {
		t.Errorf("multi-error string should contain both: %q", got)
	}
}

func TestParse_WaitBoolean(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		wantWait *bool
	}{
		{
			name: "wait true",
			yaml: `
profiles:
  default:
    wait: true
`,
			wantWait: boolPtr(true),
		},
		{
			name: "wait false",
			yaml: `
profiles:
  default:
    wait: false
`,
			wantWait: boolPtr(false),
		},
		{
			name: "wait omitted",
			yaml: `
profiles:
  default:
    mode: until_complete
`,
			wantWait: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			p := cfg.GetProfile("default")
			if p == nil {
				t.Fatal("profile not found")
			}
			if tt.wantWait == nil && p.Wait != nil {
				t.Errorf("Wait = %v, want nil", p.Wait)
			}
			if tt.wantWait != nil {
				if p.Wait == nil {
					t.Fatalf("Wait = nil, want %v", *tt.wantWait)
				}
				if *p.Wait != *tt.wantWait {
					t.Errorf("Wait = %v, want %v", *p.Wait, *tt.wantWait)
				}
			}
		})
	}
}

func TestParse_SecretInEndpointQueryParams(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{"clean URL", "https://cloud.example.com", false},
		{"authToken param", "https://cloud.example.com?authToken=secret", true},
		{"token param", "https://cloud.example.com?token=abc", true},
		{"password param", "https://cloud.example.com?password=abc", true},
		{"safe param", "https://cloud.example.com?region=us-east", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := []byte(`
profiles:
  default:
    endpoint: "` + tt.endpoint + `"
`)
			_, err := Parse(data)
			if tt.wantErr && err == nil {
				t.Error("expected error for secret in URL query")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestParse_SecretValueInNonEndpointField(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantField string
		wantRule  string
	}{
		{
			name: "scope field with authToken query param",
			yaml: `
profiles:
  default:
    scope: "https://api.example.com/scope?authToken=secret123"
`,
			wantField: "profiles.default.scope",
			wantRule:  "secret_in_url",
		},
		{
			name: "repo field with token query param",
			yaml: `
profiles:
  default:
    repo: "https://api.example.com/repo?token=abc"
`,
			wantField: "profiles.default.repo",
			wantRule:  "secret_in_url",
		},
		{
			name: "top-level unknown field with secret query param",
			yaml: `
callback: "https://example.com/hook?password=hunter2"
profiles: {}
`,
			wantField: "callback",
			wantRule:  "secret_in_url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected secret value rejection error")
			}
			verrs, ok := err.(ValidationErrors)
			if !ok {
				t.Fatalf("expected ValidationErrors, got %T: %v", err, err)
			}
			found := false
			for _, e := range verrs {
				if e.Field == tt.wantField && e.Rule == tt.wantRule {
					found = true
					if !strings.Contains(e.Remediation, "environment variables") {
						t.Errorf("Remediation should suggest environment variables: %q", e.Remediation)
					}
					break
				}
			}
			if !found {
				t.Errorf("expected %s error for %q, got: %v", tt.wantRule, tt.wantField, verrs)
			}
		})
	}
}

func TestParse_SecretDetectionFailsFastBeforeValidation(t *testing.T) {
	// Secret detection must fail before structural validation.
	// This YAML has both a secret field AND an invalid mode — the secret
	// should be caught first by detectSecrets, before Validate runs.
	data := []byte(`
token: "my-secret"
profiles:
  default:
    mode: invalid_mode
`)
	_, err := Parse(data)
	if err == nil {
		t.Fatal("expected error")
	}
	verrs, ok := err.(ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T: %v", err, err)
	}
	// All errors should be secret_field — not invalid_value from Validate().
	for _, e := range verrs {
		if e.Rule == "invalid_value" {
			t.Errorf("Validate() ran before secret detection completed; got rule %q for %q", e.Rule, e.Field)
		}
	}
	// Must have at least one secret_field error.
	found := false
	for _, e := range verrs {
		if e.Rule == "secret_field" && e.Field == "token" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected secret_field error for 'token', got: %v", verrs)
	}
}

func TestParse_SecretValueSafeStringsAllowed(t *testing.T) {
	// Non-URL strings and URLs without secret params should pass.
	data := []byte(`
profiles:
  default:
    scope: "prd-001"
    repo: "org/myrepo"
    base: "main"
    engine: "claude"
    authProfile: "ap-123"
    endpoint: "https://cloud.example.com?region=us-east"
`)
	_, err := Parse(data)
	if err != nil {
		t.Fatalf("unexpected error for safe values: %v", err)
	}
}

func TestValidationError_ErrorFormatWithSecretRule(t *testing.T) {
	e := &ValidationError{
		Field:       "profiles.prod.token",
		Rule:        "secret_field",
		Remediation: `field "token" looks like a secret and must not be stored in cloud.yaml; use environment variables or a secrets manager instead`,
	}
	got := e.Error()
	if !strings.Contains(got, "profiles.prod.token") {
		t.Errorf("missing field path in error: %q", got)
	}
	if !strings.Contains(got, "secret_field") {
		t.Errorf("missing rule in error: %q", got)
	}
	if !strings.Contains(got, "environment variables") {
		t.Errorf("missing remediation guidance in error: %q", got)
	}
}

func TestValidationError_ErrorFormatWithSecretInURL(t *testing.T) {
	e := &ValidationError{
		Field:       "profiles.default.scope",
		Rule:        "secret_in_url",
		Remediation: `value of "scope" contains a URL with secret-bearing query parameters (authToken, token, password, secret); use environment variables for secrets`,
	}
	got := e.Error()
	if !strings.Contains(got, "profiles.default.scope") {
		t.Errorf("missing field path in error: %q", got)
	}
	if !strings.Contains(got, "secret_in_url") {
		t.Errorf("missing rule in error: %q", got)
	}
	if !strings.Contains(got, "environment variables") {
		t.Errorf("missing remediation guidance in error: %q", got)
	}
}

func boolPtr(b bool) *bool {
	return &b
}
