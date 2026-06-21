package factory

import "testing"

func TestRunSecretRedactorRedactsSingleValue(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "ghp_factory_secret_value_123"},
	})

	got := redactor.RedactString("using token ghp_factory_secret_value_123 for checkout")
	want := "using token " + RunSecretRedactionPlaceholder + " for checkout"
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorRedactsMultipleValues(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "ghp_factory_secret_value_123"},
		{Name: "NPM_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "npm_factory_secret_value_456"},
	})

	got := redactor.RedactString("git=ghp_factory_secret_value_123 npm=npm_factory_secret_value_456")
	want := "git=" + RunSecretRedactionPlaceholder + " npm=" + RunSecretRedactionPlaceholder
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorRedactsRepeatedValue(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "ghp_factory_secret_value_123"},
	})

	got := redactor.RedactString("ghp_factory_secret_value_123 then ghp_factory_secret_value_123")
	want := RunSecretRedactionPlaceholder + " then " + RunSecretRedactionPlaceholder
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorIgnoresEmptyValues(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "EMPTY_TOKEN", Source: RunSecretSourceEnv, Required: false, Value: ""},
		{Name: "SPACE_TOKEN", Source: RunSecretSourceEnv, Required: false, Value: " \t "},
	})

	got := redactor.RedactString("factory output should remain unchanged")
	want := "factory output should remain unchanged"
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorPrefersLongestValue(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "SHORT", Source: RunSecretSourceEnv, Required: true, Value: "token"},
		{Name: "LONG", Source: RunSecretSourceEnv, Required: true, Value: "token-extra"},
	})

	got := redactor.RedactString("token-extra token")
	want := RunSecretRedactionPlaceholder + " " + RunSecretRedactionPlaceholder
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorRedactsMultilineValueFragments(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "PRIVATE_KEY", Source: RunSecretSourceEnv, Required: true, Value: "-----BEGIN PRIVATE KEY-----\nline_one_secret_fragment\nline_two_secret_fragment\n-----END PRIVATE KEY-----"},
	})

	got := redactor.RedactString("key fragment line_one_secret_fragment\nnext line line_two_secret_fragment")
	want := "key fragment " + RunSecretRedactionPlaceholder + "\nnext line " + RunSecretRedactionPlaceholder
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}
