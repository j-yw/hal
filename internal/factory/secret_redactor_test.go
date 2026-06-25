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

func TestRunSecretRedactorRedactsURLEncodedValues(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "p@ss word"},
	})

	got := redactor.RedactString("remote=https://x:p%40ss%20word@github.com/example/repo.git query=token=p%40ss+word")
	want := "remote=https://x:" + RunSecretRedactionPlaceholder + "@github.com/example/repo.git query=token=" + RunSecretRedactionPlaceholder
	if got != want {
		t.Fatalf("RedactString() = %q, want %q", got, want)
	}
}

func TestRunSecretRedactorRedactsArtifactSummaryTypedCollections(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: "ghp_factory_secret_value_123"},
	})

	got := redactor.RedactArtifactReference(ArtifactReference{
		Name: "artifact",
		Type: "json",
		Summary: map[string]any{
			"typed_maps": []map[string]string{
				{"token": "ghp_factory_secret_value_123"},
			},
			"map_to_slice": map[string][]string{
				"values": {"prefix ghp_factory_secret_value_123"},
			},
			"typed_any_maps": []map[string]any{
				{"nested": []string{"ghp_factory_secret_value_123"}},
			},
		},
	})

	typedMaps := got.Summary["typed_maps"].([]any)
	firstTypedMap := typedMaps[0].(map[string]any)
	if firstTypedMap["token"] != RunSecretRedactionPlaceholder {
		t.Fatalf("typed map value = %q, want redacted", firstTypedMap["token"])
	}

	mapToSlice := got.Summary["map_to_slice"].(map[string]any)
	values := mapToSlice["values"].([]any)
	if values[0] != "prefix "+RunSecretRedactionPlaceholder {
		t.Fatalf("map slice value = %q, want redacted", values[0])
	}

	typedAnyMaps := got.Summary["typed_any_maps"].([]any)
	firstAnyMap := typedAnyMaps[0].(map[string]any)
	nestedValues := firstAnyMap["nested"].([]any)
	if nestedValues[0] != RunSecretRedactionPlaceholder {
		t.Fatalf("nested value = %q, want redacted", nestedValues[0])
	}
}

func TestRunSecretRedactorPreservesSecretMetadataIdentifiers(t *testing.T) {
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{
		{Name: "env", Source: RunSecretSourceEnv, Required: true, Value: "env"},
	})

	got := redactor.RedactRunRecord(RunRecord{
		BranchName: "branch-env",
		Secrets: []RunSecretMetadata{{
			Name:     "env",
			Source:   RunSecretSourceEnv,
			Required: true,
			Present:  true,
		}},
	})

	if got.BranchName != "branch-"+RunSecretRedactionPlaceholder {
		t.Fatalf("BranchName = %q, want redacted secret value", got.BranchName)
	}
	wantSecret := RunSecretMetadata{
		Name:     "env",
		Source:   RunSecretSourceEnv,
		Required: true,
		Present:  true,
	}
	if got.Secrets[0] != wantSecret {
		t.Fatalf("Secrets[0] = %#v, want %#v", got.Secrets[0], wantSecret)
	}
}
