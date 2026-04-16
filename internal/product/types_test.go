package product

import "testing"

func TestParseGeneratedPayload_AllowsPartialPayload(t *testing.T) {
	t.Parallel()

	input := []byte(`{
		"mission.md": "Mission content",
		"tech-stack.md": "Tech stack content"
	}`)

	got, err := ParseGeneratedPayload(input)
	if err != nil {
		t.Fatalf("ParseGeneratedPayload() error = %v", err)
	}

	if got.Mission == nil || *got.Mission != "Mission content" {
		t.Fatalf("Mission = %v, want %q", got.Mission, "Mission content")
	}
	if got.Roadmap != nil {
		t.Fatalf("Roadmap = %v, want nil for omitted key", *got.Roadmap)
	}
	if got.TechStack == nil || *got.TechStack != "Tech stack content" {
		t.Fatalf("TechStack = %v, want %q", got.TechStack, "Tech stack content")
	}
}

func TestParseGeneratedPayload_MalformedJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "invalid syntax",
			input: `{"mission.md":"missing brace"`,
		},
		{
			name:  "wrong value type",
			input: `{"mission.md":123}`,
		},
		{
			name:  "not json",
			input: `not-json`,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := ParseGeneratedPayload([]byte(tc.input)); err == nil {
				t.Fatalf("ParseGeneratedPayload(%q) error = nil, want non-nil", tc.input)
			}
		})
	}
}

func TestParseGeneratedPayload_IgnoresUnknownKeys(t *testing.T) {
	t.Parallel()

	got, err := ParseGeneratedPayload([]byte(`{
		"mission.md": "Mission content",
		"unknown.md": "Unexpected content"
	}`))
	if err != nil {
		t.Fatalf("ParseGeneratedPayload() error = %v", err)
	}

	if got.Mission == nil || *got.Mission != "Mission content" {
		t.Fatalf("Mission = %v, want %q", got.Mission, "Mission content")
	}
	if got.Roadmap != nil {
		t.Fatalf("Roadmap = %v, want nil", got.Roadmap)
	}
	if got.TechStack != nil {
		t.Fatalf("TechStack = %v, want nil", got.TechStack)
	}
}

func TestParseGeneratedPayload_RejectsNonObjectPayload(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "array",
			input: `["mission.md"]`,
		},
		{
			name:  "null",
			input: `null`,
		},
		{
			name:  "string",
			input: `"mission.md"`,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseGeneratedPayload([]byte(tc.input))
			if err == nil {
				t.Fatalf("ParseGeneratedPayload(%q) error = nil, want non-nil", tc.input)
			}
			if err.Error() != "parse generated payload: expected JSON object" {
				t.Fatalf("ParseGeneratedPayload(%q) error = %q, want %q", tc.input, err.Error(), "parse generated payload: expected JSON object")
			}
		})
	}
}
