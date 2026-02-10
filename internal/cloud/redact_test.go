package cloud

import (
	"regexp"
	"strings"
	"testing"
)

func testStripeLikeKey(kind, mode string) string {
	return strings.Join([]string{kind, "_", mode, "_", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"}, "")
}

func TestRedactBearerToken(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "standard bearer token",
			input: `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
			want:  `Authorization: Bearer [REDACTED]`,
		},
		{
			name:  "bearer token lowercase",
			input: `authorization: bearer abc123def456ghi789`,
			want:  `authorization: bearer [REDACTED]`,
		},
		{
			name:  "bearer in curl command",
			input: `curl -H "Authorization: Bearer ghp_abcdef1234567890abcdef1234567890abcd" https://api.github.com`,
			want:  `curl -H "Authorization: Bearer [REDACTED]" https://api.github.com`,
		},
		{
			name:  "bearer with padding",
			input: `Bearer dGVzdA==`,
			want:  `Bearer [REDACTED]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input)
			if got != tt.want {
				t.Errorf("Redact(%q)\n got: %q\nwant: %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactGitHubPAT(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "fine-grained PAT",
			input: `token: github_pat_11AABBBCC22DDDEEEFFF33_abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ`,
			want:  `token: [REDACTED]`,
		},
		{
			name:  "classic PAT ghp_",
			input: `GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234`,
			want:  `GITHUB_TOKEN=[REDACTED]`,
		},
		{
			name:  "classic PAT gho_",
			input: `token=gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234`,
			want:  `token=[REDACTED]`,
		},
		{
			name:  "classic PAT ghs_",
			input: `secret: ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234`,
			want:  `secret: [REDACTED]`,
		},
		{
			name:  "classic PAT ghu_",
			input: `AUTH=ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234`,
			want:  `AUTH=[REDACTED]`,
		},
		{
			name:  "classic PAT ghr_",
			input: `ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234`,
			want:  `[REDACTED]`,
		},
		{
			name:  "PAT in log line",
			input: `2024-01-15 10:30:00 INFO using token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234 for auth`,
			want:  `2024-01-15 10:30:00 INFO using token [REDACTED] for auth`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input)
			if got != tt.want {
				t.Errorf("Redact(%q)\n got: %q\nwant: %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactDeviceCode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "device_code in query param",
			input: `device_code=ABCD-1234-EFGH-5678`,
			want:  `device_code=[REDACTED]`,
		},
		{
			name:  "device_code in JSON",
			input: `{"device_code":"a1b2c3d4-e5f6-7890-abcd-ef1234567890"}`,
			want:  `{"device_code":"[REDACTED]"}`,
		},
		{
			name:  "device_code in log output",
			input: `Enter code: device_code=WXYZ1234ABCD at https://github.com/login/device`,
			want:  `Enter code: device_code=[REDACTED] at https://github.com/login/device`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input)
			if got != tt.want {
				t.Errorf("Redact(%q)\n got: %q\nwant: %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactSessionCookie(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "session cookie",
			input: `Cookie: session=abc123def456ghi789jkl012mno345pqr678`,
			want:  `Cookie: session=[REDACTED]`,
		},
		{
			name:  "_session cookie",
			input: `Set-Cookie: _session=s%3Aabc123.xyz789+/==`,
			want:  `Set-Cookie: _session=[REDACTED]`,
		},
		{
			name:  "session_id cookie",
			input: `session_id=abcdef123456789abcdef123456789ab`,
			want:  `session_id=[REDACTED]`,
		},
		{
			name:  "sid cookie",
			input: `sid=abc-123-def-456-ghi`,
			want:  `sid=[REDACTED]`,
		},
		{
			name:  "connect.sid cookie",
			input: `connect.sid=s:abcdef123456.xyz789abcdef123456`,
			want:  `connect.sid=[REDACTED]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input)
			if got != tt.want {
				t.Errorf("Redact(%q)\n got: %q\nwant: %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactAPIKey(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "api_key in query string",
			input: `https://api.example.com/v1/data?api_key=` + testStripeLikeKey("sk", "live"),
			want:  `https://api.example.com/v1/data?api_key=[REDACTED]`,
		},
		{
			name:  "api-key in config",
			input: `api-key: my-secret-api-key-value-1234567890`,
			want:  `api-key: [REDACTED]`,
		},
		{
			name:  "apikey in env var",
			input: `APIKEY=abcdefghijklmnop1234567890`,
			want:  `APIKEY=abcdefghijklmnop1234567890`, // APIKEY without separator does not match
		},
		{
			name:  "X-Api-Key header",
			input: `X-Api-Key: sk-abc123def456ghi789jkl012mno345pqr678`,
			want:  `X-Api-Key: [REDACTED]`,
		},
		{
			name:  "x-api-key lowercase",
			input: `x-api-key: test-key-abc123`,
			want:  `x-api-key: [REDACTED]`,
		},
		{
			name:  "api_key in JSON",
			input: `{"api_key": "live_abcdef123456789"}`,
			want:  `{"api_key": "[REDACTED]"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input)
			if got != tt.want {
				t.Errorf("Redact(%q)\n got: %q\nwant: %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactBasicAuth(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Basic auth header",
			input: `Authorization: Basic dXNlcjpwYXNzd29yZA==`,
			want:  `Authorization: Basic [REDACTED]`,
		},
		{
			name:  "basic lowercase",
			input: `authorization: basic dXNlcjpwYXNzd29yZA==`,
			want:  `authorization: basic [REDACTED]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input)
			if got != tt.want {
				t.Errorf("Redact(%q)\n got: %q\nwant: %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactStripeKeys(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "sk_live key",
			input: `STRIPE_KEY=` + testStripeLikeKey("sk", "live"),
			want:  `STRIPE_KEY=[REDACTED]`,
		},
		{
			name:  "sk_test key",
			input: `key: ` + testStripeLikeKey("sk", "test"),
			want:  `key: [REDACTED]`,
		},
		{
			name:  "rk_live key",
			input: testStripeLikeKey("rk", "live"),
			want:  `[REDACTED]`,
		},
		{
			name:  "rk_test key",
			input: `restricted: ` + testStripeLikeKey("rk", "test"),
			want:  `restricted: [REDACTED]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input)
			if got != tt.want {
				t.Errorf("Redact(%q)\n got: %q\nwant: %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactNoFalsePositives(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "normal log line",
			input: `2024-01-15 10:30:00 INFO server started on port 8080`,
		},
		{
			name:  "git output",
			input: `Cloning into '/workspace/repo'...`,
		},
		{
			name:  "hal command",
			input: `hal init --force`,
		},
		{
			name:  "empty string",
			input: ``,
		},
		{
			name:  "URL without credentials",
			input: `https://api.example.com/v1/users?page=1&limit=10`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input)
			if got != tt.input {
				t.Errorf("Redact(%q) should not modify input\n got: %q", tt.input, got)
			}
		})
	}
}

func TestRedactMultipleSecrets(t *testing.T) {
	input := `Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123 and ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234`
	got := Redact(input)
	if strings.Contains(got, "eyJhbGciOiJIUzI1NiJ9") {
		t.Error("bearer token was not redacted")
	}
	if strings.Contains(got, "ghp_") {
		t.Error("GitHub PAT was not redacted")
	}
	if !strings.Contains(got, "[REDACTED]") {
		t.Error("expected [REDACTED] placeholder in output")
	}
}

func TestRedactPreservesPrefix(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantPrefix string
	}{
		{
			name:       "Bearer prefix preserved",
			input:      `Bearer eyJhbGciOiJIUzI1NiJ9.test`,
			wantPrefix: `Bearer `,
		},
		{
			name:       "device_code= prefix preserved",
			input:      `device_code=ABCD1234EFGH`,
			wantPrefix: `device_code=`,
		},
		{
			name:       "session= prefix preserved",
			input:      `session=abc123def456`,
			wantPrefix: `session=`,
		},
		{
			name:       "api_key= prefix preserved",
			input:      `api_key=secret123value`,
			wantPrefix: `api_key=`,
		},
		{
			name:       "X-Api-Key: prefix preserved",
			input:      `X-Api-Key: secret123value`,
			wantPrefix: `X-Api-Key: `,
		},
		{
			name:       "Basic prefix preserved",
			input:      `Basic dXNlcjpwYXNz`,
			wantPrefix: `Basic `,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Redact(tt.input)
			if !strings.HasPrefix(got, tt.wantPrefix) {
				t.Errorf("Redact(%q) = %q, want prefix %q", tt.input, got, tt.wantPrefix)
			}
			if !strings.HasSuffix(got, "[REDACTED]") {
				t.Errorf("Redact(%q) = %q, want suffix [REDACTED]", tt.input, got)
			}
		})
	}
}

func TestRedactBytes(t *testing.T) {
	input := []byte(`Bearer secret-token-123`)
	got := RedactBytes(input)
	want := []byte(`Bearer [REDACTED]`)
	if string(got) != string(want) {
		t.Errorf("RedactBytes(%q) = %q, want %q", input, got, want)
	}
}

func TestContainsSecret(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "bearer token",
			input: `Bearer abc123`,
			want:  true,
		},
		{
			name:  "GitHub PAT",
			input: `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234`,
			want:  true,
		},
		{
			name:  "no secret",
			input: `hello world`,
			want:  false,
		},
		{
			name:  "empty",
			input: ``,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContainsSecret(tt.input)
			if got != tt.want {
				t.Errorf("ContainsSecret(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactMultiline(t *testing.T) {
	input := "line1: Bearer secret123\nline2: normal text\nline3: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234"
	got := RedactMultiline(input)
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if strings.Contains(lines[0], "secret123") {
		t.Error("line 1 bearer token not redacted")
	}
	if lines[1] != "line2: normal text" {
		t.Errorf("line 2 should be unchanged, got %q", lines[1])
	}
	if strings.Contains(lines[2], "ghp_") {
		t.Error("line 3 GitHub PAT not redacted")
	}
}

func TestRedactWithCustomRules(t *testing.T) {
	customRules := []RedactionRule{
		{
			Name:    "custom_secret",
			Pattern: regexp.MustCompile(`secret_[a-z0-9]{10,}`),
		},
	}
	input := "my secret_abcdef1234 is here"
	got := RedactWith(input, customRules)
	want := "my [REDACTED] is here"
	if got != want {
		t.Errorf("RedactWith(%q) = %q, want %q", input, got, want)
	}
}

func TestDefaultRedactionRulesReturnsACopy(t *testing.T) {
	rules1 := DefaultRedactionRules()
	rules2 := DefaultRedactionRules()

	if len(rules1) != len(rules2) {
		t.Fatalf("expected same length, got %d and %d", len(rules1), len(rules2))
	}

	// Modifying the returned slice should not affect defaults
	rules1[0].Name = "modified"
	rules3 := DefaultRedactionRules()
	if rules3[0].Name == "modified" {
		t.Error("DefaultRedactionRules() returned a reference instead of a copy")
	}
}

func TestRedactPlaceholderFormat(t *testing.T) {
	// Verify the exact placeholder format
	input := `Bearer secret123token`
	got := Redact(input)
	if !strings.Contains(got, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in output, got %q", got)
	}
	// Should NOT contain other redaction formats
	for _, bad := range []string{"***", "XXXXX", "<redacted>", "[MASKED]"} {
		if strings.Contains(got, bad) {
			t.Errorf("unexpected redaction format %q in output %q", bad, got)
		}
	}
}

func TestEveryRuleHasName(t *testing.T) {
	rules := DefaultRedactionRules()
	for i, rule := range rules {
		if rule.Name == "" {
			t.Errorf("rule %d has empty name", i)
		}
		if rule.Pattern == nil {
			t.Errorf("rule %q has nil pattern", rule.Name)
		}
	}
}
