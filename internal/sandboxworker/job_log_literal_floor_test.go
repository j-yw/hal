package sandboxworker

import "testing"

// A job launched as `sh -c "set -eu\n..."` must not register its interpreter
// tokens as secrets: masking "sh" and "-c" mangles ordinary output such as
// `git status --short` and `node --check`. Long literals stay masked.
func TestJobLiteralRedactorIgnoresShortCommandTokens(t *testing.T) {
	redactor := newJobLiteralRedactor(ExecRequest{
		Args: []string{"sh", "-c", "set -eu\nexec hal run --token-like-argument-value"},
		Env:  map[string]string{"HAL_FLAG": "true", "API_TOKEN": "tok_0123456789abcdef"},
	})
	input := "git status --short && node --check greet.js\n" +
		"flag is true\n" +
		"leaked tok_0123456789abcdef and exec hal run --token-like-argument-value\n"
	want := "git status --short && node --check greet.js\n" +
		"flag is true\n" +
		"leaked [redacted] and [redacted]\n"
	if got := string(redactor.Consume([]byte(input), true)); got != want {
		t.Fatalf("redacted output =\n%q\nwant\n%q", got, want)
	}
}
