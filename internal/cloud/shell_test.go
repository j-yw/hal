package cloud

import "testing"

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain_text",
			input: "hello",
			want:  "'hello'",
		},
		{
			name:  "whitespace",
			input: "hello world",
			want:  "'hello world'",
		},
		{
			name:  "embedded_single_quote",
			input: "it's",
			want:  "'it'\\''s'",
		},
		{
			name:  "multiple_single_quotes",
			input: "it's a 'test'",
			want:  "'it'\\''s a '\\''test'\\'''",
		},
		{
			name:  "newline",
			input: "line1\nline2",
			want:  "'line1\nline2'",
		},
		{
			name:  "empty_string",
			input: "",
			want:  "''",
		},
		{
			name:  "tabs_and_spaces",
			input: "key\tvalue  data",
			want:  "'key\tvalue  data'",
		},
		{
			name:  "special_shell_chars",
			input: "$(rm -rf /)",
			want:  "'$(rm -rf /)'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShellQuote(tt.input)
			if got != tt.want {
				t.Errorf("ShellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
