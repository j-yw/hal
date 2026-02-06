package loop

import (
	"fmt"
	"testing"
)

func TestIsRetryable(t *testing.T) {
	r := &Runner{}

	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		// Nil error
		{"nil error", nil, false},

		// Transient API errors — should be retryable
		{"rate limit", fmt.Errorf("rate limit exceeded"), true},
		{"429 status", fmt.Errorf("API returned 429"), true},
		{"503 status", fmt.Errorf("API returned 503"), true},
		{"overloaded", fmt.Errorf("model is overloaded"), true},
		{"connection reset", fmt.Errorf("connection reset by peer"), true},
		{"i/o timeout", fmt.Errorf("i/o timeout"), true},
		{"connection timeout", fmt.Errorf("connection timeout"), true},

		// Execution timeouts — should NOT be retryable (hung commands will hang again)
		{"execution timed out 15m", fmt.Errorf("execution timed out after 15m0s"), false},
		{"execution timed out 30m", fmt.Errorf("execution timed out after 30m0s"), false},
		{"prompt timed out", fmt.Errorf("prompt timed out after 15m0s"), false},

		// Other non-retryable errors
		{"generic error", fmt.Errorf("something went wrong"), false},
		{"file not found", fmt.Errorf("file not found: prompt.md"), false},
		{"unknown engine", fmt.Errorf("unknown engine: foo"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := r.isRetryable(tt.err)
			if got != tt.expected {
				t.Errorf("isRetryable(%q) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	tests := []struct {
		s      string
		substr string
		want   bool
	}{
		{"Rate Limit exceeded", "rate limit", true},
		{"CONNECTION reset", "connection", true},
		{"hello world", "world", true},
		{"hello", "hello world", false}, // substr longer than s
		{"", "a", false},
		{"execution timed out after 15m0s", "timeout", false}, // "timeout" != "timed out"
		{"i/o timeout", "timeout", true},
	}

	for _, tt := range tests {
		t.Run(tt.s+"_"+tt.substr, func(t *testing.T) {
			got := containsIgnoreCase(tt.s, tt.substr)
			if got != tt.want {
				t.Errorf("containsIgnoreCase(%q, %q) = %v, want %v", tt.s, tt.substr, got, tt.want)
			}
		})
	}
}
