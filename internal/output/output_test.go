package output

import (
	"bytes"
	"testing"
)

func TestTaskCount(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		expected string
	}{
		{"zero tasks", 0, "Found 0 pending tasks\n"},
		{"one task", 1, "Found 1 pending task\n"},
		{"multiple tasks", 5, "Found 5 pending tasks\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			p := New(&buf)
			p.TaskCount(tt.count)
			if buf.String() != tt.expected {
				t.Errorf("got %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}

func TestTaskStart(t *testing.T) {
	tests := []struct {
		name        string
		current     int
		total       int
		description string
		expected    string
	}{
		{"first of three", 1, 3, "Implement feature X", "Task 1/3: Implement feature X\n"},
		{"second of two", 2, 2, "Fix bug Y", "Task 2/2: Fix bug Y\n"},
		{"single task", 1, 1, "Setup project", "Task 1/1: Setup project\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			p := New(&buf)
			p.TaskStart(tt.current, tt.total, tt.description)
			if buf.String() != tt.expected {
				t.Errorf("got %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}

func TestTaskSuccess(t *testing.T) {
	var buf bytes.Buffer
	p := New(&buf)
	p.TaskSuccess()

	expected := "✓ Task completed\n"
	if buf.String() != expected {
		t.Errorf("got %q, want %q", buf.String(), expected)
	}
}

func TestTaskFailure(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{"simple error", "connection timeout", "✗ Task failed: connection timeout\n"},
		{"detailed error", "syntax error on line 42", "✗ Task failed: syntax error on line 42\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			p := New(&buf)
			p.TaskFailure(tt.reason)
			if buf.String() != tt.expected {
				t.Errorf("got %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}

func TestRetry(t *testing.T) {
	tests := []struct {
		name        string
		delaySecs   int
		attempt     int
		maxAttempts int
		expected    string
	}{
		{"first retry", 5, 1, 3, "Retrying in 5s... (attempt 1/3)\n"},
		{"second retry", 10, 2, 3, "Retrying in 10s... (attempt 2/3)\n"},
		{"last retry", 20, 3, 3, "Retrying in 20s... (attempt 3/3)\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			p := New(&buf)
			p.Retry(tt.delaySecs, tt.attempt, tt.maxAttempts)
			if buf.String() != tt.expected {
				t.Errorf("got %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}

func TestSummary(t *testing.T) {
	tests := []struct {
		name      string
		completed int
		total     int
		expected  string
	}{
		{"all completed", 5, 5, "Completed 5/5 tasks\n"},
		{"partial completion", 2, 5, "Completed 2/5 tasks\n"},
		{"none completed", 0, 3, "Completed 0/3 tasks\n"},
		{"zero tasks", 0, 0, "Completed 0/0 tasks\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			p := New(&buf)
			p.Summary(tt.completed, tt.total)
			if buf.String() != tt.expected {
				t.Errorf("got %q, want %q", buf.String(), tt.expected)
			}
		})
	}
}
