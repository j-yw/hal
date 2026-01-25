package marker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkCompleteContent(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		lineNumber int
		want       string
		wantErr    bool
		errContain string
	}{
		{
			name:       "mark first task complete",
			input:      "- [ ] Task one\n- [ ] Task two\n",
			lineNumber: 1,
			want:       "- [x] Task one\n- [ ] Task two\n",
			wantErr:    false,
		},
		{
			name:       "mark second task complete",
			input:      "- [ ] Task one\n- [ ] Task two\n",
			lineNumber: 2,
			want:       "- [ ] Task one\n- [x] Task two\n",
			wantErr:    false,
		},
		{
			name:       "preserve UTF-8 content",
			input:      "- [ ] Tâche avec émojis 🎉\n- [ ] 日本語タスク\n",
			lineNumber: 1,
			want:       "- [x] Tâche avec émojis 🎉\n- [ ] 日本語タスク\n",
			wantErr:    false,
		},
		{
			name:       "preserve surrounding content",
			input:      "# Header\n\n- [ ] Task one\n\nSome text\n",
			lineNumber: 3,
			want:       "# Header\n\n- [x] Task one\n\nSome text\n",
			wantErr:    false,
		},
		{
			name:       "error on non-task line",
			input:      "# Header\n- [ ] Task\n",
			lineNumber: 1,
			wantErr:    true,
			errContain: "not a pending task",
		},
		{
			name:       "error on completed task line",
			input:      "- [x] Already done\n- [ ] Pending\n",
			lineNumber: 1,
			wantErr:    true,
			errContain: "not a pending task",
		},
		{
			name:       "error on line number too high",
			input:      "- [ ] Task one\n",
			lineNumber: 5,
			wantErr:    true,
			errContain: "exceeds file length",
		},
		{
			name:       "error on zero line number",
			input:      "- [ ] Task one\n",
			lineNumber: 0,
			wantErr:    true,
			errContain: "invalid line number",
		},
		{
			name:       "error on negative line number",
			input:      "- [ ] Task one\n",
			lineNumber: -1,
			wantErr:    true,
			errContain: "invalid line number",
		},
		{
			name:       "error on empty file",
			input:      "",
			lineNumber: 1,
			wantErr:    true,
			errContain: "file is empty",
		},
		{
			name:       "preserve indented lines after task",
			input:      "- [ ] Task with details\n  More info here\n- [ ] Next task\n",
			lineNumber: 1,
			want:       "- [x] Task with details\n  More info here\n- [ ] Next task\n",
			wantErr:    false,
		},
		{
			name:       "task without trailing space after bracket",
			input:      "- [ ]NoSpace\n",
			lineNumber: 1,
			want:       "- [x]NoSpace\n",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MarkCompleteContent(strings.NewReader(tt.input), tt.lineNumber)

			if tt.wantErr {
				if err == nil {
					t.Errorf("MarkCompleteContent() expected error, got nil")
					return
				}
				if tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("MarkCompleteContent() error = %v, want error containing %q", err, tt.errContain)
				}
				return
			}

			if err != nil {
				t.Errorf("MarkCompleteContent() unexpected error: %v", err)
				return
			}

			if string(got) != tt.want {
				t.Errorf("MarkCompleteContent() = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestMarkComplete(t *testing.T) {
	// Test the file-based function
	tests := []struct {
		name       string
		content    string
		lineNumber int
		want       string
		wantErr    bool
	}{
		{
			name:       "mark task in file",
			content:    "- [ ] First task\n- [ ] Second task\n",
			lineNumber: 1,
			want:       "- [x] First task\n- [ ] Second task\n",
			wantErr:    false,
		},
		{
			name:       "preserve UTF-8 in file",
			content:    "- [ ] Привет мир\n- [ ] مرحبا\n",
			lineNumber: 2,
			want:       "- [ ] Привет мир\n- [x] مرحبا\n",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "test.md")

			err := os.WriteFile(tmpFile, []byte(tt.content), 0644)
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}

			// Run MarkComplete
			err = MarkComplete(tmpFile, tt.lineNumber)

			if tt.wantErr {
				if err == nil {
					t.Errorf("MarkComplete() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("MarkComplete() unexpected error: %v", err)
				return
			}

			// Read result
			got, err := os.ReadFile(tmpFile)
			if err != nil {
				t.Fatalf("Failed to read result file: %v", err)
			}

			if string(got) != tt.want {
				t.Errorf("MarkComplete() file content = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestMarkComplete_FileErrors(t *testing.T) {
	t.Run("non-existent file", func(t *testing.T) {
		err := MarkComplete("/nonexistent/path/file.md", 1)
		if err == nil {
			t.Error("MarkComplete() expected error for non-existent file, got nil")
		}
	})
}
