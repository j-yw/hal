package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadDockerfile(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) string
		wantErr string
		wantLen int // minimum expected content length
	}{
		{
			name: "reads existing Dockerfile",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "Dockerfile")
				os.WriteFile(path, []byte("FROM ubuntu:22.04\nRUN echo hello"), 0644)
				return path
			},
			wantLen: 10,
		},
		{
			name: "error when Dockerfile does not exist",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				return filepath.Join(dir, "nonexistent", "Dockerfile")
			},
			wantErr: "Dockerfile not found",
		},
		{
			name: "reads empty Dockerfile",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "Dockerfile")
				os.WriteFile(path, []byte(""), 0644)
				return path
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := tt.setup(t, dir)

			content, err := ReadDockerfile(path)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(content) < tt.wantLen {
				t.Errorf("content length %d, want at least %d", len(content), tt.wantLen)
			}
		})
	}
}
