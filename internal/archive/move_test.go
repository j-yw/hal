package archive

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMoveFile(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) (src, dst string)
		wantErr bool
		check   func(t *testing.T, src, dst string)
	}{
		{
			name: "same-device move succeeds",
			setup: func(t *testing.T, dir string) (string, string) {
				src := filepath.Join(dir, "source.txt")
				dst := filepath.Join(dir, "dest.txt")
				if err := os.WriteFile(src, []byte("hello"), 0644); err != nil {
					t.Fatal(err)
				}
				return src, dst
			},
			check: func(t *testing.T, src, dst string) {
				// Source should be gone
				if _, err := os.Stat(src); !os.IsNotExist(err) {
					t.Error("source file should not exist after move")
				}
				// Destination should exist with correct content
				data, err := os.ReadFile(dst)
				if err != nil {
					t.Fatalf("failed to read destination: %v", err)
				}
				if string(data) != "hello" {
					t.Errorf("destination content = %q, want %q", string(data), "hello")
				}
			},
		},
		{
			name: "file permissions are preserved",
			setup: func(t *testing.T, dir string) (string, string) {
				src := filepath.Join(dir, "source.txt")
				dst := filepath.Join(dir, "dest.txt")
				if err := os.WriteFile(src, []byte("data"), 0755); err != nil {
					t.Fatal(err)
				}
				return src, dst
			},
			check: func(t *testing.T, src, dst string) {
				info, err := os.Stat(dst)
				if err != nil {
					t.Fatalf("failed to stat destination: %v", err)
				}
				// os.Rename preserves permissions; check the mode bits
				if info.Mode().Perm() != 0755 {
					t.Errorf("destination permissions = %o, want %o", info.Mode().Perm(), 0755)
				}
			},
		},
		{
			name: "move to non-existent destination directory returns error",
			setup: func(t *testing.T, dir string) (string, string) {
				src := filepath.Join(dir, "source.txt")
				dst := filepath.Join(dir, "no-such-dir", "dest.txt")
				if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
					t.Fatal(err)
				}
				return src, dst
			},
			wantErr: true,
		},
		{
			name: "move of non-existent source file returns error",
			setup: func(t *testing.T, dir string) (string, string) {
				src := filepath.Join(dir, "does-not-exist.txt")
				dst := filepath.Join(dir, "dest.txt")
				return src, dst
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			src, dst := tt.setup(t, dir)

			err := moveFile(src, dst)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, src, dst)
			}
		})
	}
}
