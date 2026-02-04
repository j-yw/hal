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

func TestMoveDir(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) (src, dst string)
		wantErr bool
		check   func(t *testing.T, src, dst string)
	}{
		{
			name: "same-device directory move succeeds",
			setup: func(t *testing.T, dir string) (string, string) {
				src := filepath.Join(dir, "srcdir")
				dst := filepath.Join(dir, "dstdir")
				if err := os.MkdirAll(src, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("aaa"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(src, "b.txt"), []byte("bbb"), 0644); err != nil {
					t.Fatal(err)
				}
				return src, dst
			},
			check: func(t *testing.T, src, dst string) {
				// Source directory should be gone
				if _, err := os.Stat(src); !os.IsNotExist(err) {
					t.Error("source directory should not exist after move")
				}
				// Destination files should exist with correct content
				for _, tc := range []struct {
					name, content string
				}{
					{"a.txt", "aaa"},
					{"b.txt", "bbb"},
				} {
					data, err := os.ReadFile(filepath.Join(dst, tc.name))
					if err != nil {
						t.Fatalf("failed to read %s: %v", tc.name, err)
					}
					if string(data) != tc.content {
						t.Errorf("%s content = %q, want %q", tc.name, string(data), tc.content)
					}
				}
			},
		},
		{
			name: "nested subdirectories with files are handled correctly",
			setup: func(t *testing.T, dir string) (string, string) {
				src := filepath.Join(dir, "srcdir")
				dst := filepath.Join(dir, "dstdir")
				sub := filepath.Join(src, "sub")
				if err := os.MkdirAll(sub, 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(src, "top.txt"), []byte("top"), 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(sub, "nested.txt"), []byte("nested"), 0644); err != nil {
					t.Fatal(err)
				}
				return src, dst
			},
			check: func(t *testing.T, src, dst string) {
				if _, err := os.Stat(src); !os.IsNotExist(err) {
					t.Error("source directory should not exist after move")
				}
				// Top-level file
				data, err := os.ReadFile(filepath.Join(dst, "top.txt"))
				if err != nil {
					t.Fatalf("failed to read top.txt: %v", err)
				}
				if string(data) != "top" {
					t.Errorf("top.txt content = %q, want %q", string(data), "top")
				}
				// Nested file
				data, err = os.ReadFile(filepath.Join(dst, "sub", "nested.txt"))
				if err != nil {
					t.Fatalf("failed to read sub/nested.txt: %v", err)
				}
				if string(data) != "nested" {
					t.Errorf("sub/nested.txt content = %q, want %q", string(data), "nested")
				}
			},
		},
		{
			name: "move of non-existent source directory returns error",
			setup: func(t *testing.T, dir string) (string, string) {
				src := filepath.Join(dir, "does-not-exist")
				dst := filepath.Join(dir, "dstdir")
				return src, dst
			},
			wantErr: true,
		},
		{
			name: "empty source directory move succeeds",
			setup: func(t *testing.T, dir string) (string, string) {
				src := filepath.Join(dir, "emptydir")
				dst := filepath.Join(dir, "dstdir")
				if err := os.MkdirAll(src, 0755); err != nil {
					t.Fatal(err)
				}
				return src, dst
			},
			check: func(t *testing.T, src, dst string) {
				if _, err := os.Stat(src); !os.IsNotExist(err) {
					t.Error("source directory should not exist after move")
				}
				info, err := os.Stat(dst)
				if err != nil {
					t.Fatalf("destination should exist: %v", err)
				}
				if !info.IsDir() {
					t.Error("destination should be a directory")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			src, dst := tt.setup(t, dir)

			err := moveDir(src, dst)

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
