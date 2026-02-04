package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateConfigDir(t *testing.T) {
	tests := []struct {
		name       string
		setupFn    func(t *testing.T, dir string)
		wantResult migrateResult
		wantOutput string
		wantErr    bool
		checkFn    func(t *testing.T, dir string)
	}{
		{
			name: "only old dir exists - migrates",
			setupFn: func(t *testing.T, dir string) {
				old := filepath.Join(dir, ".goralph")
				os.MkdirAll(old, 0755)
				os.WriteFile(filepath.Join(old, "marker.txt"), []byte("hello"), 0644)
			},
			wantResult: migrateDone,
			wantOutput: "Migrated",
			checkFn: func(t *testing.T, dir string) {
				if _, err := os.Stat(filepath.Join(dir, ".goralph")); !os.IsNotExist(err) {
					t.Error(".goralph should not exist after migration")
				}
				data, err := os.ReadFile(filepath.Join(dir, ".hal", "marker.txt"))
				if err != nil {
					t.Fatalf(".hal/marker.txt should exist: %v", err)
				}
				if string(data) != "hello" {
					t.Errorf("marker content = %q, want %q", string(data), "hello")
				}
			},
		},
		{
			name: "both dirs exist - warning",
			setupFn: func(t *testing.T, dir string) {
				old := filepath.Join(dir, ".goralph")
				os.MkdirAll(old, 0755)
				os.WriteFile(filepath.Join(old, "marker-old.txt"), []byte("old"), 0644)
				newD := filepath.Join(dir, ".hal")
				os.MkdirAll(newD, 0755)
				os.WriteFile(filepath.Join(newD, "marker-new.txt"), []byte("new"), 0644)
			},
			wantResult: migrateWarning,
			wantOutput: "Warning: both",
			checkFn: func(t *testing.T, dir string) {
				dataOld, err := os.ReadFile(filepath.Join(dir, ".goralph", "marker-old.txt"))
				if err != nil {
					t.Fatalf(".goralph/marker-old.txt should exist: %v", err)
				}
				if string(dataOld) != "old" {
					t.Errorf("old marker content = %q, want %q", string(dataOld), "old")
				}
				dataNew, err := os.ReadFile(filepath.Join(dir, ".hal", "marker-new.txt"))
				if err != nil {
					t.Fatalf(".hal/marker-new.txt should exist: %v", err)
				}
				if string(dataNew) != "new" {
					t.Errorf("new marker content = %q, want %q", string(dataNew), "new")
				}
			},
		},
		{
			name: "neither dir exists - fresh init",
			setupFn: func(t *testing.T, dir string) {
				// no setup — neither directory exists
			},
			wantResult: migrateNone,
			wantOutput: "",
			checkFn: func(t *testing.T, dir string) {
				if _, err := os.Stat(filepath.Join(dir, ".goralph")); !os.IsNotExist(err) {
					t.Error(".goralph should not exist")
				}
				if _, err := os.Stat(filepath.Join(dir, ".hal")); !os.IsNotExist(err) {
					t.Error(".hal should not have been created by migrateConfigDir")
				}
			},
		},
		{
			name: "rename fails - returns error",
			setupFn: func(t *testing.T, dir string) {
				old := filepath.Join(dir, ".goralph")
				os.MkdirAll(old, 0755)
				os.WriteFile(filepath.Join(old, "marker.txt"), []byte("data"), 0644)
				// Remove write permission on parent dir so os.Rename fails
				os.Chmod(dir, 0555)
				t.Cleanup(func() {
					// Restore permissions so t.TempDir() cleanup can remove the dir
					os.Chmod(dir, 0755)
				})
			},
			wantResult: migrateNone,
			wantErr:    true,
			checkFn: func(t *testing.T, dir string) {
				// Restore permissions for checkFn stat calls
				os.Chmod(dir, 0755)
				if _, err := os.Stat(filepath.Join(dir, ".goralph")); os.IsNotExist(err) {
					t.Error(".goralph should still exist on rename failure")
				}
			},
		},
		{
			name: "only new dir exists - no-op",
			setupFn: func(t *testing.T, dir string) {
				newD := filepath.Join(dir, ".hal")
				os.MkdirAll(newD, 0755)
				os.WriteFile(filepath.Join(newD, "marker.txt"), []byte("existing"), 0644)
			},
			wantResult: migrateNone,
			wantOutput: "",
			checkFn: func(t *testing.T, dir string) {
				data, err := os.ReadFile(filepath.Join(dir, ".hal", "marker.txt"))
				if err != nil {
					t.Fatalf(".hal/marker.txt should exist: %v", err)
				}
				if string(data) != "existing" {
					t.Errorf("marker content = %q, want %q", string(data), "existing")
				}
				if _, err := os.Stat(filepath.Join(dir, ".goralph")); !os.IsNotExist(err) {
					t.Error(".goralph should not exist")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if tt.setupFn != nil {
				tt.setupFn(t, tmpDir)
			}

			oldDir := filepath.Join(tmpDir, ".goralph")
			newDir := filepath.Join(tmpDir, ".hal")
			var buf bytes.Buffer

			result, err := migrateConfigDir(oldDir, newDir, &buf)

			if (err != nil) != tt.wantErr {
				t.Fatalf("migrateConfigDir() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil {
				if !strings.Contains(err.Error(), "failed to migrate") {
					t.Errorf("error %q should contain 'failed to migrate'", err.Error())
				}
			}
			if result != tt.wantResult {
				t.Errorf("migrateConfigDir() result = %v, want %v", result, tt.wantResult)
			}
			if tt.wantOutput != "" && !bytes.Contains(buf.Bytes(), []byte(tt.wantOutput)) {
				t.Errorf("output %q does not contain %q", buf.String(), tt.wantOutput)
			}
			if tt.wantOutput == "" && buf.Len() > 0 {
				t.Errorf("expected no output, got %q", buf.String())
			}
			if tt.checkFn != nil {
				tt.checkFn(t, tmpDir)
			}
		})
	}
}
