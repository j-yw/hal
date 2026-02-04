package cmd

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestMigrateConfigDir(t *testing.T) {
	tests := []struct {
		name       string
		setupFn    func(dir string)
		wantResult migrateResult
		wantOutput string
		wantErr    bool
		checkFn    func(t *testing.T, dir string)
	}{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			if tt.setupFn != nil {
				tt.setupFn(tmpDir)
			}

			oldDir := filepath.Join(tmpDir, ".goralph")
			newDir := filepath.Join(tmpDir, ".hal")
			var buf bytes.Buffer

			result, err := migrateConfigDir(oldDir, newDir, &buf)

			if (err != nil) != tt.wantErr {
				t.Fatalf("migrateConfigDir() error = %v, wantErr %v", err, tt.wantErr)
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
