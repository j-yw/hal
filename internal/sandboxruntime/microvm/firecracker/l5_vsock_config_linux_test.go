//go:build linux

package firecracker

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestL5ProductionRenderRejectsSwappedSupportFileBeforeTruncation(t *testing.T) {
	stateDir, err := os.MkdirTemp("/tmp", "hal-l5-render-swap-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, DefaultConfigPath)
	replacementPath := filepath.Join(stateDir, "replacement")
	if err := os.WriteFile(configPath, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacementPath, []byte("replacement-must-survive"), 0o600); err != nil {
		t.Fatal(err)
	}
	state, err := openSecureLiveBootStateDir(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer state.close()
	state.beforeOpen = func(name string) error {
		if err := os.Remove(filepath.Join(stateDir, name)); err != nil {
			return err
		}
		return os.Rename(replacementPath, filepath.Join(stateDir, name))
	}

	err = state.writeFile(configPath, []byte("new config"))
	if !errors.Is(err, errUnsafeLiveBootStateEntry) {
		t.Fatalf("writeFile() error = %v, want unsafe entry rejection", err)
	}
	data, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if got, want := string(data), "replacement-must-survive"; got != want {
		t.Fatalf("swapped replacement contents = %q, want %q", got, want)
	}
}
