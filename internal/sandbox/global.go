package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	halConfigHomeEnv = "HAL_CONFIG_HOME"
	xdgConfigHomeEnv = "XDG_CONFIG_HOME"
	sandboxesDirName = "sandboxes"
)

var (
	userHomeDirFn           = os.UserHomeDir
	errGlobalDirUnavailable = errors.New("no global hal config home found")
)

// GlobalDir resolves where global sandbox state should live.
//
// Resolution order:
//   - $HAL_CONFIG_HOME
//   - $XDG_CONFIG_HOME/hal
//   - ~/.config/hal
func GlobalDir() string {
	dir, err := resolveGlobalDir()
	if err != nil {
		return ""
	}
	return dir
}

func resolveGlobalDir() (string, error) {
	if dir := os.Getenv(halConfigHomeEnv); dir != "" {
		return dir, nil
	}
	if dir := os.Getenv(xdgConfigHomeEnv); dir != "" {
		return filepath.Join(dir, "hal"), nil
	}
	if home := homeDir(); home != "" {
		return filepath.Join(home, ".config", "hal"), nil
	}
	return "", errGlobalDirUnavailable
}

// SandboxesDir returns the global sandbox instances directory.
func SandboxesDir() string {
	dir, err := sandboxesDirPath()
	if err != nil {
		return ""
	}
	return dir
}

func sandboxesDirPath() (string, error) {
	dir, err := resolveGlobalDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, sandboxesDirName), nil
}

// EnsureGlobalDir creates the global sandbox directory and sandboxes subdirectory.
func EnsureGlobalDir() error {
	dir, err := resolveGlobalDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create global sandbox dir: %w", err)
	}
	sandboxesDir, err := sandboxesDirPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(sandboxesDir, 0o700); err != nil {
		return fmt.Errorf("create sandboxes dir: %w", err)
	}
	return nil
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	home, err := userHomeDirFn()
	if err != nil {
		return ""
	}
	return home
}
