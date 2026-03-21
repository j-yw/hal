package sandbox

import (
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
	userHomeDirFn   = os.UserHomeDir
	userConfigDirFn = os.UserConfigDir
	tempDirFn       = os.TempDir
)

// GlobalDir resolves where global sandbox state should live.
//
// Resolution order:
//   - $HAL_CONFIG_HOME
//   - $XDG_CONFIG_HOME/hal
//   - ~/.config/hal
func GlobalDir() string {
	if dir := os.Getenv(halConfigHomeEnv); dir != "" {
		return dir
	}
	if dir := os.Getenv(xdgConfigHomeEnv); dir != "" {
		return filepath.Join(dir, "hal")
	}
	if home := homeDir(); home != "" {
		return filepath.Join(home, ".config", "hal")
	}
	if configDir, err := userConfigDirFn(); err == nil && configDir != "" {
		return filepath.Join(configDir, "hal")
	}
	if tmp := tempDirFn(); tmp != "" && filepath.IsAbs(tmp) {
		return filepath.Join(tmp, "hal")
	}
	return filepath.Join(string(os.PathSeparator), "tmp", "hal")
}

// SandboxesDir returns the global sandbox instances directory.
func SandboxesDir() string {
	return filepath.Join(GlobalDir(), sandboxesDirName)
}

// EnsureGlobalDir creates the global sandbox directory and sandboxes subdirectory.
func EnsureGlobalDir() error {
	if err := os.MkdirAll(GlobalDir(), 0o700); err != nil {
		return fmt.Errorf("create global sandbox dir: %w", err)
	}
	if err := os.MkdirAll(SandboxesDir(), 0o700); err != nil {
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
