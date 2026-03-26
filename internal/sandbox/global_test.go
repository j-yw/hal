package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGlobalDir(t *testing.T) {
	tests := []struct {
		name string
		set  func(t *testing.T) string
	}{
		{
			name: "uses HAL_CONFIG_HOME when set",
			set: func(t *testing.T) string {
				halHome := filepath.Join(t.TempDir(), "hal-home")
				t.Setenv(halConfigHomeEnv, halHome)
				t.Setenv(xdgConfigHomeEnv, filepath.Join(t.TempDir(), "xdg-home"))
				t.Setenv("HOME", t.TempDir())
				return halHome
			},
		},
		{
			name: "uses XDG_CONFIG_HOME when HAL_CONFIG_HOME is unset",
			set: func(t *testing.T) string {
				xdgHome := filepath.Join(t.TempDir(), "xdg-home")
				t.Setenv(halConfigHomeEnv, "")
				t.Setenv(xdgConfigHomeEnv, xdgHome)
				t.Setenv("HOME", t.TempDir())
				return filepath.Join(xdgHome, "hal")
			},
		},
		{
			name: "falls back to HOME/.config/hal",
			set: func(t *testing.T) string {
				home := t.TempDir()
				t.Setenv(halConfigHomeEnv, "")
				t.Setenv(xdgConfigHomeEnv, "")
				t.Setenv("HOME", home)
				return filepath.Join(home, ".config", "hal")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.set(t)
			got := GlobalDir()
			if got != want {
				t.Fatalf("GlobalDir() = %q, want %q", got, want)
			}
		})
	}
}

func TestSandboxesDir(t *testing.T) {
	global := t.TempDir()
	t.Setenv(halConfigHomeEnv, global)
	t.Setenv(xdgConfigHomeEnv, "")

	want := filepath.Join(global, sandboxesDirName)
	if got := SandboxesDir(); got != want {
		t.Fatalf("SandboxesDir() = %q, want %q", got, want)
	}
}

func TestEnsureGlobalDir(t *testing.T) {
	global := filepath.Join(t.TempDir(), "global-hal")
	t.Setenv(halConfigHomeEnv, global)
	t.Setenv(xdgConfigHomeEnv, "")

	if err := EnsureGlobalDir(); err != nil {
		t.Fatalf("EnsureGlobalDir() unexpected error: %v", err)
	}

	assertDirExists(t, global)
	assertDirExists(t, filepath.Join(global, sandboxesDirName))

	if runtime.GOOS != "windows" {
		assertDirPerm(t, global, 0o700)
		assertDirPerm(t, filepath.Join(global, sandboxesDirName), 0o700)
	}

	if err := EnsureGlobalDir(); err != nil {
		t.Fatalf("EnsureGlobalDir() should be idempotent, got error: %v", err)
	}
}

func TestGlobalDir_FallbacksWhenHomeUnavailable(t *testing.T) {
	origHomeFn := userHomeDirFn
	t.Cleanup(func() {
		userHomeDirFn = origHomeFn
	})

	t.Setenv(halConfigHomeEnv, "")
	t.Setenv(xdgConfigHomeEnv, "")
	t.Setenv("HOME", "")

	userHomeDirFn = func() (string, error) {
		return "", errors.New("no home")
	}

	got := GlobalDir()
	if got != "" {
		t.Fatalf("GlobalDir() = %q, want empty when no configured home is available", got)
	}
}

func assertDirExists(t *testing.T, path string) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("expected %q to exist: %v", path, err)
	}
	if !info.IsDir() {
		t.Fatalf("expected %q to be a directory", path)
	}
}

func assertDirPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("permissions for %q = %o, want %o", path, info.Mode().Perm(), want)
	}
}
