//go:build !linux || !amd64

package rolebootstrap

import (
	"errors"
	"testing"
)

func TestNewInstallerFailsClosedOffLinuxAMD64(t *testing.T) {
	installer, err := NewInstaller(InstallerOptions{})
	if installer != nil || !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("NewInstaller() = %#v, %v, want unsupported platform", installer, err)
	}
}
