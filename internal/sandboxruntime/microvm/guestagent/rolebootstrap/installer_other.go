//go:build !linux || !amd64

package rolebootstrap

// NewInstaller fails closed away from the exact Linux-amd64 native target and
// never invokes or retains injected system operations.
func NewInstaller(InstallerOptions) (Installer, error) {
	return nil, ErrUnsupportedPlatform
}
