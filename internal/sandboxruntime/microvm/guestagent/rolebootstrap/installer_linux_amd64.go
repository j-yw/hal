//go:build linux && amd64

package rolebootstrap

type installerState uint8

const (
	installerStateReady installerState = iota + 1
	installerStateFinalized
	installerStateClosed
)

type installer struct {
	gate     chan struct{}
	state    installerState
	artifact GeneratedArtifact
	system   System
}

// NewInstaller constructs the explicit Linux-amd64 D4 consumer seam. It does
// not contain, compile, install, or infer a syscall policy by itself.
func NewInstaller(options InstallerOptions) (Installer, error) {
	if !validGeneratedArtifact(options.Artifact) {
		return nil, ErrInvalidArgument
	}
	if !options.System.configured() {
		return nil, ErrDependency
	}
	value := &installer{
		gate:     make(chan struct{}, 1),
		state:    installerStateReady,
		artifact: options.Artifact,
		system:   options.System,
	}
	value.gate <- struct{}{}
	return value, nil
}

func (installer *installer) Install(plan InstallPlan) (InstalledRole, error) {
	if !validInstallPlan(plan) {
		return InstalledRole{}, ErrInvalidArgument
	}
	if plan.artifact != installer.artifact {
		return InstalledRole{}, ErrArtifactMismatch
	}
	<-installer.gate
	defer func() { installer.gate <- struct{}{} }()
	if installer.state != installerStateReady {
		return InstalledRole{}, ErrTransition
	}
	installer.state = installerStateFinalized
	installed, err := installer.system.install(plan)
	if err != nil {
		return InstalledRole{}, ErrSystem
	}
	if !validInstalledRole(installed) || installed.role != plan.role || installed.artifact != plan.artifact || installed.binarySHA256 != plan.binarySHA256 {
		return InstalledRole{}, ErrResult
	}
	return installed, nil
}

func (installer *installer) Close() error {
	<-installer.gate
	defer func() { installer.gate <- struct{}{} }()
	if installer.state == installerStateClosed {
		return nil
	}
	installer.state = installerStateClosed
	if err := installer.system.close(); err != nil {
		return ErrSystem
	}
	return nil
}
