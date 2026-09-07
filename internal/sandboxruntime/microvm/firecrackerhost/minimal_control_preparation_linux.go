//go:build linux

package firecrackerhost

// Compiling RED delegates only. Neither method is selected by the executable.
// They expose the existing lost preparation lifetime without manufacturing a
// ready controller, a resource owner, or a replacement launch implementation.
func (owned *l8RuntimeOwnerLinuxRuntime) serveMinimalControlPreparation(owner *l8RuntimeOwnerSupervisor, fd int, admission *minimalControlSupervisorAdmission) error {
	return owned.serveBootstrap(owner, fd)
}

func (selected *jailerRecoveryRuntime) startMinimalControlChild() (l8RuntimeOwnerStartedChild, error) {
	return selected.startChild()
}
