package rootlesspodman

// Options groups the fakeable command boundaries used by the rootless Podman
// driver. Later lifecycle/exec/copy implementations should build commands and
// pass them through these interfaces instead of invoking Podman directly.
type Options struct {
	LifecycleRunner LifecycleCommandRunner
	ExecRunner      ExecCommandRunner
	CopyRunner      CopyCommandRunner
}

// Driver is the rootless Podman runtime adapter shell. Operation methods are
// added in later implementation stories.
type Driver struct {
	lifecycleRunner LifecycleCommandRunner
	execRunner      ExecCommandRunner
	copyRunner      CopyCommandRunner
}

func New(opts Options) *Driver {
	return &Driver{
		lifecycleRunner: opts.LifecycleRunner,
		execRunner:      opts.ExecRunner,
		copyRunner:      opts.CopyRunner,
	}
}

func (d *Driver) ID() string {
	return DriverID
}

func (d *Driver) Metadata() RuntimeMetadata {
	return DefaultMetadata()
}
