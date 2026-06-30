package rootlesspodman

import "strings"

const (
	DefaultPodmanExecutable = "podman"
	DefaultImage            = "ghcr.io/jywlabs/hal-agent:latest"
	DefaultWorkDir          = "/workspace"
)

// Options groups the fakeable command boundaries used by the rootless Podman
// driver. Operation methods build commands and pass them through these
// interfaces instead of invoking Podman directly.
type Options struct {
	LifecycleRunner LifecycleCommandRunner
	ExecRunner      ExecCommandRunner
	CopyRunner      CopyCommandRunner
	PodmanPath      string
	Image           string
	WorkDir         string
}

// Driver is the rootless Podman runtime adapter.
type Driver struct {
	lifecycleRunner LifecycleCommandRunner
	execRunner      ExecCommandRunner
	copyRunner      CopyCommandRunner
	podmanPath      string
	image           string
	workDir         string
}

func New(opts Options) *Driver {
	podmanPath := strings.TrimSpace(opts.PodmanPath)
	if podmanPath == "" {
		podmanPath = DefaultPodmanExecutable
	}
	image := strings.TrimSpace(opts.Image)
	if image == "" {
		image = DefaultImage
	}
	workDir := strings.TrimSpace(opts.WorkDir)
	if workDir == "" {
		workDir = DefaultWorkDir
	}
	return &Driver{
		lifecycleRunner: opts.LifecycleRunner,
		execRunner:      opts.ExecRunner,
		copyRunner:      opts.CopyRunner,
		podmanPath:      podmanPath,
		image:           image,
		workDir:         workDir,
	}
}

func (d *Driver) ID() string {
	return DriverID
}

func (d *Driver) Metadata() RuntimeMetadata {
	return DefaultMetadata()
}
