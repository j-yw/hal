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
	// JobExecutionSupported explicitly attests that a custom image supplies
	// the shell and process-supervision utilities required by async jobs.
	JobExecutionSupported bool
}

// Driver is the rootless Podman runtime adapter.
type Driver struct {
	lifecycleRunner       LifecycleCommandRunner
	execRunner            ExecCommandRunner
	copyRunner            CopyCommandRunner
	podmanPath            string
	image                 string
	workDir               string
	jobExecutionSupported bool
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
		lifecycleRunner:       opts.LifecycleRunner,
		execRunner:            opts.ExecRunner,
		copyRunner:            opts.CopyRunner,
		podmanPath:            podmanPath,
		image:                 image,
		workDir:               workDir,
		jobExecutionSupported: image == DefaultImage || opts.JobExecutionSupported,
	}
}

func (d *Driver) ID() string {
	return DriverID
}

// SupportsJobExecution reports whether this driver was configured with the
// provisioned default image or an explicitly attested compatible custom image.
func (d *Driver) SupportsJobExecution() bool {
	return d != nil && d.jobExecutionSupported
}

func (d *Driver) Metadata() RuntimeMetadata {
	return DefaultMetadata()
}
