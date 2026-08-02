package rootlesspodman

import (
	"strings"
	"sync"
	"time"
)

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
	// NetworkTopologyFactory enables the explicit L7 per-target topology path.
	// Nil preserves the legacy rootless Podman lifecycle and command bytes.
	NetworkTopologyFactory NetworkTopologyFactory
	// NetworkTopologyCleanupTimeout bounds revoke and cleanup work independently
	// from a canceled lifecycle caller. Zero selects the package default.
	NetworkTopologyCleanupTimeout time.Duration
}

// Driver is the rootless Podman runtime adapter.
type Driver struct {
	lifecycleRunner               LifecycleCommandRunner
	execRunner                    ExecCommandRunner
	copyRunner                    CopyCommandRunner
	podmanPath                    string
	image                         string
	workDir                       string
	jobExecutionSupported         bool
	networkTopologyFactory        NetworkTopologyFactory
	networkTopologyCleanupTimeout time.Duration
	networkTopologyMu             sync.Mutex
	networkTopologySessions       map[string]*networkTopologyEntry
	pendingNetworkTopologyCleanup map[*pendingNetworkTopologyCleanup]struct{}
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
		lifecycleRunner:               opts.LifecycleRunner,
		execRunner:                    opts.ExecRunner,
		copyRunner:                    opts.CopyRunner,
		podmanPath:                    podmanPath,
		image:                         image,
		workDir:                       workDir,
		jobExecutionSupported:         image == DefaultImage || opts.JobExecutionSupported,
		networkTopologyFactory:        opts.NetworkTopologyFactory,
		networkTopologyCleanupTimeout: opts.NetworkTopologyCleanupTimeout,
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
