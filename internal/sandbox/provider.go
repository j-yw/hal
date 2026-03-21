package sandbox

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

// SandboxResult holds the result of creating a sandbox.
type SandboxResult struct {
	ID          string
	Name        string
	IP          string
	TailscaleIP string
}

// Provider defines the interface for sandbox backends.
// Implementations shell out to CLI tools (daytona, hcloud+ssh) rather than
// using SDKs, keeping dependencies minimal.
type Provider interface {
	// Create provisions a new sandbox with the given name and env vars.
	// Output is streamed to out. Returns the result or an error.
	Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*SandboxResult, error)

	// Stop halts a running sandbox.
	Stop(ctx context.Context, name string, out io.Writer) error

	// Delete removes a sandbox permanently.
	Delete(ctx context.Context, name string, out io.Writer) error

	// SSH returns an *exec.Cmd for an interactive SSH session.
	// The caller decides whether to Run() or syscall.Exec() into it.
	SSH(name string) (*exec.Cmd, error)

	// Exec returns an *exec.Cmd that runs args inside the sandbox.
	// The caller decides whether to Run() or syscall.Exec() into it.
	Exec(name string, args []string) (*exec.Cmd, error)

	// Status displays the current status of a sandbox.
	Status(ctx context.Context, name string, out io.Writer) error
}

// RunCmd executes cmd, piping its stdout and stderr to out, and returns the
// exit error (if any). This is the standard way to run a Provider-returned
// *exec.Cmd when you want streamed output rather than collected bytes.
func RunCmd(cmd *exec.Cmd, out io.Writer) error {
	safeOut := synchronizedWriter(out)
	cmd.Stdout = safeOut
	cmd.Stderr = safeOut
	return cmd.Run()
}

// ProviderFromConfig returns the Provider implementation matching the given
// provider name. Known providers: "daytona", "hetzner", "digitalocean".
func ProviderFromConfig(provider string, cfg ProviderConfig) (Provider, error) {
	switch provider {
	case "daytona":
		return &DaytonaProvider{
			APIKey:    cfg.DaytonaAPIKey,
			ServerURL: cfg.DaytonaServerURL,
		}, nil
	case "hetzner":
		return &HetznerProvider{
			SSHKey:            cfg.HetznerSSHKey,
			ServerType:        cfg.HetznerServerType,
			Image:             cfg.HetznerImage,
			TailscaleLockdown: cfg.TailscaleLockdown,
			StateDir:          cfg.StateDir,
		}, nil
	case "digitalocean":
		return &DigitalOceanProvider{
			SSHKey:            cfg.DigitalOceanSSHKey,
			Size:              cfg.DigitalOceanSize,
			TailscaleLockdown: cfg.TailscaleLockdown,
			StateDir:          cfg.StateDir,
		}, nil
	case "lightsail":
		return &LightsailProvider{
			Region:            cfg.LightsailRegion,
			AvailabilityZone:  cfg.LightsailAvailabilityZone,
			Bundle:            cfg.LightsailBundle,
			KeyPairName:       cfg.LightsailKeyPairName,
			TailscaleLockdown: cfg.TailscaleLockdown,
			StateDir:          cfg.StateDir,
		}, nil
	default:
		return nil, fmt.Errorf("unknown sandbox provider: %q (supported: daytona, hetzner, digitalocean, lightsail)", provider)
	}
}

// ProviderConfig holds the configuration needed to instantiate any Provider.
// Fields are populated from .hal/config.yaml by the caller.
type ProviderConfig struct {
	DaytonaAPIKey             string
	DaytonaServerURL          string
	HetznerSSHKey             string
	HetznerServerType         string
	HetznerImage              string
	DigitalOceanSSHKey        string
	DigitalOceanSize          string
	LightsailRegion           string
	LightsailAvailabilityZone string
	LightsailBundle           string
	LightsailKeyPairName      string
	TailscaleLockdown         bool
	// StateDir is the .hal directory path, used by providers that need to
	// read sandbox state (e.g. Hetzner/DigitalOcean/Lightsail SSH needs the IP from state).
	StateDir string
}
