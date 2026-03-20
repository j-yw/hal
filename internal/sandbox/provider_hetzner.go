package sandbox

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

// HetznerProvider implements Provider by shelling out to the hcloud CLI and ssh.
type HetznerProvider struct {
	SSHKey     string
	ServerType string
	Image      string
	// StateDir is the .hal directory path, needed to look up the server IP
	// from sandbox state for SSH connections.
	StateDir string
}

func (h *HetznerProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*SandboxResult, error) {
	return nil, fmt.Errorf("HetznerProvider.Create not yet implemented")
}

func (h *HetznerProvider) Stop(ctx context.Context, name string, out io.Writer) error {
	return fmt.Errorf("HetznerProvider.Stop not yet implemented")
}

func (h *HetznerProvider) Delete(ctx context.Context, name string, out io.Writer) error {
	return fmt.Errorf("HetznerProvider.Delete not yet implemented")
}

func (h *HetznerProvider) SSH(name string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("HetznerProvider.SSH not yet implemented")
}

func (h *HetznerProvider) Exec(name string, args []string) (*exec.Cmd, error) {
	return nil, fmt.Errorf("HetznerProvider.Exec not yet implemented")
}

func (h *HetznerProvider) Status(ctx context.Context, name string, out io.Writer) error {
	return fmt.Errorf("HetznerProvider.Status not yet implemented")
}
