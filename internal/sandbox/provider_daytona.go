package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// DaytonaProvider implements Provider by shelling out to the daytona CLI.
type DaytonaProvider struct {
	APIKey string
}

func (d *DaytonaProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*SandboxResult, error) {
	return nil, fmt.Errorf("DaytonaProvider.Create not yet implemented")
}

func (d *DaytonaProvider) Stop(ctx context.Context, name string, out io.Writer) error {
	return fmt.Errorf("DaytonaProvider.Stop not yet implemented")
}

func (d *DaytonaProvider) Delete(ctx context.Context, name string, out io.Writer) error {
	return fmt.Errorf("DaytonaProvider.Delete not yet implemented")
}

func (d *DaytonaProvider) SSH(name string) (*exec.Cmd, error) {
	cmd := exec.Command("daytona", "ssh", name)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (d *DaytonaProvider) Exec(name string, args []string) (*exec.Cmd, error) {
	cmdArgs := []string{"ssh", name, "--"}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command("daytona", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd, nil
}

func (d *DaytonaProvider) Status(ctx context.Context, name string, out io.Writer) error {
	return fmt.Errorf("DaytonaProvider.Status not yet implemented")
}
