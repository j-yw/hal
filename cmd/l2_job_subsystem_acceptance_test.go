package cmd

import "testing"

func TestL2SandboxdExposesPrivateJobStateRoot(t *testing.T) {
	t.Parallel()

	cmd := newSandboxdCommand(defaultSandboxdDeps())
	flag := cmd.Flags().Lookup("job-state-dir")
	if flag == nil {
		t.Fatal("sandboxd does not expose --job-state-dir for durable worker jobs")
	}
	if flag.DefValue == "" {
		t.Fatal("sandboxd --job-state-dir does not have a stable private default")
	}
}
