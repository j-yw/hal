package cmd

import (
	"path/filepath"
	"testing"
)

func TestL2SandboxdExposesPrivateJobStateRoot(t *testing.T) {
	t.Parallel()

	cmd := newSandboxdCommand(sandboxdDeps{})
	flag := cmd.Flags().Lookup("job-state-dir")
	if flag == nil {
		t.Fatal("sandboxd does not expose --job-state-dir for durable worker jobs")
		return
	}
	if flag.DefValue == "" {
		t.Fatal("sandboxd --job-state-dir does not have a stable private default")
	}
	if !filepath.IsAbs(flag.DefValue) || flag.DefValue == string(filepath.Separator) {
		t.Fatalf("sandboxd --job-state-dir default = %q, want a scoped absolute path", flag.DefValue)
	}

	req, err := sandboxdRequestFromCommand(cmd, defaultSandboxdFlags(), sandboxdDeps{
		workerID: func() string { return "worker-l2-test" },
	})
	if err != nil {
		t.Fatalf("sandboxdRequestFromCommand() error: %v", err)
	}
	if req.JobStateDir != flag.DefValue {
		t.Fatalf("sandboxd request job state dir = %q, want flag default %q", req.JobStateDir, flag.DefValue)
	}

	customSocket := filepath.Join(t.TempDir(), "custom-worker.sock")
	if err := cmd.Flags().Set("socket", customSocket); err != nil {
		t.Fatalf("set sandboxd socket: %v", err)
	}
	req, err = sandboxdRequestFromCommand(cmd, defaultSandboxdFlags(), sandboxdDeps{
		workerID: func() string { return "worker-l2-test" },
	})
	if err != nil {
		t.Fatalf("sandboxdRequestFromCommand(custom socket) error: %v", err)
	}
	if req.JobStateDir != customSocket+".jobs" {
		t.Fatalf("custom socket job state dir = %q, want beside socket", req.JobStateDir)
	}
}
