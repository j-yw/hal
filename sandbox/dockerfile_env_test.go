package sandbox

import (
	"os"
	"regexp"
	"testing"
)

// Agent workloads run as uid 0 inside the image (rootless Podman maps that to
// the unprivileged host user). Claude Code refuses --dangerously-skip-permissions
// as root unless the process declares it is sandboxed, so the image must carry
// IS_SANDBOX=1 for every exec, including daemon-owned worker jobs.
func TestSandboxImageDeclaresSandboxedEnvironmentForRootAgents(t *testing.T) {
	dockerfile, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	if !regexp.MustCompile(`(?m)^ENV IS_SANDBOX=1$`).Match(dockerfile) {
		t.Fatal("sandbox/Dockerfile must set ENV IS_SANDBOX=1 so the Claude engine can run as the container's root user")
	}
}
