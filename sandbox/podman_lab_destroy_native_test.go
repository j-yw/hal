package sandbox

import (
	"os"
	"strings"
	"testing"
)

// Native rootless Podman stores image layers under subordinate UIDs that the
// invoking user cannot delete directly, so destroy must remove the validated
// lab root from inside the Podman user namespace.
func TestPodmanLabDestroyNativeRemovesLabRootInsideUserNamespace(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	env.podmanMode = "native"
	if err := os.MkdirAll(env.labRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll(lab root) error = %v", err)
	}

	runPodmanLabScript(t, env, "destroy")

	log := readPodmanLabLog(t, env.logPath)
	if !strings.Contains(log, "unshare rm -rf "+env.labRoot) {
		t.Fatalf("native destroy did not remove the lab root inside the Podman user namespace:\n%s", log)
	}
	if _, err := os.Stat(env.labRoot); !os.IsNotExist(err) {
		t.Fatalf("lab root still exists after destroy: %v", err)
	}
}

func TestPodmanLabDestroyMachineModeDoesNotUnshare(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	if err := os.MkdirAll(env.labRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll(lab root) error = %v", err)
	}

	runPodmanLabScript(t, env, "destroy")

	if log := readPodmanLabLog(t, env.logPath); strings.Contains(log, "unshare") {
		t.Fatalf("machine-mode destroy must not use the host user namespace:\n%s", log)
	}
}
