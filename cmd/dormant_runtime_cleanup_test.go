package cmd

import (
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxtarget"
)

func TestSandboxdHelpHasNoDormantRuntimeFlags(t *testing.T) {
	cmd, out, _ := newTestSandboxdCommand(defaultSandboxdDeps())
	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{"firecracker", "microvm"} {
		if strings.Contains(strings.ToLower(out.String()), removed) {
			t.Fatalf("sandboxd help still advertises %s", removed)
		}
	}
	for _, surviving := range []string{"--driver", "--podman", "--image-job-execution-supported"} {
		if !strings.Contains(out.String(), surviving) {
			t.Fatalf("sandboxd help missing %s", surviving)
		}
	}
}

func TestSandboxRuntimeCompatRejectsReservedMicroVMBeforeProvider(t *testing.T) {
	driver, err := sandboxRuntimeDriverFromTarget(sandboxruntime.Target{
		Runtime: sandboxruntime.RuntimeState{Driver: sandboxruntime.DriverMicroVM},
	}, func(string) (sandbox.Provider, error) {
		t.Fatal("unsupported runtime contacted a provider")
		return nil, nil
	})
	var failure *sandboxtarget.Failure
	if driver != nil || !errors.As(err, &failure) || failure.Reason != sandboxtarget.FailureReasonRuntimeUnsupported {
		t.Fatalf("driver = %T, error = %v; want runtime_unsupported", driver, err)
	}
}
