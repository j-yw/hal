package firecrackerhost

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestOSExecProcessRunnerImplementsInjectableHostBoundary(t *testing.T) {
	var _ HostProcessRunner = NewOSExecProcessRunner()

	manager := NewProcessLifecycleManager(NewOSExecProcessRunner())
	adapter := NewAdapter(
		WithProcessRunner(manager),
		WithLiveProcessCleanup(manager),
	)

	if adapter.processRunner != manager {
		t.Fatal("real process runner was not hidden behind ProcessLifecycleManager process boundary")
	}
	if adapter.cleanup != manager {
		t.Fatal("real process cleanup was not hidden behind ProcessLifecycleManager cleanup boundary")
	}
}

func TestOSExecProcessRunnerRejectsMissingExecutableBeforeLaunch(t *testing.T) {
	process, err := NewOSExecProcessRunner().StartHostProcess(context.Background(), firecracker.ProcessRunnerStartRequest{})

	if process != nil {
		t.Fatalf("process = %#v, want nil", process)
	}
	if !errors.Is(err, ErrHostProcessExecutableRequired) {
		t.Fatalf("StartHostProcess() error = %v, want ErrHostProcessExecutableRequired", err)
	}
}

func TestOSExecProcessRunnerRejectsEnvironmentDeliveryBeforeLaunch(t *testing.T) {
	req := firecracker.ProcessRunnerStartRequest{
		Executable:  "/Users/alice/private/bin/firecracker",
		Args:        []string{"--api-sock", "/Users/alice/private/firecracker.sock"},
		Environment: []string{"OPENAI_API_KEY=sk-live-secret"},
	}

	process, err := NewOSExecProcessRunner().StartHostProcess(context.Background(), req)

	if process != nil {
		t.Fatalf("process = %#v, want nil", process)
	}
	if !errors.Is(err, ErrHostProcessEnvironmentUnsupported) {
		t.Fatalf("StartHostProcess() error = %v, want ErrHostProcessEnvironmentUnsupported", err)
	}
	for _, unsafe := range []string{"/Users/alice", "private", "firecracker.sock", "OPENAI_API_KEY", "sk-live-secret"} {
		if strings.Contains(err.Error(), unsafe) {
			t.Fatalf("StartHostProcess() error leaked unsafe fragment %q in %q", unsafe, err.Error())
		}
	}
}

func TestOSExecProcessRunnerRejectsControlCharactersBeforeLaunch(t *testing.T) {
	tests := []struct {
		name string
		req  firecracker.ProcessRunnerStartRequest
	}{
		{
			name: "executable",
			req: firecracker.ProcessRunnerStartRequest{
				Executable: "firecracker\nsecret",
			},
		},
		{
			name: "argument",
			req: firecracker.ProcessRunnerStartRequest{
				Executable: "firecracker",
				Args:       []string{"--api-sock", "firecracker.sock\rsecret"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			process, err := NewOSExecProcessRunner().StartHostProcess(context.Background(), tt.req)

			if process != nil {
				t.Fatalf("process = %#v, want nil", process)
			}
			if !errors.Is(err, ErrHostProcessArgumentInvalid) {
				t.Fatalf("StartHostProcess() error = %v, want ErrHostProcessArgumentInvalid", err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "firecracker.sock") {
				t.Fatalf("StartHostProcess() error leaked raw invalid input in %q", err.Error())
			}
		})
	}
}
