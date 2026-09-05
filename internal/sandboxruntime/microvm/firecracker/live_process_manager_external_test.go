package firecracker_test

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

type externalLiveProcessManager struct{}

type externalBootAcceptanceWaiter struct{}

var _ firecracker.BootAcceptanceWaiter = externalBootAcceptanceWaiter{}
var _ firecracker.LiveProcessManager = externalLiveProcessManager{}

func (externalBootAcceptanceWaiter) WaitForBootAcceptance(context.Context, firecracker.BootAcceptanceRequest) (firecracker.BootAcceptanceResult, error) {
	return firecracker.BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	}, nil
}

func (externalLiveProcessManager) CleanupLiveProcess(context.Context, firecracker.LiveProcessRequest) error {
	return nil
}

func (externalLiveProcessManager) StopLiveProcess(context.Context, firecracker.LiveProcessRequest) error {
	return nil
}

func (externalLiveProcessManager) DeleteLiveProcess(context.Context, firecracker.LiveProcessRequest) error {
	return nil
}

func TestLiveProcessManagerCanBeInjectedOutsideFirecrackerPackage(t *testing.T) {
	t.Parallel()

	_ = firecracker.NewBackend(firecracker.BackendOptions{
		BootAcceptanceWaiter: externalBootAcceptanceWaiter{},
		LiveProcessManager:   externalLiveProcessManager{},
	})
}
