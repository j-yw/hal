package firecracker_test

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

type externalLiveProcessManager struct{}

var _ firecracker.LiveProcessManager = externalLiveProcessManager{}

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
		LiveProcessManager: externalLiveProcessManager{},
	})
}
