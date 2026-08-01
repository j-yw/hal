package l7network

import (
	"context"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

type ProductionRuntimeReconciler struct {
	Runner     rootlesspodman.LifecycleCommandRunner
	PodmanPath string
}

func (r ProductionRuntimeReconciler) Stop(ctx context.Context, request rootlesspodman.NetworkTopologyTargetRequest) error {
	return r.run(ctx, request, rootlesspodman.OperationStop, []string{r.path(), "stop", request.Target.Runtime.RuntimeID})
}
func (r ProductionRuntimeReconciler) Delete(ctx context.Context, request rootlesspodman.NetworkTopologyTargetRequest) error {
	return r.run(ctx, request, rootlesspodman.OperationDelete, []string{r.path(), "rm", "--force", request.Target.Runtime.RuntimeID})
}
func (r ProductionRuntimeReconciler) run(ctx context.Context, request rootlesspodman.NetworkTopologyTargetRequest, operation string, args []string) error {
	if r.Runner == nil || request.Target.ID == "" || request.Target.ID != request.Target.Runtime.RuntimeID || request.Target.Runtime.Driver != rootlesspodman.DriverID || !safeID(request.Target.ID) {
		return ErrIdentityMismatch
	}
	result, err := r.Runner.RunLifecycleCommand(ctx, rootlesspodman.CommandRequest{Operation: operation, Args: args, MaxStdoutBytes: 64 << 10, MaxStderrBytes: 64 << 10})
	if err != nil || result.ExitCode != 0 {
		return ErrCleanupIncomplete
	}
	return nil
}
func (r ProductionRuntimeReconciler) path() string {
	if strings.TrimSpace(r.PodmanPath) == "" {
		return rootlesspodman.DefaultPodmanExecutable
	}
	return r.PodmanPath
}
