package cmd

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func sandboxStateFromRuntimeTarget(target sandboxruntime.Target) *sandbox.SandboxState {
	state := &sandbox.SandboxState{
		ID:                target.ID,
		Name:              target.Name,
		Provider:          target.Provider,
		WorkspaceID:       target.Connection.WorkspaceID,
		IP:                target.Connection.PublicIP,
		TailscaleIP:       target.Connection.TailscaleIP,
		TailscaleHostname: target.Connection.TailscaleHostname,
		TailscaleLockdown: target.Connection.TailscaleLockdown,
		Status:            target.Status,
	}
	if strings.TrimSpace(state.IP) == "" {
		state.IP = target.Connection.Address
	}
	if hasRuntimeState(target.Runtime) {
		state.Runtime = &sandbox.SandboxRuntimeState{
			Driver:         target.Runtime.Driver,
			IsolationLevel: target.Runtime.IsolationLevel,
			RuntimeID:      target.Runtime.RuntimeID,
			Image:          target.Runtime.Image,
			WorkerID:       target.Runtime.WorkerID,
		}
	}
	return state
}

func sandboxConnectInfoFromRuntimeTarget(target sandboxruntime.Target) *sandbox.ConnectInfo {
	return &sandbox.ConnectInfo{
		Name:              target.Name,
		IP:                target.Connection.Address,
		PublicIP:          target.Connection.PublicIP,
		TailscaleIP:       target.Connection.TailscaleIP,
		TailscaleHostname: target.Connection.TailscaleHostname,
		TailscaleLockdown: target.Connection.TailscaleLockdown,
		WorkspaceID:       target.Connection.WorkspaceID,
	}
}

func hasRuntimeState(runtime sandboxruntime.RuntimeState) bool {
	return strings.TrimSpace(runtime.Driver) != "" ||
		strings.TrimSpace(runtime.IsolationLevel) != "" ||
		strings.TrimSpace(runtime.RuntimeID) != "" ||
		strings.TrimSpace(runtime.Image) != "" ||
		strings.TrimSpace(runtime.WorkerID) != ""
}
