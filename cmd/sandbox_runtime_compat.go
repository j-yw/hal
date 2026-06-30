package cmd

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"
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

func sandboxRuntimeTargetFromState(target *sandbox.SandboxState) sandboxruntime.Target {
	if target == nil {
		return sandboxruntime.Target{}
	}
	runtimeTarget := sandboxruntime.Target{
		ID:       target.ID,
		Name:     target.Name,
		Provider: target.Provider,
		Status:   target.Status,
		Runtime: sandboxruntime.RuntimeState{
			Driver: sandboxRuntimeDriverFromState(target),
		},
	}
	if target.Runtime != nil {
		runtimeTarget.Runtime = sandboxruntime.RuntimeState{
			Driver:         sandboxRuntimeDriverFromState(target),
			RuntimeID:      target.Runtime.RuntimeID,
			Image:          target.Runtime.Image,
			WorkerID:       target.Runtime.WorkerID,
			IsolationLevel: target.Runtime.IsolationLevel,
		}
	}
	if info := sandbox.ConnectInfoFromState(target); info != nil {
		runtimeTarget.Connection = sandboxruntime.ConnectionInfo{
			Address:           info.IP,
			PublicIP:          info.PublicIP,
			TailscaleIP:       info.TailscaleIP,
			TailscaleHostname: info.TailscaleHostname,
			TailscaleLockdown: info.TailscaleLockdown,
			WorkspaceID:       info.WorkspaceID,
		}
	}
	return runtimeTarget
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

func sandboxRuntimeDriverFromState(target *sandbox.SandboxState) string {
	if target == nil || target.Runtime == nil {
		return sandbox.SandboxRuntimeDriverSSHMachine
	}
	if driver := strings.TrimSpace(target.Runtime.Driver); driver != "" {
		return driver
	}
	return sandbox.SandboxRuntimeDriverSSHMachine
}

func sandboxRuntimeDriverFromProvider(provider sandbox.Provider) sandboxruntime.Driver {
	if provider == nil {
		return nil
	}
	return sshmachine.New(provider)
}

type sandboxRuntimeDriverFactories struct {
	sshMachine     func(sandbox.Provider) sandboxruntime.Driver
	rootlessPodman func() sandboxruntime.Driver
}

var defaultSandboxRuntimeDriverFactories = productionSandboxRuntimeDriverFactories

func sandboxRuntimeDriverFromTarget(target sandboxruntime.Target, resolveProvider func(string) (sandbox.Provider, error)) (sandboxruntime.Driver, error) {
	return sandboxRuntimeDriverFromTargetWithFactories(target, resolveProvider, defaultSandboxRuntimeDriverFactories())
}

func productionSandboxRuntimeDriverFactories() sandboxRuntimeDriverFactories {
	return sandboxRuntimeDriverFactories{
		sshMachine: sandboxRuntimeDriverFromProvider,
		rootlessPodman: func() sandboxruntime.Driver {
			runner := rootlesspodman.DefaultCommandRunner{}
			return rootlesspodman.New(rootlesspodman.Options{
				LifecycleRunner: runner,
				ExecRunner:      runner,
				CopyRunner:      runner,
			})
		},
	}
}

func sandboxRuntimeDriverFromTargetWithFactories(target sandboxruntime.Target, resolveProvider func(string) (sandbox.Provider, error), factories sandboxRuntimeDriverFactories) (sandboxruntime.Driver, error) {
	switch strings.TrimSpace(target.Runtime.Driver) {
	case sandboxruntime.DriverRootlessPodman:
		if factories.rootlessPodman == nil {
			return nil, nil
		}
		return factories.rootlessPodman(), nil
	default:
		if resolveProvider == nil {
			return nil, nil
		}
		provider, err := resolveProvider(target.Provider)
		if err != nil {
			return nil, err
		}
		if factories.sshMachine == nil {
			return nil, nil
		}
		return factories.sshMachine(provider), nil
	}
}
