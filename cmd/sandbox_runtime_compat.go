package cmd

import (
	"fmt"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxruntime/sshmachine"
	"github.com/jywlabs/hal/internal/sandboxtarget"
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
			TemplateLock:   sandboxTemplateLockFromRuntimeMetadata(target.Runtime.Metadata),
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
			Metadata:       sandboxRuntimeMetadataFromState(target.Runtime),
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
		strings.TrimSpace(runtime.WorkerID) != "" ||
		runtime.Metadata != nil
}

func sandboxRuntimeMetadataFromState(runtime *sandbox.SandboxRuntimeState) *sandboxruntime.RuntimeMetadata {
	if runtime == nil {
		return nil
	}
	return sandboxruntime.SanitizeRuntimeMetadata(&sandboxruntime.RuntimeMetadata{
		TemplateLock: sandboxRuntimeTemplateLockFromSandbox(runtime.TemplateLock),
	})
}

func sandboxRuntimeTemplateLockFromSandbox(lock *sandbox.SandboxTemplateLockMetadata) *sandboxruntime.RuntimeTemplateLockMetadata {
	lock = sandbox.SanitizeSandboxTemplateLockMetadata(lock)
	if lock == nil {
		return nil
	}
	return sandboxruntime.SanitizeRuntimeTemplateLockMetadata(&sandboxruntime.RuntimeTemplateLockMetadata{
		Document:          sandboxRuntimeTemplateLockEntryFromSandbox(lock.Document),
		TemplateReference: sandboxRuntimeTemplateLockEntryFromSandbox(lock.TemplateReference),
		RuntimeImage:      sandboxRuntimeTemplateLockEntryFromSandbox(lock.RuntimeImage),
		SourceArtifact:    sandboxRuntimeTemplateLockEntryFromSandbox(lock.SourceArtifact),
		TrustPolicy:       sandboxRuntimeTemplateTrustPolicyFromSandbox(lock.TrustPolicy),
	})
}

func sandboxRuntimeTemplateLockEntryFromSandbox(entry *sandbox.SandboxTemplateLockEntryMetadata) *sandboxruntime.RuntimeTemplateLockEntryMetadata {
	if entry == nil {
		return nil
	}
	return &sandboxruntime.RuntimeTemplateLockEntryMetadata{
		SourceKind:      entry.SourceKind,
		ReferenceKind:   entry.ReferenceKind,
		Status:          entry.Status,
		DigestAlgorithm: entry.DigestAlgorithm,
		DigestValue:     entry.DigestValue,
		SizeBytes:       entry.SizeBytes,
		LockedAt:        entry.LockedAt,
		WarningCodes:    append([]string(nil), entry.WarningCodes...),
		ReasonCode:      entry.ReasonCode,
	}
}

func sandboxRuntimeTemplateTrustPolicyFromSandbox(policy *sandbox.SandboxTemplateTrustPolicyMetadata) *sandboxruntime.RuntimeTemplateTrustPolicyMetadata {
	if policy == nil {
		return nil
	}
	return &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{
		Mode:            policy.Mode,
		Decision:        policy.Decision,
		SourceKind:      policy.SourceKind,
		ReferenceKind:   policy.ReferenceKind,
		Status:          policy.Status,
		DigestAlgorithm: policy.DigestAlgorithm,
		DigestValue:     policy.DigestValue,
		WarningCodes:    append([]string(nil), policy.WarningCodes...),
		ErrorCodes:      append([]string(nil), policy.ErrorCodes...),
		ReasonCodes:     append([]string(nil), policy.ReasonCodes...),
	}
}

func sandboxTemplateLockFromRuntimeMetadata(metadata *sandboxruntime.RuntimeMetadata) *sandbox.SandboxTemplateLockMetadata {
	metadata = sandboxruntime.SanitizeRuntimeMetadata(metadata)
	if metadata == nil || metadata.TemplateLock == nil {
		return nil
	}
	lock := metadata.TemplateLock
	return sandbox.SanitizeSandboxTemplateLockMetadata(&sandbox.SandboxTemplateLockMetadata{
		Document:          sandboxTemplateLockEntryFromRuntime(lock.Document),
		TemplateReference: sandboxTemplateLockEntryFromRuntime(lock.TemplateReference),
		RuntimeImage:      sandboxTemplateLockEntryFromRuntime(lock.RuntimeImage),
		SourceArtifact:    sandboxTemplateLockEntryFromRuntime(lock.SourceArtifact),
		TrustPolicy:       sandboxTemplateTrustPolicyFromRuntime(lock.TrustPolicy),
	})
}

func sandboxTemplateLockEntryFromRuntime(entry *sandboxruntime.RuntimeTemplateLockEntryMetadata) *sandbox.SandboxTemplateLockEntryMetadata {
	if entry == nil {
		return nil
	}
	return &sandbox.SandboxTemplateLockEntryMetadata{
		SourceKind:      entry.SourceKind,
		ReferenceKind:   entry.ReferenceKind,
		Status:          entry.Status,
		DigestAlgorithm: entry.DigestAlgorithm,
		DigestValue:     entry.DigestValue,
		SizeBytes:       entry.SizeBytes,
		LockedAt:        entry.LockedAt,
		WarningCodes:    append([]string(nil), entry.WarningCodes...),
		ReasonCode:      entry.ReasonCode,
	}
}

func sandboxTemplateTrustPolicyFromRuntime(policy *sandboxruntime.RuntimeTemplateTrustPolicyMetadata) *sandbox.SandboxTemplateTrustPolicyMetadata {
	if policy == nil {
		return nil
	}
	return &sandbox.SandboxTemplateTrustPolicyMetadata{
		Mode:            policy.Mode,
		Decision:        policy.Decision,
		SourceKind:      policy.SourceKind,
		ReferenceKind:   policy.ReferenceKind,
		Status:          policy.Status,
		DigestAlgorithm: policy.DigestAlgorithm,
		DigestValue:     policy.DigestValue,
		WarningCodes:    append([]string(nil), policy.WarningCodes...),
		ErrorCodes:      append([]string(nil), policy.ErrorCodes...),
		ReasonCodes:     append([]string(nil), policy.ReasonCodes...),
	}
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
	microVM        func() sandboxruntime.Driver
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
		microVM: func() sandboxruntime.Driver {
			return microvm.New()
		},
	}
}

func sandboxRuntimeDriverFromTargetWithFactories(target sandboxruntime.Target, resolveProvider func(string) (sandbox.Provider, error), factories sandboxRuntimeDriverFactories) (sandboxruntime.Driver, error) {
	switch driver := strings.TrimSpace(target.Runtime.Driver); driver {
	case sandboxruntime.DriverRootlessPodman:
		if factories.rootlessPodman == nil {
			return nil, nil
		}
		return factories.rootlessPodman(), nil
	case sandboxruntime.DriverMicroVM:
		if factories.microVM == nil {
			return nil, nil
		}
		return factories.microVM(), nil
	case "", sandboxruntime.DriverSSHMachine:
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
	default:
		return nil, sandboxRuntimeUnsupportedError(target, driver)
	}
}

func sandboxRuntimeUnsupportedError(target sandboxruntime.Target, driver string) error {
	driver = strings.TrimSpace(driver)
	hostID := strings.TrimSpace(target.Runtime.WorkerID)
	failure := sandboxtarget.Failure{
		Reason:        sandboxtarget.FailureReasonRuntimeUnsupported,
		HostID:        hostID,
		RuntimeDriver: driver,
	}
	if hostID != "" {
		failure.Message = fmt.Sprintf("runtime_unsupported: worker host %q requested sandbox runtime driver %q is not supported by current execution resolver", hostID, driver)
	} else {
		failure.Message = fmt.Sprintf("runtime_unsupported: requested sandbox runtime driver %q is not supported by current execution resolver", driver)
	}
	return &failure
}
