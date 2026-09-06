package cmd

import (
	"fmt"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	sandboxHostFlagName    = "sandbox-host"
	sandboxRuntimeFlagName = "sandbox-runtime"
)

type sandboxTargetFlagValues struct {
	HostID         string
	HostChanged    bool
	RuntimeDriver  string
	RuntimeChanged bool
}

func parseSandboxTargetFlagValues(values sandboxTargetFlagValues) (sandboxTargetFlagValues, error) {
	values.HostID = strings.TrimSpace(values.HostID)
	if values.HostChanged && values.HostID == "" {
		return sandboxTargetFlagValues{}, fmt.Errorf("--%s must not be empty", sandboxHostFlagName)
	}

	values.RuntimeDriver = strings.TrimSpace(values.RuntimeDriver)
	if values.RuntimeChanged {
		if values.RuntimeDriver == "" {
			return sandboxTargetFlagValues{}, fmt.Errorf("--%s must not be empty", sandboxRuntimeFlagName)
		}
		switch values.RuntimeDriver {
		case sandboxruntime.DriverSSHMachine, sandboxruntime.DriverRootlessPodman, sandboxruntime.DriverMicroVM:
		default:
			return sandboxTargetFlagValues{}, fmt.Errorf("--%s must be one of %s, %s, or %s", sandboxRuntimeFlagName, sandboxruntime.DriverSSHMachine, sandboxruntime.DriverRootlessPodman, sandboxruntime.DriverMicroVM)
		}
	}

	return values, nil
}

func validateSandboxTargetFlagsRequireSandbox(sandboxMode bool, values sandboxTargetFlagValues) error {
	if sandboxMode || (!values.HostChanged && !values.RuntimeChanged) {
		return nil
	}
	if values.HostChanged && values.RuntimeChanged {
		return fmt.Errorf("--%s and --%s require --sandbox", sandboxHostFlagName, sandboxRuntimeFlagName)
	}
	if values.HostChanged {
		return fmt.Errorf("--%s requires --sandbox", sandboxHostFlagName)
	}
	return fmt.Errorf("--%s requires --sandbox", sandboxRuntimeFlagName)
}
