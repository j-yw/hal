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
