package cmd

import "fmt"

const (
	sandboxSyncOutFlagName = "sandbox-sync-out"
	sandboxApplyFlagName   = "sandbox-apply"
)

type sandboxSyncOutFlagValues struct {
	SyncOut        bool
	SyncOutChanged bool
	Apply          bool
	ApplyChanged   bool
}

type sandboxSyncOutOptions struct {
	Enabled bool
	Apply   bool
}

func parseSandboxSyncOutFlagValues(values sandboxSyncOutFlagValues) sandboxSyncOutOptions {
	return sandboxSyncOutOptions{
		Enabled: values.SyncOut || values.Apply,
		Apply:   values.Apply,
	}
}

func validateSandboxSyncOutFlagsRequireSandbox(sandboxMode bool, values sandboxSyncOutFlagValues) error {
	if sandboxMode || (!values.SyncOutChanged && !values.ApplyChanged) {
		return nil
	}
	if values.SyncOutChanged && values.ApplyChanged {
		return fmt.Errorf("--%s and --%s require --sandbox", sandboxSyncOutFlagName, sandboxApplyFlagName)
	}
	if values.SyncOutChanged {
		return fmt.Errorf("--%s requires --sandbox", sandboxSyncOutFlagName)
	}
	return fmt.Errorf("--%s requires --sandbox", sandboxApplyFlagName)
}
