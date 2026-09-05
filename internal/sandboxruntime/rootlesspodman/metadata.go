package rootlesspodman

import (
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	DriverID       = sandboxruntime.DriverRootlessPodman
	HostKind       = sandbox.SandboxHostKindLocal
	IsolationLevel = sandbox.SandboxIsolationLevelContainer
)

// RuntimeMetadata identifies the runtime/security posture exposed by this
// adapter before any target-specific metadata is available.
type RuntimeMetadata struct {
	DriverID       string
	HostKind       string
	IsolationLevel string
}

func DefaultMetadata() RuntimeMetadata {
	return RuntimeMetadata{
		DriverID:       DriverID,
		HostKind:       HostKind,
		IsolationLevel: IsolationLevel,
	}
}
