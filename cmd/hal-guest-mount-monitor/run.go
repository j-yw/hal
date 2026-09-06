package main

import (
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/rolebootstrap"
)

const failClosedExit = 127

type mountMonitorDeps struct {
	Artifact     rolebootstrap.GeneratedArtifact
	System       rolebootstrap.System
	BinarySHA256 [32]byte
	Expected     l8composition.ControllerMonitorExpected
}

func productionRun(args []string) int {
	if len(args) != 0 {
		return failClosedExit
	}
	artifact, err := rolebootstrap.EmbeddedGeneratedArtifact()
	if err != nil {
		return failClosedExit
	}
	return runMonitor(nil, mountMonitorDeps{Artifact: artifact})
}

func runMonitor(args []string, deps mountMonitorDeps) int {
	if len(args) != 0 {
		return failClosedExit
	}
	installer, err := rolebootstrap.NewInstaller(rolebootstrap.InstallerOptions{
		Artifact: deps.Artifact,
		System:   deps.System,
	})
	if err != nil {
		return failClosedExit
	}
	defer func() { _ = installer.Close() }()
	plan, err := rolebootstrap.NewInstallPlan(rolebootstrap.RoleMonitor, deps.Artifact, deps.BinarySHA256)
	if err != nil {
		return failClosedExit
	}
	if _, err := installer.Install(plan); err != nil {
		return failClosedExit
	}
	state, err := l8composition.NewControllerMonitorState(deps.Expected)
	if err != nil || state == nil {
		return failClosedExit
	}
	// Live HL8M sockets, bind, listen, and dial remain unaccepted.
	return failClosedExit
}
