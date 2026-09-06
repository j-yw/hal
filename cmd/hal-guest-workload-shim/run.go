package main

import (
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/rolebootstrap"
)

const failClosedExit = 127

type workloadShimDeps struct {
	Artifact     rolebootstrap.GeneratedArtifact
	System       rolebootstrap.System
	BinarySHA256 [32]byte
}

func productionRun(args []string) int {
	if len(args) != 0 {
		return failClosedExit
	}
	artifact, err := rolebootstrap.EmbeddedGeneratedArtifact()
	if err != nil {
		return failClosedExit
	}
	return runShim(nil, workloadShimDeps{Artifact: artifact})
}

func runShim(args []string, deps workloadShimDeps) int {
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
	plan, err := rolebootstrap.NewInstallPlan(rolebootstrap.RoleWorkloadShim, deps.Artifact, deps.BinarySHA256)
	if err != nil {
		return failClosedExit
	}
	if _, err := installer.Install(plan); err != nil {
		return failClosedExit
	}
	// Live exec, listen, bind, and dial remain unaccepted.
	return failClosedExit
}
