package main

import (
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
	helperlinux "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper/linux"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/rolebootstrap"
)

const failClosedExit = 127

func productionRun(args []string) int {
	if len(args) != 0 {
		return failClosedExit
	}
	options, err := assembleHelperOptions()
	if err != nil {
		return failClosedExit
	}
	return runHelper(options)
}

func assembleHelperOptions() (l8composition.HelperOptions, error) {
	if _, err := rolebootstrap.EmbeddedGeneratedArtifact(); err != nil {
		return l8composition.HelperOptions{}, err
	}
	kernel, err := helperlinux.NewSyscallPolicyCoreKernel(helperlinux.SyscallPolicyCoreKernelOptions{})
	if err != nil {
		return l8composition.HelperOptions{}, err
	}
	core, err := helperlinux.NewCore(helperlinux.CoreOptions{Kernel: kernel})
	if err != nil {
		return l8composition.HelperOptions{}, err
	}
	// Host, Runtime, Transport, and SSH stay caller-supplied. This process
	// never installs a default SSH extension.
	return l8composition.HelperOptions{
		Core:   core,
		Policy: credentialhelper.NewHelperPolicy(),
	}, nil
}

func runHelper(options l8composition.HelperOptions) int {
	service, _, err := l8composition.NewHelper(options)
	if err != nil || service == nil {
		return failClosedExit
	}
	// Live Serve, listen, bind, and dial remain unaccepted.
	return failClosedExit
}
