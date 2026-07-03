package cmd

import (
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"
)

func defaultSandboxdMicroVMDriver(config sandboxdMicroVMConfig) (sandboxruntime.Driver, error) {
	return firecrackerhost.NewLiveDriver(firecrackerhost.LiveDriverOptions{
		Config:               config.Config,
		BaseStateDir:         config.StateDir,
		BootAcceptancePoller: firecrackerhost.NewAPISocketBootAcceptancePoller(),
		BootTimeout:          config.BootAcceptanceTimeout,
		BootPollInterval:     config.BootAcceptancePollInterval,
	})
}
