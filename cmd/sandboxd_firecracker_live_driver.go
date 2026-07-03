package cmd

import (
	"fmt"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"
)

func defaultSandboxdMicroVMDriver(config sandboxdMicroVMConfig) (sandboxruntime.Driver, error) {
	guestAgent, err := firecrackerhost.NewGuestTransportFromEndpoint(firecrackerhost.GuestAgentEndpointOptions{
		Endpoint: config.GuestAgentEndpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("configure Firecracker guest agent endpoint: %w", err)
	}
	return firecrackerhost.NewLiveDriver(firecrackerhost.LiveDriverOptions{
		Config:               config.Config,
		BaseStateDir:         config.StateDir,
		BootAcceptancePoller: firecrackerhost.NewAPISocketBootAcceptancePoller(),
		BootTimeout:          config.BootAcceptanceTimeout,
		BootPollInterval:     config.BootAcceptancePollInterval,
		GuestTransport:       guestAgent,
	})
}

func defaultSandboxdMicroVMConfigValidator(config sandboxdMicroVMConfig) error {
	if err := firecrackerhost.ValidateGuestAgentEndpoint(config.GuestAgentEndpoint); err != nil {
		return fmt.Errorf("sandboxd --firecracker-guest-agent-endpoint is invalid: %w", err)
	}
	return nil
}
