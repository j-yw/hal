package livegate

const MicroVME2ELiveGateID GateID = "microvm-e2e-live"

// MicroVME2ELiveGate composes the existing optional live gates required before
// a microVM live E2E harness can attempt any live action.
func MicroVME2ELiveGate() Gate {
	return Gate{
		ID:           MicroVME2ELiveGateID,
		Category:     GateCategoryMicroVME2E,
		BuildTags:    MicroVME2ERequiredBuildTags(),
		EnvVars:      MicroVME2ERequiredEnvVars(),
		Capabilities: MicroVME2ERequiredCapabilities(),
	}
}

// MicroVME2ERequiredBuildTags returns every build tag that must be present for
// the composed live E2E harness. The dedicated E2E tag is additive to the
// existing component live tags.
func MicroVME2ERequiredBuildTags() []BuildTagName {
	return []BuildTagName{
		BuildTagMicroVME2ELive,
		BuildTagFirecrackerLive,
		BuildTagNetworkEnforcementLive,
		BuildTagCredentialDeliveryLive,
	}
}

// MicroVME2ERequiredEnvVars returns the shared all-of environment markers.
// Credential delivery mode selection remains an any-of check using
// CredentialDeliveryLiveModeEnvVars.
func MicroVME2ERequiredEnvVars() []EnvVarName {
	return []EnvVarName{
		EnvVarFirecrackerLive,
		EnvVarFirecrackerLiveFirecracker,
		EnvVarFirecrackerLiveKernel,
		EnvVarFirecrackerLiveRootfs,
		EnvVarNetworkEnforcementLive,
		EnvVarNetworkEnforcementLiveProxy,
		EnvVarNetworkEnforcementLiveFirewall,
		EnvVarCredentialDeliveryLive,
	}
}

func MicroVME2ERequiredCapabilities() []CapabilityID {
	return []CapabilityID{
		CapabilityFirecrackerMicroVM,
		CapabilityNetworkEnforcement,
		CapabilityCredentialDelivery,
	}
}

func CredentialDeliveryLiveModeEnvVars() []EnvVarName {
	return []EnvVarName{
		EnvVarCredentialDeliveryLiveHTTPProxy,
		EnvVarCredentialDeliveryLiveFileTmpfs,
		EnvVarCredentialDeliveryLiveSSHAgent,
		EnvVarCredentialDeliveryLiveEnv,
	}
}
