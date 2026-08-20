package sshrelay

// LinuxAgentDialerOptions freezes one private host-admin Unix endpoint and its
// expected filesystem owner. It is a live, non-serializable configuration.
type LinuxAgentDialerOptions struct {
	liveValue
	EndpointPath string
	ExpectedUID  uint32
	ExpectedGID  uint32
}

// LinuxPeerVerifierOptions freezes the expected connected peer credentials.
type LinuxPeerVerifierOptions struct {
	liveValue
	ExpectedUID uint32
	ExpectedGID uint32
}
