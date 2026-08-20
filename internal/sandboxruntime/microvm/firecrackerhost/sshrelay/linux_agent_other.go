//go:build !linux

package sshrelay

func NewLinuxAgentDialer(LinuxAgentDialerOptions) (AgentDialer, error) {
	return nil, ErrDependencyRequired
}

func NewLinuxPeerVerifier(LinuxPeerVerifierOptions) (PeerVerifier, error) {
	return nil, ErrDependencyRequired
}
