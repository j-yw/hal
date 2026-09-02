//go:build !linux

package firecrackerhost

import "os/exec"

func startStrictJailerOSExecCommand(*exec.Cmd) (HostProcess, error) {
	return nil, errStrictJailerNamespaceInvalidConfiguration
}
