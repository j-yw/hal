//go:build !linux

package firecrackerhost

import (
	"os"
	"os/exec"
)

func prepareStrictJailerNetworkNamespaceForExec(*os.File) error {
	return errStrictJailerNamespaceInvalidConfiguration
}

func startStrictJailerOSExecCommand(*exec.Cmd, *os.File) (HostProcess, error) {
	return nil, errStrictJailerNamespaceInvalidConfiguration
}
