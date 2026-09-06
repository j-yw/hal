//go:build !linux

package firecrackerhost

import (
	"os"
	"os/exec"
)

func prepareStrictJailerNetworkNamespaceForExec(*os.File) error {
	return errStrictJailerNamespaceInvalidConfiguration
}

func configureStrictJailerCgroup(*exec.Cmd, *os.File) error { return errJailerCgroup }

func startStrictJailerOSExecCommand(*exec.Cmd, *os.File, *strictJailerExecutableLease) (HostProcess, error) {
	return nil, errStrictJailerNamespaceInvalidConfiguration
}
