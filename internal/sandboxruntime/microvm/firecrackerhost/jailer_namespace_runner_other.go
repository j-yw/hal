//go:build !linux

package firecrackerhost

import (
	"os"
	"os/exec"
)

func startStrictJailerOSExecCommand(*exec.Cmd, *os.File) (HostProcess, error) {
	return nil, errStrictJailerNamespaceInvalidConfiguration
}
