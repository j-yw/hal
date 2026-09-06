//go:build linux

package firecrackerhost

import (
	"os/exec"
	"syscall"
	"testing"
)

func TestJailerCgroupParentDeathSignalPreservesAtomicPlacement(t *testing.T) {
	command := &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: 123}}
	armStrictJailerParentDeathSignal(command)
	if !command.SysProcAttr.UseCgroupFD || command.SysProcAttr.CgroupFD != 123 || command.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("lost atomic cgroup placement: %#v", command.SysProcAttr)
	}
}
