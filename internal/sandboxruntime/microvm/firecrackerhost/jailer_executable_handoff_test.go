package firecrackerhost

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

func TestStrictJailerExecutableHandoffRejectsUnpinnedRealStarter(t *testing.T) {
	network, writer := atomicJailerTestPipe(t)
	defer network.Close()
	defer writer.Close()
	started := false
	starter := OSExecNamespaceProcessStarter{startCommand: func(*exec.Cmd) error {
		started = true
		return errors.New("unexpected unpinned execution")
	}}
	plan := atomicJailerTestPlan(t, "run-alpha")
	_, err := starter.startStrictJailerNamespaceProcess(context.Background(), strictJailerNamespaceProcessStartRequest{
		executable: plan.process.Executable, args: plan.process.Args, networkNamespace: network,
	})
	if started {
		t.Fatal("real Jailer starter reached exec without measured executable ownership")
	}
	if err == nil {
		t.Fatal("real Jailer starter accepted a pathname-only launch")
	}
}
