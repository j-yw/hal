//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
)

func TestStrictJailerNamespaceRunnerRealStarterKeepsTwoFDsAndEmptyEnvironment(t *testing.T) {
	user, network := atomicJailerTestDescriptorPair(t)
	provider := &atomicJailerNamespaceProvider{nextUser: user, nextNetwork: network}
	var command *exec.Cmd
	starter := OSExecNamespaceProcessStarter{startCommand: func(got *exec.Cmd) error {
		command = got
		return errors.New("injected start stop")
	}}
	runner, err := newStrictJailerNamespaceRunner(strictJailerNamespaceRunnerOptions{
		namespace: provider, starter: starter, nsenterPath: "/usr/bin/nsenter",
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = runner.StartHostProcess(context.Background(), atomicJailerTestPlan(t, "run-alpha").processRequest())
	if !errors.Is(err, errStrictJailerNamespaceStartFailed) {
		t.Fatalf("StartHostProcess() error = %v, want sanitized start failure", err)
	}
	if command == nil || command.Path != "/usr/bin/nsenter" {
		t.Fatalf("command = %#v, want injected nsenter command", command)
	}
	if len(command.Env) != 0 {
		t.Fatalf("command environment = %#v, want empty", command.Env)
	}
	if len(command.ExtraFiles) != 2 || command.ExtraFiles[0] != user || command.ExtraFiles[1] != network {
		t.Fatalf("command inherited files = %#v, want exact user/network pair", command.ExtraFiles)
	}
	if provider.calls != 1 {
		t.Fatalf("namespace duplication calls = %d, want one", provider.calls)
	}
	for _, file := range []*os.File{user, network} {
		if _, statErr := file.Stat(); statErr == nil {
			t.Fatal("namespace descriptor remained open after real starter returned")
		}
	}
}
