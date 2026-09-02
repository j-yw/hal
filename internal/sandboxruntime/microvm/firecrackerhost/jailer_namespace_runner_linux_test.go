//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestStrictJailerNamespaceRunnerRealStarterExecsJailerWithNoInheritedFDsAndEmptyEnvironment(t *testing.T) {
	network, writer := atomicJailerTestPipe(t)
	writer.Close()
	provider := &atomicJailerNamespaceProvider{nextNetwork: network}
	var command *exec.Cmd
	starter := OSExecNamespaceProcessStarter{startCommand: func(got *exec.Cmd) error {
		command = got
		return errors.New("injected start stop")
	}}
	runner, err := newStrictJailerNamespaceRunner(strictJailerNamespaceRunnerOptions{
		namespace: provider, starter: starter,
	})
	if err != nil {
		t.Fatal(err)
	}

	plan := atomicJailerTestPlan(t, "run-alpha")
	request := plan.processRequest()
	_, err = runner.StartHostProcess(context.Background(), request)
	if !errors.Is(err, errStrictJailerNamespaceStartFailed) {
		t.Fatalf("StartHostProcess() error = %v, want sanitized start failure", err)
	}
	if command == nil || command.Path != request.Executable {
		t.Fatalf("command = %#v, want direct Jailer command %q", command, request.Executable)
	}
	wantArgs := append([]string{request.Executable}, request.Args...)
	if !reflect.DeepEqual(command.Args, wantArgs) {
		t.Fatalf("command args = %#v, want exact Jailer args %#v", command.Args, wantArgs)
	}
	if len(command.Env) != 0 {
		t.Fatalf("command environment = %#v, want empty", command.Env)
	}
	if len(command.ExtraFiles) != 0 {
		t.Fatalf("command inherited files = %#v, want zero", command.ExtraFiles)
	}
	if provider.calls != 1 {
		t.Fatalf("namespace duplication calls = %d, want one", provider.calls)
	}
	if _, statErr := network.Stat(); statErr == nil {
		t.Fatal("network namespace descriptor remained open after real starter returned")
	}
}

func TestStrictJailerOSExecLaunchSetsNetworkOnLockedCreatingThreadAndRetainsItThroughWait(t *testing.T) {
	var events []string
	runStrictJailerOSExecLaunch(strictJailerOSExecLaunchOps{
		lockOSThread: func() { events = append(events, "lock") },
		unshareFilesystem: func() error {
			events = append(events, "unshare")
			return nil
		},
		setNetworkNamespace: func() error {
			events = append(events, "setns-network")
			return nil
		},
		umask: func(mask int) int {
			if mask == 0o177 {
				events = append(events, "umask-private")
				return 0o022
			}
			events = append(events, "umask-restore")
			return 0o177
		},
		armParentDeathSignal: func() { events = append(events, "arm") },
		start:                func() error { events = append(events, "start"); return nil },
		publishStarted:       func(error) { events = append(events, "publish") },
		wait:                 func() error { events = append(events, "wait"); return nil },
		publishCompleted:     func(error) { events = append(events, "complete") },
	})
	want := []string{"lock", "unshare", "setns-network", "umask-private", "arm", "start", "publish", "wait", "complete", "umask-restore"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("launch events = %#v, want locked creator retained through wait %#v", events, want)
	}
}

func TestStrictJailerOSExecLaunchSetnsFailurePreventsProcessStart(t *testing.T) {
	var events []string
	var published error
	runStrictJailerOSExecLaunch(strictJailerOSExecLaunchOps{
		lockOSThread: func() { events = append(events, "lock") },
		unshareFilesystem: func() error {
			events = append(events, "unshare")
			return nil
		},
		setNetworkNamespace: func() error {
			events = append(events, "setns-network")
			return errors.New("unsafe /Users/alice/network namespace failure")
		},
		umask:                func(int) int { events = append(events, "umask"); return 0o022 },
		armParentDeathSignal: func() { events = append(events, "arm") },
		start:                func() error { events = append(events, "start"); return nil },
		publishStarted: func(err error) {
			events = append(events, "publish")
			published = err
		},
		wait:             func() error { events = append(events, "wait"); return nil },
		publishCompleted: func(error) { events = append(events, "complete") },
	})
	want := []string{"lock", "unshare", "setns-network", "publish"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("launch events = %#v, want fail before start %#v", events, want)
	}
	if !errors.Is(published, errStrictJailerNamespaceStartFailed) {
		t.Fatalf("published error = %v, want sanitized start failure", published)
	}
	if containsAny(published.Error(), "/Users/alice", "network namespace failure") {
		t.Fatalf("setns failure leaked cause: %q", published)
	}
}

func TestStrictJailerOSExecLaunchArmsSIGKILLParentDeath(t *testing.T) {
	command := exec.Command("/bin/true")
	armStrictJailerParentDeathSignal(command)
	if command.SysProcAttr == nil || command.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("SysProcAttr = %#v, want Pdeathsig SIGKILL", command.SysProcAttr)
	}
}

func TestStrictJailerOSExecLaunchDoesNotClaimPostCredentialDropContainment(t *testing.T) {
	source, err := os.ReadFile("jailer_namespace_runner_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{
		"does not prove final", "credential changes", "Production selection therefore remains blocked",
		"initial user namespace", "calling locked OS thread", "not inherited",
	} {
		if !strings.Contains(string(source), marker) {
			t.Fatalf("strict Jailer launch documentation lost containment limit %q", marker)
		}
	}
}
