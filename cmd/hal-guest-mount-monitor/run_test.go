package main

import (
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/rolebootstrap"
)

func TestProductionRunFailsClosed(t *testing.T) {
	if code := productionRun(nil); code != failClosedExit {
		t.Fatalf("productionRun() = %d, want %d", code, failClosedExit)
	}
	if code := productionRun([]string{"extra"}); code != failClosedExit {
		t.Fatalf("productionRun(extra) = %d, want %d", code, failClosedExit)
	}
}

func TestRunMonitorRejectsMissingTypedNilAndExtraArgs(t *testing.T) {
	artifact := testArtifact(t)
	system := testSystem(t)
	binary := testDigest(5)
	expected := validMonitorExpected(t)
	var zeroSystem rolebootstrap.System
	tests := []struct {
		name string
		args []string
		deps mountMonitorDeps
	}{
		{name: "zero deps"},
		{name: "extra args", args: []string{"extra"}, deps: mountMonitorDeps{Artifact: artifact, System: system, BinarySHA256: binary, Expected: expected}},
		{name: "missing artifact", deps: mountMonitorDeps{System: system, BinarySHA256: binary, Expected: expected}},
		{name: "missing system", deps: mountMonitorDeps{Artifact: artifact, System: zeroSystem, BinarySHA256: binary, Expected: expected}},
		{name: "missing binary", deps: mountMonitorDeps{Artifact: artifact, System: system, Expected: expected}},
		{name: "missing expected", deps: mountMonitorDeps{Artifact: artifact, System: system, BinarySHA256: binary}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if code := runMonitor(test.args, test.deps); code != failClosedExit {
				t.Fatalf("runMonitor() = %d, want %d", code, failClosedExit)
			}
		})
	}
}

func TestRunMonitorFailsClosedAfterSuccessfulConstruction(t *testing.T) {
	deps := mountMonitorDeps{
		Artifact:     testArtifact(t),
		System:       testSystem(t),
		BinarySHA256: testDigest(5),
		Expected:     validMonitorExpected(t),
	}
	if code := runMonitor(nil, deps); code != failClosedExit {
		t.Fatalf("runMonitor(valid) = %d, want %d", code, failClosedExit)
	}
}

func TestUnsupportedPlatformStubFailsClosed(t *testing.T) {
	source, err := os.ReadFile("main_other.go")
	if err != nil {
		t.Fatalf("ReadFile(main_other.go): %v", err)
	}
	if !strings.Contains(string(source), "os.Exit(127)") {
		t.Fatal("unsupported mount-monitor platform does not fail closed")
	}
}

func TestProductionMonitorDoesNotListenOrInstallDefaultSSH(t *testing.T) {
	for _, name := range []string{"run.go", "main_linux.go", "main_other.go"} {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", name, err)
		}
		text := string(source)
		for _, forbidden := range []string{
			"sshrelay.NewHelperExtension",
			"l8composition.NewHelper",
			"l8composition.NewClient",
			"net.Listen",
			"net.Dial",
			"unix.Socket",
			"unix.Listen",
			"unix.Bind",
			"SOCK_STREAM",
			"SOCK_SEQPACKET",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains live monitor marker %q", name, forbidden)
			}
		}
	}
}

func testArtifact(t *testing.T) rolebootstrap.GeneratedArtifact {
	t.Helper()
	artifact, err := rolebootstrap.NewGeneratedArtifact(testDigest(1), testDigest(2), testDigest(3), testDigest(4))
	if err != nil {
		t.Fatalf("NewGeneratedArtifact: %v", err)
	}
	return artifact
}

func testSystem(t *testing.T) rolebootstrap.System {
	t.Helper()
	system, err := rolebootstrap.NewSystem(
		func(plan rolebootstrap.InstallPlan) (rolebootstrap.InstalledRole, error) {
			return rolebootstrap.NewInstalledRole(plan)
		},
		func() error { return nil },
	)
	if err != nil {
		t.Fatalf("NewSystem: %v", err)
	}
	return system
}

func testDigest(seed byte) (digest [32]byte) {
	for index := range digest {
		digest[index] = seed + byte(index)
	}
	return digest
}

func validMonitorExpected(t *testing.T) l8composition.ControllerMonitorExpected {
	t.Helper()
	job := testDigest(0)
	ready := l8composition.ControllerMonitorReadyBody{
		Revision:          1,
		JobGeneration:     "job-gen-1",
		MonitorGeneration: "monitor-gen-1",
		MountGeneration:   "mount-gen-1",
		CgroupGeneration:  "cgroup-gen-1",
		LimitSetID:        l8composition.ControllerMonitorLimitSetID,
		CreateJobSHA256:   testDigest(0x20),
	}
	digest, err := l8composition.ControllerMonitorReadySHA256(job, ready)
	if err != nil {
		t.Fatalf("ControllerMonitorReadySHA256: %v", err)
	}
	ready.MonitorReadySHA256 = digest
	return l8composition.ControllerMonitorExpected{
		MonitorCredential:                      l8composition.ControllerMonitorKernelCredential{PID: 43, UID: 0, GID: 0},
		ControllerCredential:                   l8composition.ControllerMonitorKernelCredential{PID: 42, UID: 0, GID: 0},
		AgentPID:                               44,
		JobIdentityDigest:                      job,
		MonitorReady:                           ready,
		AuthenticatedSessionHardExpiryUnixNano: 1,
	}
}
