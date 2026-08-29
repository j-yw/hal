package main

import (
	"os"
	"strings"
	"testing"

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

func TestRunShimRejectsMissingTypedNilAndExtraArgs(t *testing.T) {
	artifact := testArtifact(t)
	system := testSystem(t)
	binary := testDigest(5)
	var zeroSystem rolebootstrap.System
	tests := []struct {
		name string
		args []string
		deps workloadShimDeps
	}{
		{name: "zero deps"},
		{name: "extra args", args: []string{"extra"}, deps: workloadShimDeps{Artifact: artifact, System: system, BinarySHA256: binary}},
		{name: "missing artifact", deps: workloadShimDeps{System: system, BinarySHA256: binary}},
		{name: "missing system", deps: workloadShimDeps{Artifact: artifact, System: zeroSystem, BinarySHA256: binary}},
		{name: "missing binary", deps: workloadShimDeps{Artifact: artifact, System: system}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if code := runShim(test.args, test.deps); code != failClosedExit {
				t.Fatalf("runShim() = %d, want %d", code, failClosedExit)
			}
		})
	}
}

func TestRunShimFailsClosedAfterSuccessfulConstruction(t *testing.T) {
	deps := workloadShimDeps{
		Artifact:     testArtifact(t),
		System:       testSystem(t),
		BinarySHA256: testDigest(5),
	}
	if code := runShim(nil, deps); code != failClosedExit {
		t.Fatalf("runShim(valid) = %d, want %d", code, failClosedExit)
	}
}

func TestUnsupportedPlatformStubFailsClosed(t *testing.T) {
	source, err := os.ReadFile("main_other.go")
	if err != nil {
		t.Fatalf("ReadFile(main_other.go): %v", err)
	}
	if !strings.Contains(string(source), "os.Exit(127)") {
		t.Fatal("unsupported workload-shim platform does not fail closed")
	}
}

func TestProductionShimDoesNotListenOrInstallDefaultSSH(t *testing.T) {
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
				t.Fatalf("%s contains live shim marker %q", name, forbidden)
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
