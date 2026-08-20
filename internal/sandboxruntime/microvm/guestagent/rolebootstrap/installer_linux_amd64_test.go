//go:build linux && amd64

package rolebootstrap

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestNewInstallerRequiresGeneratedArtifactAndSystem(t *testing.T) {
	artifact := roleBootstrapTestArtifact(t, 1)
	if installer, err := NewInstaller(InstallerOptions{}); installer != nil || !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("NewInstaller(empty) = %#v, %v, want invalid argument", installer, err)
	}
	if installer, err := NewInstaller(InstallerOptions{Artifact: artifact}); installer != nil || !errors.Is(err, ErrDependency) {
		t.Fatalf("NewInstaller(no system) = %#v, %v, want dependency", installer, err)
	}
}

func TestInstallerExecutesExactValidatedPlanOnce(t *testing.T) {
	artifact := roleBootstrapTestArtifact(t, 1)
	plan, err := NewInstallPlan(RoleAgent, artifact, roleBootstrapDigest(9))
	if err != nil {
		t.Fatalf("NewInstallPlan() error = %v", err)
	}
	var calls, closes int
	var received InstallPlan
	system, err := NewSystem(
		func(candidate InstallPlan) (InstalledRole, error) {
			calls++
			received = candidate
			return NewInstalledRole(candidate)
		},
		func() error { closes++; return nil },
	)
	if err != nil {
		t.Fatalf("NewSystem() error = %v", err)
	}
	installer, err := NewInstaller(InstallerOptions{Artifact: artifact, System: system})
	if err != nil {
		t.Fatalf("NewInstaller() error = %v", err)
	}
	installed, err := installer.Install(plan)
	if err != nil {
		t.Fatalf("Install() error = %v", err)
	}
	if calls != 1 || received != plan || installed.Role() != RoleAgent || installed.BinarySHA256() != plan.BinarySHA256() {
		t.Fatalf("Install() did not preserve the exact plan/result")
	}
	if _, err := installer.Install(plan); !errors.Is(err, ErrTransition) {
		t.Fatalf("second Install() error = %v, want transition", err)
	}
	if calls != 1 {
		t.Fatalf("system calls = %d, want 1", calls)
	}
	if err := installer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := installer.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if closes != 1 {
		t.Fatalf("system close calls = %d, want 1", closes)
	}
}

func TestInstallerRejectsGeneratedIdentityMismatchBeforeSystemCall(t *testing.T) {
	configured := roleBootstrapTestArtifact(t, 1)
	foreign := roleBootstrapTestArtifact(t, 2)
	plan, err := NewInstallPlan(RoleMonitor, foreign, roleBootstrapDigest(9))
	if err != nil {
		t.Fatalf("NewInstallPlan() error = %v", err)
	}
	var calls int
	system, err := NewSystem(
		func(candidate InstallPlan) (InstalledRole, error) {
			calls++
			return NewInstalledRole(candidate)
		},
		func() error { return nil },
	)
	if err != nil {
		t.Fatalf("NewSystem() error = %v", err)
	}
	installer, err := NewInstaller(InstallerOptions{Artifact: configured, System: system})
	if err != nil {
		t.Fatalf("NewInstaller() error = %v", err)
	}
	if _, err := installer.Install(plan); !errors.Is(err, ErrArtifactMismatch) {
		t.Fatalf("Install(foreign artifact) error = %v, want mismatch", err)
	}
	if calls != 0 {
		t.Fatalf("system calls = %d, want 0", calls)
	}
}

func TestInstallerConcurrentInstallCallsConsumeSystemOnce(t *testing.T) {
	artifact := roleBootstrapTestArtifact(t, 1)
	plan, err := NewInstallPlan(RoleWorkloadShim, artifact, roleBootstrapDigest(9))
	if err != nil {
		t.Fatalf("NewInstallPlan() error = %v", err)
	}
	var calls atomic.Int32
	system, err := NewSystem(
		func(candidate InstallPlan) (InstalledRole, error) {
			calls.Add(1)
			return NewInstalledRole(candidate)
		},
		func() error { return nil },
	)
	if err != nil {
		t.Fatalf("NewSystem() error = %v", err)
	}
	installer, err := NewInstaller(InstallerOptions{Artifact: artifact, System: system})
	if err != nil {
		t.Fatalf("NewInstaller() error = %v", err)
	}

	const count = 16
	errorsByCall := make(chan error, count)
	var wait sync.WaitGroup
	for range count {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, installErr := installer.Install(plan)
			errorsByCall <- installErr
		}()
	}
	wait.Wait()
	close(errorsByCall)
	var successes, transitions int
	for installErr := range errorsByCall {
		switch {
		case installErr == nil:
			successes++
		case errors.Is(installErr, ErrTransition):
			transitions++
		default:
			t.Fatalf("Install() error = %v", installErr)
		}
	}
	if successes != 1 || transitions != count-1 || calls.Load() != 1 {
		t.Fatalf("successes/transitions/system calls = %d/%d/%d, want 1/%d/1", successes, transitions, calls.Load(), count-1)
	}
}

func roleBootstrapTestArtifact(t *testing.T, seed byte) GeneratedArtifact {
	t.Helper()
	artifact, err := NewGeneratedArtifact(
		roleBootstrapDigest(seed),
		roleBootstrapDigest(seed+1),
		roleBootstrapDigest(seed+2),
		roleBootstrapDigest(seed+3),
	)
	if err != nil {
		t.Fatalf("NewGeneratedArtifact() error = %v", err)
	}
	return artifact
}

func roleBootstrapDigest(seed byte) [32]byte {
	var digest [32]byte
	for index := range digest {
		digest[index] = seed + byte(index)
	}
	return digest
}
