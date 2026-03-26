package cmd

import (
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestPersistLiveStatus_SetsStoppedAtWhenSandboxStops(t *testing.T) {
	now := time.Date(2026, 3, 26, 10, 0, 0, 0, time.UTC)
	inst := &sandbox.SandboxState{
		Name:      "dev-box",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-2 * time.Hour),
	}

	writeCalls := 0
	err := persistLiveStatus(inst, sandbox.StatusStopped, now, func(updated *sandbox.SandboxState) error {
		writeCalls++
		if updated.StoppedAt == nil || !updated.StoppedAt.Equal(now) {
			t.Fatalf("StoppedAt = %v, want %v", updated.StoppedAt, now)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("persistLiveStatus() unexpected error: %v", err)
	}
	if writeCalls != 1 {
		t.Fatalf("writeCalls = %d, want 1", writeCalls)
	}
	if inst.Status != sandbox.StatusStopped {
		t.Fatalf("Status = %q, want %q", inst.Status, sandbox.StatusStopped)
	}
	if inst.StoppedAt == nil || !inst.StoppedAt.Equal(now) {
		t.Fatalf("StoppedAt = %v, want %v", inst.StoppedAt, now)
	}
}

func TestPersistLiveStatus_ClearsStaleStoppedAtOnConfirmedRunningStatus(t *testing.T) {
	stoppedAt := time.Date(2026, 3, 26, 8, 0, 0, 0, time.UTC)
	now := stoppedAt.Add(90 * time.Minute)
	inst := &sandbox.SandboxState{
		Name:      "dev-box",
		Status:    sandbox.StatusRunning,
		CreatedAt: stoppedAt.Add(-4 * time.Hour),
		StoppedAt: &stoppedAt,
	}

	writeCalls := 0
	err := persistLiveStatus(inst, sandbox.StatusRunning, now, func(updated *sandbox.SandboxState) error {
		writeCalls++
		if updated.StoppedAt != nil {
			t.Fatalf("StoppedAt = %v, want nil", updated.StoppedAt)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("persistLiveStatus() unexpected error: %v", err)
	}
	if writeCalls != 1 {
		t.Fatalf("writeCalls = %d, want 1", writeCalls)
	}
	if inst.Status != sandbox.StatusRunning {
		t.Fatalf("Status = %q, want %q", inst.Status, sandbox.StatusRunning)
	}
	if inst.StoppedAt != nil {
		t.Fatalf("StoppedAt = %v, want nil", inst.StoppedAt)
	}
}

func TestLiveStatusWriteTarget_SkipsPersistForStagedFallback(t *testing.T) {
	now := time.Date(2026, 3, 26, 10, 0, 0, 0, time.UTC)
	inst := &sandbox.SandboxState{
		Name:      "staged-box",
		Status:    sandbox.StatusStopped,
		CreatedAt: now.Add(-2 * time.Hour),
	}

	writeCalls := 0
	writeTarget, err := liveStatusWriteTarget(
		inst.Name,
		func(string) (*sandbox.SandboxState, error) { return nil, fs.ErrNotExist },
		func(updated *sandbox.SandboxState) error {
			writeCalls++
			return nil
		},
	)
	if err != nil {
		t.Fatalf("liveStatusWriteTarget() unexpected error: %v", err)
	}

	if err := persistLiveStatus(inst, sandbox.StatusRunning, now, writeTarget); err != nil {
		t.Fatalf("persistLiveStatus() unexpected error: %v", err)
	}
	if writeCalls != 0 {
		t.Fatalf("writeCalls = %d, want 0", writeCalls)
	}
	if inst.Status != sandbox.StatusRunning {
		t.Fatalf("Status = %q, want %q", inst.Status, sandbox.StatusRunning)
	}
}

func TestLiveStatusWriteTarget_SkipsPersistWhenSandboxDeletedAfterTargetCreation(t *testing.T) {
	now := time.Date(2026, 3, 26, 10, 0, 0, 0, time.UTC)
	inst := &sandbox.SandboxState{
		Name:      "deleted-box",
		Status:    sandbox.StatusStopped,
		CreatedAt: now.Add(-2 * time.Hour),
	}

	active := true
	loadCalls := 0
	writeCalls := 0
	writeTarget, err := liveStatusWriteTarget(
		inst.Name,
		func(string) (*sandbox.SandboxState, error) {
			loadCalls++
			if active {
				return &sandbox.SandboxState{Name: inst.Name, Status: sandbox.StatusStopped}, nil
			}
			return nil, fs.ErrNotExist
		},
		func(updated *sandbox.SandboxState) error {
			writeCalls++
			return nil
		},
	)
	if err != nil {
		t.Fatalf("liveStatusWriteTarget() unexpected error: %v", err)
	}

	active = false
	if err := persistLiveStatus(inst, sandbox.StatusRunning, now, writeTarget); err != nil {
		t.Fatalf("persistLiveStatus() unexpected error: %v", err)
	}
	if loadCalls != 2 {
		t.Fatalf("loadCalls = %d, want 2", loadCalls)
	}
	if writeCalls != 0 {
		t.Fatalf("writeCalls = %d, want 0", writeCalls)
	}
	if inst.Status != sandbox.StatusRunning {
		t.Fatalf("Status = %q, want %q", inst.Status, sandbox.StatusRunning)
	}
}

func TestParseLiveStatus_IgnoresUnrelatedTokensOutsideStatusFields(t *testing.T) {
	output := "Recent event: shutdown requested during last maintenance window"

	if status := parseLiveStatus(output); status != sandbox.StatusUnknown {
		t.Fatalf("parseLiveStatus() = %q, want %q", status, sandbox.StatusUnknown)
	}
}

func TestParseLiveStatus_ParsesLabeledStatusField(t *testing.T) {
	output := "Status: active"

	if status := parseLiveStatus(output); status != sandbox.StatusRunning {
		t.Fatalf("parseLiveStatus() = %q, want %q", status, sandbox.StatusRunning)
	}
}

func TestParseLiveStatus_ParsesNegatedRunningStatusField(t *testing.T) {
	tests := []struct {
		name   string
		output string
	}{
		{name: "not running", output: "Status: not running"},
		{name: "not active", output: "State: NOT ACTIVE"},
		{name: "not started", output: "Status: not-started"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if status := parseLiveStatus(tt.output); status != sandbox.StatusStopped {
				t.Fatalf("parseLiveStatus() = %q, want %q", status, sandbox.StatusStopped)
			}
		})
	}
}

func TestParseLiveStatus_ParsesSingleRunningToken(t *testing.T) {
	output := " running \n"

	if status := parseLiveStatus(output); status != sandbox.StatusRunning {
		t.Fatalf("parseLiveStatus() = %q, want %q", status, sandbox.StatusRunning)
	}
}

func TestParseLiveStatus_ParsesSingleStoppedToken(t *testing.T) {
	output := "stopped"

	if status := parseLiveStatus(output); status != sandbox.StatusStopped {
		t.Fatalf("parseLiveStatus() = %q, want %q", status, sandbox.StatusStopped)
	}
}

func TestParseLiveStatus_ParsesTabularStatusColumn(t *testing.T) {
	output := strings.Join([]string{
		"ID          Name         Status    Public IPv4",
		"123456789   dev-box      active    203.0.113.12",
	}, "\n")

	if status := parseLiveStatus(output); status != sandbox.StatusRunning {
		t.Fatalf("parseLiveStatus() = %q, want %q", status, sandbox.StatusRunning)
	}
}
