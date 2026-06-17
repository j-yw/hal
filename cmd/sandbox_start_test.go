package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

type mockLifecycleStartProvider struct {
	mu                sync.Mutex
	startCalls        []string
	startErr          error
	startErrByName    map[string]error
	startResult       *sandbox.LifecycleResult
	startResultByName map[string]*sandbox.LifecycleResult
	statusOut         string
}

func (m *mockLifecycleStartProvider) sortedStartCalls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := append([]string{}, m.startCalls...)
	sort.Strings(result)
	return result
}

func (m *mockLifecycleStartProvider) Create(context.Context, string, map[string]string, io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (m *mockLifecycleStartProvider) Stop(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (m *mockLifecycleStartProvider) Start(_ context.Context, info *sandbox.ConnectInfo, _ io.Writer) (*sandbox.LifecycleResult, error) {
	name := ""
	if info != nil {
		name = info.Name
	}
	m.mu.Lock()
	m.startCalls = append(m.startCalls, name)
	m.mu.Unlock()
	if m.startErrByName != nil {
		if err, ok := m.startErrByName[name]; ok {
			return nil, err
		}
	}
	if m.startErr != nil {
		return nil, m.startErr
	}
	if m.startResultByName != nil {
		if result, ok := m.startResultByName[name]; ok {
			return result, nil
		}
	}
	if m.startResult != nil {
		return m.startResult, nil
	}
	return &sandbox.LifecycleResult{Status: sandbox.StatusRunning}, nil
}

func (m *mockLifecycleStartProvider) Delete(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (m *mockLifecycleStartProvider) SSH(*sandbox.ConnectInfo) (*exec.Cmd, error) { return nil, nil }
func (m *mockLifecycleStartProvider) Exec(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
	return nil, nil
}

func (m *mockLifecycleStartProvider) Status(_ context.Context, _ *sandbox.ConnectInfo, out io.Writer) error {
	if m.statusOut != "" {
		fmt.Fprint(out, m.statusOut)
	}
	return nil
}

func TestSandboxStartCommandLifecycleFlagsOnly(t *testing.T) {
	for _, name := range []string{"all", "pattern"} {
		if sandboxStartCmd.Flags().Lookup(name) == nil {
			t.Fatalf("expected lifecycle flag %q", name)
		}
	}
	for _, name := range []string{"name", "count", "size", "repo", "env", "force", "auto-shutdown", "no-auto-shutdown", "idle-hours"} {
		if sandboxStartCmd.Flags().Lookup(name) != nil {
			t.Fatalf("start command should not expose provisioning flag %q", name)
		}
	}
}

func TestResolveStartTargets_ExplicitNamesIncludeRunningAndDedupe(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "worker", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})

	targets, _, err := resolveStartTargets([]string{"worker", "api", "worker"}, false, "")
	if err != nil {
		t.Fatalf("resolveStartTargets: %v", err)
	}
	got := []string{targets[0].Name, targets[1].Name}
	want := []string{"api", "worker"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("targets = %v, want %v", got, want)
		}
	}
}

func TestResolveStartTargets_AllAndPatternFilterStopped(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
		{Name: "worker-01", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
		{Name: "worker-02", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})

	allTargets, _, err := resolveStartTargets(nil, true, "")
	if err != nil {
		t.Fatalf("resolveStartTargets(--all): %v", err)
	}
	if got := []string{allTargets[0].Name, allTargets[1].Name}; strings.Join(got, ",") != "worker-01,worker-02" {
		t.Fatalf("--all targets = %v, want stopped workers", got)
	}

	patternTargets, _, err := resolveStartTargets(nil, false, "worker-0?")
	if err != nil {
		t.Fatalf("resolveStartTargets(--pattern): %v", err)
	}
	if got := []string{patternTargets[0].Name, patternTargets[1].Name}; strings.Join(got, ",") != "worker-01,worker-02" {
		t.Fatalf("--pattern targets = %v, want stopped workers", got)
	}
}

func TestResolveStartTargets_NoStoppedGuidanceAndMultipleStopped(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "api", Provider: "daytona", Status: sandbox.StatusRunning, CreatedAt: time.Now()},
	})
	_, _, err := resolveStartTargets(nil, false, "")
	if err == nil || err.Error() != "no stopped sandboxes; use 'hal sandbox create' to provision a new sandbox" {
		t.Fatalf("err = %v, want no-stopped create guidance", err)
	}

	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "one", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
		{Name: "two", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})
	_, _, err = resolveStartTargets(nil, false, "")
	if err == nil || !strings.Contains(err.Error(), "multiple stopped sandboxes found: one, two") {
		t.Fatalf("err = %v, want multiple stopped names", err)
	}
}

func TestResolveStartTargets_RejectsConflictingSelectors(t *testing.T) {
	_, _, err := resolveStartTargets([]string{"api"}, true, "")
	if err == nil || err.Error() != "sandbox names, --all, and --pattern are mutually exclusive" {
		t.Fatalf("err = %v, want selector conflict", err)
	}
}

func TestRunSandboxStart_StartsAndPersistsRunningState(t *testing.T) {
	stoppedAt := time.Now().Add(-time.Hour)
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{{
		Name:      "worker",
		Provider:  "daytona",
		Status:    sandbox.StatusStopped,
		StoppedAt: &stoppedAt,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		IP:        "203.0.113.10",
	}})
	provider := &mockLifecycleStartProvider{startResult: &sandbox.LifecycleResult{Status: sandbox.StatusRunning, IP: "203.0.113.99"}}

	var out bytes.Buffer
	if err := runSandboxStart([]string{"worker"}, false, "", &out, provider); err != nil {
		t.Fatalf("runSandboxStart: %v", err)
	}
	if got := provider.sortedStartCalls(); strings.Join(got, ",") != "worker" {
		t.Fatalf("Start calls = %v, want worker", got)
	}
	updated, err := sandbox.LoadActiveInstance("worker")
	if err != nil {
		t.Fatalf("LoadActiveInstance: %v", err)
	}
	if updated.Status != sandbox.StatusRunning {
		t.Fatalf("Status = %q, want running", updated.Status)
	}
	if updated.StoppedAt != nil {
		t.Fatalf("StoppedAt = %v, want nil", updated.StoppedAt)
	}
	if updated.IP != "203.0.113.99" {
		t.Fatalf("IP = %q, want refreshed provider IP", updated.IP)
	}
	if !strings.Contains(out.String(), "Started worker") {
		t.Fatalf("output = %q, want Started worker", out.String())
	}
}

func TestRunSandboxStart_LiveStatusRefreshPersistsChangedIP(t *testing.T) {
	stoppedAt := time.Now().Add(-time.Hour)
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{{
		Name:      "lightsail-box",
		Provider:  "lightsail",
		Status:    sandbox.StatusStopped,
		StoppedAt: &stoppedAt,
		CreatedAt: time.Now(),
		IP:        "44.203.78.10",
	}})
	provider := &mockLifecycleStartProvider{
		startResult: &sandbox.LifecycleResult{Status: sandbox.StatusRunning},
		statusOut:   "Status: running\nPublic IP: 44.203.78.182\n",
	}

	if err := runSandboxStart([]string{"lightsail-box"}, false, "", io.Discard, provider); err != nil {
		t.Fatalf("runSandboxStart: %v", err)
	}
	updated, err := sandbox.LoadActiveInstance("lightsail-box")
	if err != nil {
		t.Fatalf("LoadActiveInstance: %v", err)
	}
	if updated.IP != "44.203.78.182" {
		t.Fatalf("IP = %q, want live status refreshed IP", updated.IP)
	}
}

func TestRunSandboxStart_ExplicitAlreadyRunningIsIdempotent(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{{
		Name:      "api",
		Provider:  "daytona",
		Status:    sandbox.StatusRunning,
		CreatedAt: time.Now(),
	}})
	provider := &mockLifecycleStartProvider{}

	if err := runSandboxStart([]string{"api"}, false, "", io.Discard, provider); err != nil {
		t.Fatalf("runSandboxStart: %v", err)
	}
	if got := provider.sortedStartCalls(); strings.Join(got, ",") != "api" {
		t.Fatalf("Start calls = %v, want api", got)
	}
}

func TestRunSandboxStart_PartialFailures(t *testing.T) {
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{
		{Name: "one", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
		{Name: "two", Provider: "daytona", Status: sandbox.StatusStopped, CreatedAt: time.Now()},
	})
	provider := &mockLifecycleStartProvider{startErrByName: map[string]error{"two": errors.New("boom")}}

	var out bytes.Buffer
	err := runSandboxStart(nil, true, "", &out, provider)
	if err == nil || !strings.Contains(err.Error(), "1/2 sandbox starts failed") {
		t.Fatalf("err = %v, want partial failure", err)
	}
	one, _ := sandbox.LoadActiveInstance("one")
	two, _ := sandbox.LoadActiveInstance("two")
	if one.Status != sandbox.StatusRunning {
		t.Fatalf("one status = %q, want running", one.Status)
	}
	if two.Status != sandbox.StatusStopped {
		t.Fatalf("two status = %q, want stopped", two.Status)
	}
}

func TestRunSandboxStart_SyncsMatchingLocalState(t *testing.T) {
	projectDir := t.TempDir()
	t.Chdir(projectDir)
	origMigrate := sandboxMigrate
	sandboxMigrate = func(projectDir string, out io.Writer) error { return nil }
	t.Cleanup(func() { sandboxMigrate = origMigrate })

	stoppedAt := time.Now().Add(-time.Hour)
	state := &sandbox.SandboxState{
		ID:        "global-id",
		Name:      "local-box",
		Provider:  "daytona",
		Status:    sandbox.StatusStopped,
		StoppedAt: &stoppedAt,
		CreatedAt: time.Now(),
	}
	setupStopGlobalRegistry(t, []*sandbox.SandboxState{state})
	halDir := filepath.Join(projectDir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := sandbox.SaveState(halDir, state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	provider := &mockLifecycleStartProvider{}
	if err := runSandboxStart([]string{"local-box"}, false, "", io.Discard, provider); err != nil {
		t.Fatalf("runSandboxStart: %v", err)
	}
	local, err := sandbox.LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if local.Status != sandbox.StatusRunning || local.StoppedAt != nil {
		t.Fatalf("local state status/stoppedAt = %q/%v, want running/nil", local.Status, local.StoppedAt)
	}
}
