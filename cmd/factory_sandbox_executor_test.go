package cmd

import (
	"context"
	"io"
	"os/exec"
	"reflect"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

func TestNormalizeFactorySandboxExecutorDepsFillsProductionDefaults(t *testing.T) {
	deps := normalizeFactorySandboxExecutorDeps(factorySandboxExecutorDeps{})

	checks := map[string]any{
		"defaultStore":    deps.defaultStore,
		"now":             deps.now,
		"resolveDefault":  deps.resolveDefault,
		"loadSandbox":     deps.loadSandbox,
		"provision":       deps.provision,
		"startSandbox":    deps.startSandbox,
		"resolveProvider": deps.resolveProvider,
		"runProviderExec": deps.runProviderExec,
		"saveRun":         deps.saveRun,
		"appendEvent":     deps.appendEvent,
	}
	for name, fn := range checks {
		if reflect.ValueOf(fn).IsNil() {
			t.Fatalf("%s dependency was not defaulted", name)
		}
	}
}

func TestRunFactorySandboxExecutorWithDepsUsesFakeSideEffectBoundaries(t *testing.T) {
	now := time.Date(2026, 6, 21, 9, 30, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := &sandbox.SandboxState{
		Name:     "factory-dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}

	var calls []string
	var savedRecord factory.RunRecord
	var appendedEvent factory.EventRecord
	var gotExecArgs []string
	var gotExecInfo *sandbox.ConnectInfo

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:  ".",
		SandboxName: "factory-dev",
		RunRecord: factory.RunRecord{
			RunID:        "run-sandbox",
			Status:       factory.RunStatusRunning,
			ExecutorMode: factory.ExecutorModeLocal,
			RepoRemote:   "git@github.com:example/repo.git",
		},
		RemoteArgs:   []string{"hal", "auto", ".hal/prd.md"},
		RemoteOutput: io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) {
			calls = append(calls, "store")
			return store, nil
		},
		now: func() time.Time {
			calls = append(calls, "now")
			return now
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			calls = append(calls, "load")
			if name != "factory-dev" {
				t.Fatalf("load sandbox name = %q, want factory-dev", name)
			}
			return target, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatalf("resolveDefault should not be called for explicit sandbox target")
			return nil, "", nil
		},
		provision: func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			t.Fatalf("provision should not be called when resolve succeeds")
			return nil, nil
		},
		startSandbox: func(context.Context, *sandbox.SandboxState, io.Writer) (*sandbox.SandboxState, error) {
			t.Fatalf("startSandbox should not be called for running target")
			return nil, nil
		},
		resolveProvider: func(providerName string) (sandbox.Provider, error) {
			calls = append(calls, "provider")
			if providerName != "daytona" {
				t.Fatalf("providerName = %q, want daytona", providerName)
			}
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, info *sandbox.ConnectInfo, args []string, _ io.Writer) error {
			calls = append(calls, "exec")
			gotExecInfo = info
			gotExecArgs = append([]string(nil), args...)
			return nil
		},
		saveRun: func(_ factory.Store, record *factory.RunRecord) error {
			calls = append(calls, "save")
			savedRecord = *record
			return nil
		},
		appendEvent: func(_ factory.Store, event *factory.EventRecord) error {
			calls = append(calls, "event")
			appendedEvent = *event
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}

	wantCalls := []string{"store", "now", "save", "load", "provider", "exec", "now", "event"}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	if savedRecord.ExecutorMode != factory.ExecutorModeSandbox {
		t.Fatalf("saved executorMode = %q, want %q", savedRecord.ExecutorMode, factory.ExecutorModeSandbox)
	}
	if !savedRecord.UpdatedAt.Equal(now) {
		t.Fatalf("saved UpdatedAt = %s, want %s", savedRecord.UpdatedAt, now)
	}
	if gotExecInfo == nil || gotExecInfo.Name != "factory-dev" || gotExecInfo.IP != "127.0.0.1" {
		t.Fatalf("exec info = %#v, want factory-dev at 127.0.0.1", gotExecInfo)
	}
	if !reflect.DeepEqual(gotExecArgs, []string{"hal", "auto", ".hal/prd.md"}) {
		t.Fatalf("exec args = %#v", gotExecArgs)
	}
	if appendedEvent.RunID != "run-sandbox" || appendedEvent.Metadata["executorMode"] != factory.ExecutorModeSandbox {
		t.Fatalf("appended event = %#v", appendedEvent)
	}
}

func TestRunFactorySandboxExecutorWithDepsCanProvisionAndStartWithFakes(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	provisioned := &sandbox.SandboxState{
		Name:     "factory-new",
		Provider: "hetzner",
		Status:   sandbox.StatusStopped,
	}
	started := *provisioned
	started.Status = sandbox.StatusRunning

	var provisionReq factorySandboxProvisionRequest
	startCalled := false

	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:  "/repo",
		SandboxName: "factory-new",
		RunRecord: factory.RunRecord{
			RunID:      "run-provision",
			RepoRemote: "git@github.com:example/repo.git",
		},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "factory-new" {
				t.Fatalf("load sandbox name = %q, want factory-new", name)
			}
			return nil, errNoFactorySandbox
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			t.Fatalf("resolveDefault should not be called for explicit sandbox target")
			return nil, "", nil
		},
		provision: func(_ context.Context, req factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			provisionReq = req
			return provisioned, nil
		},
		startSandbox: func(_ context.Context, instance *sandbox.SandboxState, _ io.Writer) (*sandbox.SandboxState, error) {
			startCalled = true
			if instance.Name != "factory-new" {
				t.Fatalf("start instance = %#v", instance)
			}
			return &started, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if provisionReq.ProjectDir != "/repo" || provisionReq.Name != "factory-new" || provisionReq.Repo != "git@github.com:example/repo.git" {
		t.Fatalf("provision request = %#v", provisionReq)
	}
	if !startCalled {
		t.Fatalf("startSandbox was not called for stopped provisioned target")
	}
}

func TestRunFactorySandboxExecutorWithDepsUsesDefaultResolutionWithoutExplicitTarget(t *testing.T) {
	target := &sandbox.SandboxState{
		Name:     "factory-only",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}

	resolved := false
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		RunRecord: factory.RunRecord{RunID: "run-default"},
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return factory.NewStore(t.TempDir()), nil },
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatalf("loadSandbox should not be called without explicit sandbox target")
			return nil, nil
		},
		resolveDefault: func(filter func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			resolved = true
			if !filter(target) {
				t.Fatalf("running sandbox filter rejected running target")
			}
			return target, "connecting to only active sandbox \"factory-only\"", nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
			return nil
		},
		saveRun:     func(factory.Store, *factory.RunRecord) error { return nil },
		appendEvent: func(factory.Store, *factory.EventRecord) error { return nil },
	})
	if err != nil {
		t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v", err)
	}
	if !resolved {
		t.Fatalf("resolveDefault was not called")
	}
}

type factorySandboxTestError string

func (e factorySandboxTestError) Error() string { return string(e) }

const errNoFactorySandbox = factorySandboxTestError("no running sandboxes")

type fakeFactorySandboxProvider struct{}

func (fakeFactorySandboxProvider) Create(context.Context, string, map[string]string, io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (fakeFactorySandboxProvider) Stop(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (fakeFactorySandboxProvider) Start(context.Context, *sandbox.ConnectInfo, io.Writer) (*sandbox.LifecycleResult, error) {
	return &sandbox.LifecycleResult{Status: sandbox.StatusRunning}, nil
}

func (fakeFactorySandboxProvider) Delete(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (fakeFactorySandboxProvider) SSH(*sandbox.ConnectInfo) (*exec.Cmd, error) {
	return nil, nil
}

func (fakeFactorySandboxProvider) Exec(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
	return nil, nil
}

func (fakeFactorySandboxProvider) Status(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}
