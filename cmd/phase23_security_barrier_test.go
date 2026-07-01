package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/verify"
)

func TestPhase23FinalBarrierRunAndAutoSandboxConfiguredSecurity(t *testing.T) {
	fixtures := phase23SecurityFixtures()

	t.Run("run", func(t *testing.T) {
		startedAt := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
		finishedAt := startedAt.Add(time.Second)
		projectDir := t.TempDir()
		writeRunSandboxConfig(t, projectDir, phase23SecurityConfigYAML(fixtures))
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))

		var captured runSandboxRequest
		var out bytes.Buffer
		var errOut bytes.Buffer
		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			Base:        "main",
			BaseChanged: true,
			JSON:        true,
			JSONChanged: true,
		}, &out, &errOut, runSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) {
				return store, nil
			},
			newExecutionID: func(time.Time) string {
				return "phase23-run-configured"
			},
			now:        runSandboxTestClock(startedAt, finishedAt),
			workingDir: func() (string, error) { return projectDir, nil },
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return phase23SandboxWorkspacePlan(projectDir), nil
			},
			execute: func(_ context.Context, req runSandboxRequest, out io.Writer, _ io.Writer, _ runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
				captured = req
				running, err := store.LoadManifest("phase23-run-configured")
				if err != nil {
					t.Fatalf("LoadManifest() before execute: %v", err)
				}
				requireRunSandboxConfiguredSecurityManifest(t, running.Security)
				assertNoPhase23SensitiveLeaks(t, "running run manifest security", mustMarshalSandboxSecurityMetadata(t, running.Security), fixtures)
				if err := json.NewEncoder(out).Encode(RunResult{ContractVersion: 1, OK: true, Iterations: 1, Complete: true, Summary: "phase23"}); err != nil {
					t.Fatalf("Encode(RunResult) error: %v", err)
				}
				return runSandboxExecutionResult{RemoteStarted: true}, nil
			},
		})
		if err != nil {
			t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
		}
		requireFactoryConfiguredSandboxSecurityRequest(t, captured.Security)
		var result RunResult
		decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
		if !result.OK || result.Summary != "phase23" {
			t.Fatalf("RunResult = %#v, want successful phase23 response", result)
		}
		manifest, err := store.LoadManifest("phase23-run-configured")
		if err != nil {
			t.Fatalf("LoadManifest() error: %v", err)
		}
		requireRunSandboxConfiguredSecurityManifest(t, manifest.Security)
		assertNoPhase23SensitiveLeaks(t, "run sandbox JSON", out.String(), fixtures)
		assertNoPhase23SensitiveLeaks(t, "final run manifest security", mustMarshalSandboxSecurityMetadata(t, manifest.Security), fixtures)
	})

	t.Run("auto", func(t *testing.T) {
		startedAt := time.Date(2026, 7, 2, 10, 1, 0, 0, time.UTC)
		finishedAt := startedAt.Add(time.Second)
		projectDir := t.TempDir()
		writeRunSandboxConfig(t, projectDir, phase23SecurityConfigYAML(fixtures))
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))

		var captured autoSandboxRequest
		var out bytes.Buffer
		var errOut bytes.Buffer
		err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			Base:        "main",
			BaseChanged: true,
			JSON:        true,
			JSONChanged: true,
		}, &out, &errOut, autoSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) {
				return store, nil
			},
			newExecutionID: func(time.Time) string {
				return "phase23-auto-configured"
			},
			now: runSandboxTestClock(startedAt, finishedAt),
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return phase23SandboxWorkspacePlan(projectDir), nil
			},
			execute: func(_ context.Context, req autoSandboxRequest, out io.Writer, _ io.Writer, _ autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
				captured = req
				running, err := store.LoadManifest("phase23-auto-configured")
				if err != nil {
					t.Fatalf("LoadManifest() before execute: %v", err)
				}
				requireRunSandboxConfiguredSecurityManifest(t, running.Security)
				assertNoPhase23SensitiveLeaks(t, "running auto manifest security", mustMarshalSandboxSecurityMetadata(t, running.Security), fixtures)
				_, _ = io.WriteString(out, autoSandboxRemoteSuccessJSON("phase23")+"\n")
				return autoSandboxExecutionResult{RemoteStarted: true}, nil
			},
		})
		if err != nil {
			t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
		}
		requireFactoryConfiguredSandboxSecurityRequest(t, captured.Security)
		var result AutoResult
		decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
		if !result.OK || result.Summary != "phase23" {
			t.Fatalf("AutoResult = %#v, want successful phase23 response", result)
		}
		manifest, err := store.LoadManifest("phase23-auto-configured")
		if err != nil {
			t.Fatalf("LoadManifest() error: %v", err)
		}
		requireRunSandboxConfiguredSecurityManifest(t, manifest.Security)
		assertNoPhase23SensitiveLeaks(t, "auto sandbox JSON", out.String(), fixtures)
		assertNoPhase23SensitiveLeaks(t, "final auto manifest security", mustMarshalSandboxSecurityMetadata(t, manifest.Security), fixtures)
	})
}

func TestPhase23FinalBarrierRunAndAutoSandboxLegacyDefaults(t *testing.T) {
	t.Run("run", func(t *testing.T) {
		startedAt := time.Date(2026, 7, 2, 10, 2, 0, 0, time.UTC)
		finishedAt := startedAt.Add(time.Second)
		projectDir := t.TempDir()
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))

		var captured runSandboxRequest
		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			Base:        "main",
			BaseChanged: true,
		}, io.Discard, io.Discard, runSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) {
				return store, nil
			},
			newExecutionID: func(time.Time) string {
				return "phase23-run-defaults"
			},
			now:        runSandboxTestClock(startedAt, finishedAt),
			workingDir: func() (string, error) { return projectDir, nil },
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return phase23SandboxWorkspacePlan(projectDir), nil
			},
			execute: func(_ context.Context, req runSandboxRequest, _ io.Writer, _ io.Writer, _ runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
				captured = req
				return runSandboxExecutionResult{}, nil
			},
		})
		if err != nil {
			t.Fatalf("runRunSandboxWithWriter() unexpected error: %v", err)
		}
		if captured.Security.RequestedNetworkPolicy != sandbox.SandboxNetworkPolicyDenyByDefault ||
			captured.Security.RequestedNetworkPolicyIntent != nil ||
			!reflect.DeepEqual(captured.Security.RequestedSecretModes, []string{sandbox.SandboxSecretModeHTTPProxy}) {
			t.Fatalf("run default security request = %#v, want legacy compatibility defaults", captured.Security)
		}
		manifest, err := store.LoadManifest("phase23-run-defaults")
		if err != nil {
			t.Fatalf("LoadManifest() error: %v", err)
		}
		requireRunSandboxLegacySecurityManifest(t, manifest.Security)
	})

	t.Run("auto", func(t *testing.T) {
		startedAt := time.Date(2026, 7, 2, 10, 3, 0, 0, time.UTC)
		finishedAt := startedAt.Add(time.Second)
		projectDir := t.TempDir()
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))

		var captured autoSandboxRequest
		err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			Base:        "main",
			BaseChanged: true,
		}, io.Discard, io.Discard, autoSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) {
				return store, nil
			},
			newExecutionID: func(time.Time) string {
				return "phase23-auto-defaults"
			},
			now: runSandboxTestClock(startedAt, finishedAt),
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return phase23SandboxWorkspacePlan(projectDir), nil
			},
			execute: func(_ context.Context, req autoSandboxRequest, _ io.Writer, _ io.Writer, _ autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
				captured = req
				return autoSandboxExecutionResult{}, nil
			},
		})
		if err != nil {
			t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v", err)
		}
		if captured.Security.RequestedNetworkPolicy != sandbox.SandboxNetworkPolicyDenyByDefault ||
			captured.Security.RequestedNetworkPolicyIntent != nil ||
			!reflect.DeepEqual(captured.Security.RequestedSecretModes, []string{sandbox.SandboxSecretModeHTTPProxy}) {
			t.Fatalf("auto default security request = %#v, want legacy compatibility defaults", captured.Security)
		}
		manifest, err := store.LoadManifest("phase23-auto-defaults")
		if err != nil {
			t.Fatalf("LoadManifest() error: %v", err)
		}
		requireRunSandboxLegacySecurityManifest(t, manifest.Security)
	})
}

func TestPhase23FinalBarrierFactorySandboxDurableSurfaces(t *testing.T) {
	fixtures := phase23SecurityFixtures()
	projectDir := t.TempDir()
	writeRunSandboxConfig(t, projectDir, phase23SecurityConfigYAML(fixtures))
	if err := os.WriteFile(filepath.Join(projectDir, ".hal", "prd.md"), []byte("# PRD\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(prd.md) error: %v", err)
	}

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 7, 2, 10, 4, 0, 0, time.UTC)
	target := phase23FactorySandboxTarget("hal-phase-23-security-intent-propagation")
	var captured factorySandboxExecutorRequest
	var out bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), projectDir, factoryRunRequest{
		MarkdownPath: ".hal/prd.md",
		BaseBranch:   "main",
		Sandbox:      true,
		JSON:         true,
		Secrets: []factory.RunSecretInput{{
			Name:     "PHASE23_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
		}},
	}, &out, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "phase23-factory-direct", nil },
		now:          func() time.Time { return now },
		workingDir:   func() (string, error) { return projectDir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/phase-23-security-intent-propagation", nil
		},
		repoRemote: func(string) (string, error) {
			return fixtures.credentialRemote, nil
		},
		lookupEnv: phase23LookupEnv(fixtures),
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			policy := factory.DefaultFactoryPolicy()
			return &policy, nil
		},
		loadEngine: func(string) (string, error) {
			return factory.PolicyEngineCodex, nil
		},
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			t.Fatal("local factory pipeline should not run for sandbox request")
			return nil
		},
		runSandbox: func(ctx context.Context, req factorySandboxExecutorRequest) error {
			captured = req
			return runFactorySandboxExecutorWithDeps(ctx, req, factorySandboxExecutorDeps{
				defaultStore: func() (factory.Store, error) { return store, nil },
				now:          func() time.Time { return now },
				loadSandbox: func(name string) (*sandbox.SandboxState, error) {
					if name != target.Name {
						t.Fatalf("load sandbox name = %q, want %q", name, target.Name)
					}
					return target, nil
				},
				resolveProvider: func(string) (sandbox.Provider, error) {
					return fakeFactorySandboxProvider{}, nil
				},
				resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
					return fakeFactorySandboxRuntimeDriver{execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
						return &sandboxruntime.ExecResult{}, nil
					}}, nil
				},
				runProviderExec: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, io.Writer) error {
					return nil
				},
				bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
					return factory.BootstrapResult{}, nil
				},
				cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
					return nil
				},
			})
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("verification load sandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			data, err := json.Marshal(verify.Result{
				SchemaVersion: verify.SchemaVersion,
				Status:        verify.StatusPass,
				Summary:       verify.Summary{},
				Checks:        []verify.CheckResult{},
			})
			if err != nil {
				t.Fatalf("Marshal(verify result) error: %v", err)
			}
			_, _ = out.Write(append(data, '\n'))
			return nil
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v\nstdout=%s", err, out.String())
	}
	requireFactoryConfiguredSandboxSecurityRequest(t, captured.Security)
	if len(captured.ResolvedSecrets) != 1 || captured.ResolvedSecrets[0].Value != fixtures.rawSecret {
		t.Fatalf("resolved secrets = %#v, want live secret only on executor request", captured.ResolvedSecrets)
	}

	record, err := store.LoadRun("phase23-factory-direct")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Sandbox == nil {
		t.Fatalf("record sandbox metadata = nil")
	}
	requireFactorySandboxConfiguredSecurityMetadata(t, record.Sandbox.Security)
	events, err := store.LoadEvents("phase23-factory-direct")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	requirePhase23FactorySecurityPolicyEvent(t, events)
	assertNoPhase23SensitiveLeaks(t, "factory run JSON", out.String(), fixtures)
	assertNoPhase23SensitiveLeaks(t, "factory direct durable surfaces", mustMarshalSandboxSecurityMetadata(t, struct {
		Run    *factory.RunRecord    `json:"run"`
		Events []factory.EventRecord `json:"events"`
	}{
		Run:    record,
		Events: events,
	}), fixtures)
}

func TestPhase23FinalBarrierFactoryQueueSandboxFailureRedaction(t *testing.T) {
	fixtures := phase23SecurityFixtures()
	projectDir := t.TempDir()
	writeRunSandboxConfig(t, projectDir, phase23SecurityConfigYAML(fixtures))
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 7, 2, 10, 5, 0, 0, time.UTC)
	claimedAt := createdAt.Add(time.Minute)
	record := testFactoryRunRecord("phase23-queue-run", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	record.RepoPath = projectDir
	record.RepoRemote = "https://" + factory.RunSecretRedactionPlaceholder + "@github.com/example/hal.git"
	record.Source = factory.SourceMetadata{Kind: factory.SourceKindMarkdown, Path: ".hal/prd.md"}
	record.BaseBranch = "main"
	record.Secrets = []factory.RunSecretMetadata{{
		Name:     "PHASE23_TOKEN",
		Source:   factory.RunSecretSourceEnv,
		Required: true,
		Present:  true,
	}}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	entry := testFactoryQueueEntry("phase23-queue-entry", record.RunID, factory.QueueStatusQueued, createdAt)
	entry.ExecutorMode = factory.ExecutorModeSandbox
	if err := store.SaveQueue([]factory.QueueEntry{entry}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	var captured factorySandboxExecutorRequest
	deps := queueWorkTestDepsWithExecutors(store, claimedAt, factory.QueueClaim{WorkerID: "phase23-worker", PID: 2308, Hostname: "phase23-host"}, func(context.Context, factoryRunPipelineRequest) error {
		t.Fatal("local factory pipeline should not run for sandbox queue entry")
		return nil
	}, func(_ context.Context, req factorySandboxExecutorRequest) error {
		captured = req
		return fmt.Errorf("queued sandbox failed with %s via %s", fixtures.rawSecret, fixtures.credentialRemote)
	})
	deps.lookupEnv = phase23LookupEnv(fixtures)
	deps.loadPolicy = func(string) (*factory.FactoryPolicy, error) {
		policy := factory.DefaultFactoryPolicy()
		policy.SandboxRequired = true
		return &policy, nil
	}
	deps.loadEngine = func(string) (string, error) {
		return factory.PolicyEngineCodex, nil
	}
	deps.repoRemote = func(string) (string, error) {
		return fixtures.credentialRemote, nil
	}

	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, deps)
	if err == nil {
		t.Fatalf("runFactoryQueueWorkWithDeps() error = nil, want queued sandbox failure")
	}
	requireFactoryConfiguredSandboxSecurityRequest(t, captured.Security)
	if len(captured.ResolvedSecrets) != 1 || captured.ResolvedSecrets[0].Value != fixtures.rawSecret {
		t.Fatalf("resolved secrets = %#v, want live secret only on executor request", captured.ResolvedSecrets)
	}
	assertNoPhase23SensitiveLeaks(t, "queue returned error", err.Error(), fixtures)
	assertNoPhase23SensitiveLeaks(t, "queue JSON response", out.String(), fixtures)
	loaded, loadErr := store.LoadRun(record.RunID)
	if loadErr != nil {
		t.Fatalf("LoadRun() error: %v", loadErr)
	}
	entries, loadErr := store.ListQueue()
	if loadErr != nil {
		t.Fatalf("ListQueue() error: %v", loadErr)
	}
	events, loadErr := store.LoadEvents(record.RunID)
	if loadErr != nil {
		t.Fatalf("LoadEvents() error: %v", loadErr)
	}
	assertNoPhase23SensitiveLeaks(t, "queue durable failure surfaces", mustMarshalSandboxSecurityMetadata(t, struct {
		Run     *factory.RunRecord    `json:"run"`
		Entries []factory.QueueEntry  `json:"entries"`
		Events  []factory.EventRecord `json:"events"`
	}{
		Run:     loaded,
		Entries: entries,
		Events:  events,
	}), fixtures)
}

func TestPhase23FinalBarrierRootlessSecurityDoesNotOverclaimDenyByDefault(t *testing.T) {
	security := workerRootlessHostSecurity()
	requireWorkerRootlessSandboxSecurity(t, security)
	metadata := factorySandboxSecurityMetadata(security)
	requireWorkerRootlessFactorySecurity(t, metadata)
	encoded := mustMarshalSandboxSecurityMetadata(t, struct {
		ManifestSecurity *sandbox.SandboxSecurity         `json:"manifestSecurity"`
		FactorySecurity  *factory.SandboxSecurityMetadata `json:"factorySecurity"`
	}{
		ManifestSecurity: security,
		FactorySecurity:  metadata,
	})
	if strings.Contains(encoded, `"policyEnforced":"deny_by_default"`) {
		t.Fatalf("rootless security metadata overclaimed deny-by-default enforcement: %s", encoded)
	}
}

type phase23SensitiveValues struct {
	rawSecret        string
	unixSocket       string
	providerEndpoint string
	localPath        string
	credentialRemote string
	workerEndpoint   string
	hostTempPath     string
}

func phase23SecurityFixtures() phase23SensitiveValues {
	rawSecret := "ghp_phase23_raw_secret_123"
	escaped := url.QueryEscape(rawSecret)
	return phase23SensitiveValues{
		rawSecret:        rawSecret,
		unixSocket:       "unix:///tmp/phase23/private/worker.sock",
		providerEndpoint: "https://sandbox.provider.invalid/api?token=" + escaped,
		localPath:        "/Users/v/private/phase23/id_ed25519",
		credentialRemote: "https://git:" + escaped + "@github.com/example/private-hal.git",
		workerEndpoint:   "https://worker.invalid/socket?token=" + escaped,
		hostTempPath:     "/tmp/phase23/host/private-workspace",
	}
}

func (v phase23SensitiveValues) forbidden() []string {
	return []string{
		v.rawSecret,
		url.QueryEscape(v.rawSecret),
		v.unixSocket,
		"/tmp/phase23/private/worker.sock",
		v.providerEndpoint,
		v.localPath,
		v.credentialRemote,
		v.workerEndpoint,
		v.hostTempPath,
	}
}

func phase23SecurityConfigYAML(values phase23SensitiveValues) string {
	return fmt.Sprintf(`sandbox:
  env:
    RAW_SECRET: %q
    WORKER_SOCKET: %q
    PROVIDER_ENDPOINT: %q
    LOCAL_PATH: %q
    CREDENTIAL_REMOTE: %q
    WORKER_ENDPOINT: %q
    HOST_TEMP_PATH: %q
  networkPolicy:
    preset: allow_listed
    rules:
      - kind: domain
        value: api.example.com
        decision: allow
      - kind: metadata_endpoint
        value: "169.254.169.254"
        decision: deny
  secrets:
    requestedModes:
      - env
      - file_tmpfs
    activeModes:
      - env
`, values.rawSecret, values.unixSocket, values.providerEndpoint, values.localPath, values.credentialRemote, values.workerEndpoint, values.hostTempPath)
}

func phase23SandboxWorkspacePlan(projectDir string) sandboxworkspace.Plan {
	return sandboxworkspace.Plan{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		ProjectDir:  projectDir,
		Repository:  "git@example.com:org/hal.git",
		Branch:      "hal/phase-23-security-intent-propagation",
		Upstream:    "origin/main",
		SyncRef:     "refs/remotes/origin/hal/phase-23-security-intent-propagation",
	}
}

func phase23FactorySandboxTarget(name string) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		Name:     name,
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
}

func phase23LookupEnv(values phase23SensitiveValues) func(string) (string, bool) {
	return func(name string) (string, bool) {
		if name == "PHASE23_TOKEN" {
			return values.rawSecret, true
		}
		return "", false
	}
}

func requirePhase23FactorySecurityPolicyEvent(t *testing.T, events []factory.EventRecord) {
	t.Helper()
	for _, event := range events {
		if event.EventType == factory.EventTypePolicyDecision {
			requireFactorySandboxConfiguredSecurityPolicyEvent(t, event)
			return
		}
	}
	t.Fatalf("factory events missing sandbox security policy event: %#v", events)
}

func assertNoPhase23SensitiveLeaks(t *testing.T, label, payload string, values phase23SensitiveValues) {
	t.Helper()
	for _, forbidden := range values.forbidden() {
		if forbidden != "" && strings.Contains(payload, forbidden) {
			t.Fatalf("%s leaked %q: %s", label, forbidden, payload)
		}
	}
}
