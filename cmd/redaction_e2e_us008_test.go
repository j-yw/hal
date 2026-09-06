package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestUS008RunAutoAndFactoryFakeBackedE2ERedactionSurfaces(t *testing.T) {
	raw := us008RawRedactionValues()

	t.Run("run sandbox", func(t *testing.T) {
		root := us006PrepareFakeOnlyTestEnv(t)
		startedAt := time.Date(2026, 7, 4, 3, 8, 0, 0, time.UTC)
		finishedAt := startedAt.Add(time.Second)
		projectDir := filepath.Join(root, "repo")
		store := sandboxexecution.NewStore(filepath.Join(root, "run-executions"))
		target := us006DefaultWorkerBackedTarget("us008-run-default")
		resolver := &fakeDefaultSandboxResolver{t: t, target: target}
		probe := newUS008RedactionProbe(t, "run",
			`{"contractVersion":1,"ok":true,"summary":"us008 run redaction"}`+"\n",
			us008UnsafeOutputLine(raw)+"\n",
		)

		var out bytes.Buffer
		var errOut bytes.Buffer
		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			JSON:        true,
			JSONChanged: true,
			Base:        "main",
			BaseChanged: true,
		}, &out, &errOut, runSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID: func(time.Time) string {
				return "run-us008-redaction-e2e"
			},
			now:        runSandboxTestClock(startedAt, finishedAt),
			workingDir: func() (string, error) { return projectDir, nil },
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return us006BundleWorkspacePlan(projectDir), nil
			},
			loadSandbox:            probe.forbiddenLoadSandbox,
			listSandboxes:          probe.forbiddenListSandboxes,
			listHosts:              probe.forbiddenListHosts,
			listLeases:             probe.forbiddenListLeases,
			resolveDefault:         resolver.resolve,
			provision:              probe.forbiddenProvision,
			acquireLease:           probe.forbiddenAcquireLease,
			resolveProvider:        probe.resolveProvider,
			resolveRuntimeDriver:   probe.resolveRuntimeDriver,
			resolveWorkerRuntime:   probe.forbiddenWorkerRuntime,
			persistSandboxState:    probe.persistSandboxState,
			runProviderExecWithEnv: probe.forbiddenProviderExecWithEnv,
			runProviderScript:      probe.forbiddenProviderScript,
			engineAuthFiles:        probe.engineAuthFiles,
			bootstrap:              probe.forbiddenBootstrap,
			materializeWorkspace:   probe.materializeWorkspace,
			prepareCommandContext: func(context.Context, sandboxexec.PrepareContext, string, string, io.Writer) (sandboxworkspace.MaterializationOperation, error) {
				return sandboxworkspace.MaterializationOperation{Phase: sandboxworkspace.MaterializationPhaseCommandConfig}, nil
			},
		})
		if err != nil {
			t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
		}
		probe.requireRunAutoPath(t, "run")

		manifest := us006LoadExecutionManifest(t, store, "run-us008-redaction-e2e")
		us006RequireExecutionManifestFakeOnly(t, manifest, sandboxexecution.PurposeRun, target.Name, store.Root(), root)
		us008RequireSandboxExecutionEvidenceRedacted(t, store, manifest, raw, "run")
		if got := us008CollectedPayload(t, store, manifest, "output/stderr-summary.txt"); got != "[redacted]\n" {
			t.Fatalf("run stderr summary payload = %q, want stable redaction marker", got)
		}
		us008RequireCollectedPayload(t, store, manifest, ".hal/reports.tar")
	})

	t.Run("auto sandbox", func(t *testing.T) {
		root := us006PrepareFakeOnlyTestEnv(t)
		startedAt := time.Date(2026, 7, 4, 3, 9, 0, 0, time.UTC)
		finishedAt := startedAt.Add(time.Second)
		projectDir := filepath.Join(root, "repo")
		store := sandboxexecution.NewStore(filepath.Join(root, "auto-executions"))
		target := us006DefaultWorkerBackedTarget("us008-auto-default")
		resolver := &fakeDefaultSandboxResolver{t: t, target: target}
		probe := newUS008RedactionProbe(t, "auto",
			autoSandboxRemoteSuccessJSON("us008 auto redaction")+"\n",
			us008UnsafeOutputLine(raw)+"\n",
		)

		var out bytes.Buffer
		var errOut bytes.Buffer
		err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			JSON:        true,
			JSONChanged: true,
			Base:        "main",
			BaseChanged: true,
		}, &out, &errOut, autoSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID: func(time.Time) string {
				return "auto-us008-redaction-e2e"
			},
			now: runSandboxTestClock(startedAt, finishedAt),
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return us006BundleWorkspacePlan(projectDir), nil
			},
			loadSandbox:            probe.forbiddenLoadSandbox,
			listSandboxes:          probe.forbiddenListSandboxes,
			listHosts:              probe.forbiddenListHosts,
			listLeases:             probe.forbiddenListLeases,
			resolveDefault:         resolver.resolve,
			provision:              probe.forbiddenProvision,
			acquireLease:           probe.forbiddenAcquireLease,
			resolveProvider:        probe.resolveProvider,
			resolveRuntimeDriver:   probe.resolveRuntimeDriver,
			resolveWorkerRuntime:   probe.forbiddenWorkerRuntime,
			persistSandboxState:    probe.persistSandboxState,
			runProviderExecWithEnv: probe.forbiddenProviderExecWithEnv,
			runProviderScript:      probe.forbiddenProviderScript,
			engineAuthFiles:        probe.engineAuthFiles,
			bootstrap:              probe.forbiddenBootstrap,
			materializeWorkspace:   probe.materializeWorkspace,
			prepareCommandContext: func(context.Context, sandboxexec.PrepareContext, string, string, io.Writer) (sandboxworkspace.MaterializationOperation, error) {
				return sandboxworkspace.MaterializationOperation{Phase: sandboxworkspace.MaterializationPhaseCommandConfig}, nil
			},
		})
		if err != nil {
			t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
		}
		probe.requireRunAutoPath(t, "auto")

		manifest := us006LoadExecutionManifest(t, store, "auto-us008-redaction-e2e")
		us006RequireExecutionManifestFakeOnly(t, manifest, sandboxexecution.PurposeAuto, target.Name, store.Root(), root)
		us008RequireSandboxExecutionEvidenceRedacted(t, store, manifest, raw, "auto")
		if got := us008CollectedPayload(t, store, manifest, "output/stderr-summary.txt"); got != "[redacted]\n" {
			t.Fatalf("auto stderr summary payload = %q, want stable redaction marker", got)
		}
		us008RequireCollectedPayload(t, store, manifest, ".hal/reports.tar")
	})

	t.Run("factory sandbox", func(t *testing.T) {
		root := us006PrepareFakeOnlyTestEnv(t)
		now := runSandboxTestClock(
			time.Date(2026, 7, 4, 3, 10, 0, 0, time.UTC),
			time.Date(2026, 7, 4, 3, 10, 1, 0, time.UTC),
			time.Date(2026, 7, 4, 3, 10, 2, 0, time.UTC),
		)
		store := factory.NewStore(filepath.Join(root, "factory-store"))
		target := us006DefaultWorkerBackedTarget("us008-factory-default")
		resolver := &fakeDefaultSandboxResolver{t: t, target: target}
		probe := newUS008RedactionProbe(t, "factory",
			"factory remote ok\n",
			us008UnsafeOutputLine(raw)+"\n",
		)
		resolvedSecrets := us008ResolvedSecrets(raw)

		var out bytes.Buffer
		err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
			ProjectDir: filepath.Join(root, "repo"),
			RunRecord: factory.RunRecord{
				RunID:      "factory-us008-redaction-e2e",
				RepoPath:   "/workspace/us008-factory-repo",
				RepoRemote: raw.credentialedURL,
				BranchName: "feature/us008-default-fake-only",
				BaseBranch: "main",
				Status:     factory.RunStatusRunning,
			},
			RemoteAuto:          factoryRunAutoRequest{BaseBranch: "main"},
			RemoteOutput:        &out,
			ResolvedSecrets:     resolvedSecrets,
			DeferSuccessCleanup: true,
		}, factorySandboxExecutorDeps{
			defaultStore:           func() (factory.Store, error) { return store, nil },
			now:                    now,
			loadSandbox:            probe.forbiddenLoadSandbox,
			listSandboxes:          probe.forbiddenListSandboxes,
			listHosts:              probe.forbiddenListHosts,
			listLeases:             probe.forbiddenListLeases,
			resolveDefault:         resolver.resolve,
			provision:              probe.forbiddenProvision,
			acquireLease:           probe.forbiddenAcquireLease,
			resolveProvider:        probe.resolveProvider,
			resolveRuntimeDriver:   probe.resolveRuntimeDriver,
			resolveWorkerRuntime:   probe.forbiddenWorkerRuntime,
			persistSandboxState:    probe.persistSandboxState,
			runProviderExec:        probe.forbiddenProviderExec,
			runProviderExecWithEnv: probe.forbiddenProviderExecWithEnv,
			runProviderScript:      probe.forbiddenProviderScript,
			engineAuthFiles:        probe.engineAuthFiles,
			bootstrap:              us008FactoryBootstrap(raw),
			cleanupSandbox:         probe.cleanupSandbox,
		})
		if err != nil {
			t.Fatalf("runFactorySandboxExecutorWithDeps() unexpected error: %v\noutput=%s", err, out.String())
		}
		probe.requireFactoryPath(t)

		redactor := factory.NewRunSecretRedactor(resolvedSecrets)
		_, err = factory.CollectSandboxArtifactsWithRedactor(context.Background(), store, "factory-us008-redaction-e2e", us008FactoryArtifactCopier{
			files: map[string]string{
				"/workspace/.hal/reports/factory.log": "factory artifact " + raw.factoryToken + " " + raw.localSecretPath + "\n",
			},
		}, []factory.SandboxArtifactRequest{{
			ID:         "factory-log",
			Name:       "factory-log",
			Type:       "text",
			RemotePath: "/workspace/.hal/reports/factory.log",
			Path:       ".hal/reports/factory.log",
			Summary: map[string]any{
				"endpoint": raw.providerEndpoint,
				"token":    raw.factoryToken,
			},
		}}, redactor)
		if err != nil {
			t.Fatalf("CollectSandboxArtifactsWithRedactor() unexpected error: %v", err)
		}

		copyErr := errors.New("copy failed at " + raw.localSecretPath + " with " + raw.unknownToken + " from " + raw.providerEndpoint)
		_, err = factory.CollectSandboxArtifactsWithRedactor(context.Background(), store, "factory-us008-redaction-e2e", us008FactoryArtifactCopier{
			fileErrs: map[string]error{
				"/workspace/.hal/reports/private.log": copyErr,
			},
		}, []factory.SandboxArtifactRequest{{
			ID:         "private-log",
			Name:       "private-log",
			Type:       "text",
			RemotePath: "/workspace/.hal/reports/private.log",
			Path:       ".hal/reports/private.log",
		}}, factory.RunSecretRedactor{})
		if !errors.Is(err, copyErr) {
			t.Fatalf("CollectSandboxArtifactsWithRedactor() error = %v, want wrapped copy error", err)
		}
		us008RequireNoRawValues(t, "factory artifact copy error", err.Error(), raw.values()...)
		if !strings.Contains(err.Error(), factory.RunSecretRedactionPlaceholder) {
			t.Fatalf("factory artifact copy error = %q, want stable redaction placeholder", err.Error())
		}

		storedRun, err := store.LoadRun("factory-us008-redaction-e2e")
		if err != nil {
			t.Fatalf("LoadRun() error = %v", err)
		}
		events, err := store.LoadEvents(storedRun.RunID)
		if err != nil {
			t.Fatalf("LoadEvents() error = %v", err)
		}
		chunks, err := store.LoadLogChunks(storedRun.RunID)
		if err != nil {
			t.Fatalf("LoadLogChunks() error = %v", err)
		}
		statusPayload := us008FactoryStatusJSON(t, *storedRun, events, factory.NewHandoffSummary(store, *storedRun))
		artifactPayload := us008FactoryArtifactsJSON(t, *storedRun)
		logPayload := us008FactoryLogsJSON(t, storedRun.RunID, chunks)
		evidence := us008FactoryEvidence(t, store, *storedRun, events, chunks, statusPayload, artifactPayload, logPayload)
		us008RequireNoRawValues(t, "factory evidence", evidence, raw.values()...)
		if !strings.Contains(evidence, factory.RunSecretRedactionPlaceholder) && !strings.Contains(evidence, "[redacted]") {
			t.Fatalf("factory evidence missing stable redaction markers:\n%s", evidence)
		}
	})
}

func TestUS008PersistedCommandSummaryRedactsTokenLikeValues(t *testing.T) {
	raw := us008RawRedactionValues()
	got := sanitizeSandboxOutputSummary("safe\n"+us008UnsafeOutputLine(raw)+"\n", nil)
	if got != "safe\n[redacted]\n" {
		t.Fatalf("sanitizeSandboxOutputSummary() = %q, want line-stable redaction", got)
	}
	us008RequireNoRawValues(t, "sandbox output summary", got, raw.values()...)
}

type us008RawValues struct {
	runToken         string
	factoryToken     string
	unknownToken     string
	credentialedURL  string
	providerEndpoint string
	localSecretPath  string
}

func us008RawRedactionValues() us008RawValues {
	return us008RawValues{
		runToken:         "ghp_US008RunToken1234567890",
		factoryToken:     "ghp_US008FactoryToken1234567890",
		unknownToken:     "ghp_US008UnknownCopyToken1234567890",
		credentialedURL:  "https://user:ghp_US008URLSecret1234567890@provider.internal.invalid/repo.git?token=ghp_US008URLToken1234567890",
		providerEndpoint: "https://provider.internal.invalid:8443/api",
		localSecretPath:  "/Users/alice/.config/hal/us008-secret.json",
	}
}

func (v us008RawValues) values() []string {
	return []string{
		v.runToken,
		v.factoryToken,
		v.unknownToken,
		v.credentialedURL,
		"ghp_US008URLSecret1234567890",
		"ghp_US008URLToken1234567890",
		"provider.internal.invalid",
		v.localSecretPath,
	}
}

func us008UnsafeOutputLine(raw us008RawValues) string {
	return fmt.Sprintf("TOKEN=%s remote=%s endpoint=%s secretPath=%s unknown=%s", raw.runToken, raw.credentialedURL, raw.providerEndpoint, raw.localSecretPath, raw.unknownToken)
}

func us008ResolvedSecrets(raw us008RawValues) []factory.ResolvedRunSecret {
	return []factory.ResolvedRunSecret{
		{Name: "US008_RUN_TOKEN", Source: factory.RunSecretSourceEnv, Value: raw.runToken},
		{Name: "US008_FACTORY_TOKEN", Source: factory.RunSecretSourceEnv, Value: raw.factoryToken},
		{Name: "US008_CREDENTIAL_URL", Source: factory.RunSecretSourceEnv, Value: raw.credentialedURL},
		{Name: "US008_PROVIDER_ENDPOINT", Source: factory.RunSecretSourceEnv, Value: raw.providerEndpoint},
		{Name: "US008_LOCAL_SECRET_PATH", Source: factory.RunSecretSourceEnv, Value: raw.localSecretPath},
	}
}

func us008FactoryBootstrap(raw us008RawValues) func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
	return func(_ context.Context, req factory.BootstrapRequest, _ factory.BootstrapDeps) (factory.BootstrapResult, error) {
		return factory.BootstrapResult{
			RepoPath:         req.WorkspaceDir,
			CheckedOutBranch: req.RunBranch,
			Timeline: []factory.BootstrapTimelineEvent{{
				Timestamp:      time.Date(2026, 7, 4, 3, 10, 30, 0, time.UTC),
				Step:           factory.BootstrapStepCloneRepository,
				Status:         factory.RunStatusSucceeded,
				Message:        "bootstrap cloned with " + raw.factoryToken,
				CommandSummary: "git clone " + raw.credentialedURL + " " + raw.localSecretPath,
				OutputSummary:  "bootstrap contacted " + raw.providerEndpoint,
				Metadata: map[string]string{
					"remote":     raw.credentialedURL,
					"endpoint":   raw.providerEndpoint,
					"token":      raw.factoryToken,
					"secretPath": raw.localSecretPath,
				},
			}},
		}, nil
	}
}

type us008RedactionProbe struct {
	us006DefaultFakeOnlyProbe
	stdout string
	stderr string
}

func newUS008RedactionProbe(t *testing.T, lane, stdout, stderr string) *us008RedactionProbe {
	t.Helper()
	return &us008RedactionProbe{
		us006DefaultFakeOnlyProbe: us006DefaultFakeOnlyProbe{t: t, lane: lane},
		stdout:                    stdout,
		stderr:                    stderr,
	}
}

func (p *us008RedactionProbe) resolveRuntimeDriver(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
	p.runtimeResolutions++
	if target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		p.t.Fatalf("%s runtime driver = %q, want SSH-machine compatibility", p.lane, target.Runtime.Driver)
	}
	if target.Runtime.WorkerID != "" || target.Runtime.RuntimeID != "" || target.Runtime.Image != "" {
		p.t.Fatalf("%s runtime metadata = %#v, want no worker metadata on default path", p.lane, target.Runtime)
	}
	return fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			p.execCalls++
			if isWorkerOutputArtifactGenerationExec(req) {
				return &sandboxruntime.ExecResult{}, nil
			}
			joinedArgs := strings.Join(req.Args, " ")
			if !strings.Contains(joinedArgs, "hal") {
				p.t.Fatalf("%s exec args = %#v, want hal command", p.lane, req.Args)
			}
			p.commandExecCalls++
			if _, err := io.WriteString(req.Stdout, p.stdout); err != nil {
				return nil, err
			}
			if _, err := io.WriteString(req.Stderr, p.stderr); err != nil {
				return nil, err
			}
			return &sandboxruntime.ExecResult{}, nil
		},
		copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			p.copyOutCalls++
			if err := os.MkdirAll(filepath.Dir(req.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(req.DestinationPath, []byte(us008SafeCopyOutPayload(req.SourcePath)), 0o600)
		},
	}, nil
}

func us008SafeCopyOutPayload(sourcePath string) string {
	switch {
	case strings.HasSuffix(sourcePath, "/.hal/prd.json"):
		return `{"project":"us008"}` + "\n"
	case strings.HasSuffix(sourcePath, "/.hal/progress.txt"):
		return "- US-008 safe progress\n"
	case strings.HasSuffix(sourcePath, "/.hal/auto-state.json"):
		return `{"step":"done"}` + "\n"
	case strings.HasSuffix(sourcePath, "/.hal/recovery/workspace.patch"):
		return "safe recovery patch\n"
	case strings.HasSuffix(sourcePath, "/.hal/reports.tar"):
		return "safe reports archive payload\n"
	default:
		return "safe sandbox artifact payload\n"
	}
}

type us008FactoryArtifactCopier struct {
	files    map[string]string
	fileErrs map[string]error
}

func (c us008FactoryArtifactCopier) CopyFile(_ context.Context, remotePath, localPath string) error {
	if err := c.fileErrs[remotePath]; err != nil {
		return err
	}
	payload, ok := c.files[remotePath]
	if !ok {
		return factory.ErrSandboxArtifactNotFound
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(localPath, []byte(payload), 0o600)
}

func (c us008FactoryArtifactCopier) CopyDir(context.Context, string, string) error {
	return factory.ErrSandboxArtifactNotFound
}

func us008RequireSandboxExecutionEvidenceRedacted(t *testing.T, store sandboxexecution.Store, manifest *sandboxexecution.Manifest, raw us008RawValues, label string) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(%s manifest) error = %v", label, err)
	}
	evidence := string(data)
	if manifest.ArtifactMetadata != nil {
		for _, artifact := range manifest.ArtifactMetadata.Collected {
			if strings.TrimSpace(artifact.StoredPath) == "" {
				continue
			}
			evidence += "\n" + readRunSandboxStoreFile(t, store, artifact.StoredPath)
		}
	}
	us008RequireNoRawValues(t, label+" sandbox evidence", evidence, raw.values()...)
}

func us008CollectedPayload(t *testing.T, store sandboxexecution.Store, manifest *sandboxexecution.Manifest, path string) string {
	t.Helper()
	if manifest == nil || manifest.ArtifactMetadata == nil {
		t.Fatalf("manifest missing artifact metadata for %s", path)
	}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		if artifact.Path == path {
			return readRunSandboxStoreFile(t, store, artifact.StoredPath)
		}
	}
	t.Fatalf("manifest missing collected artifact %s: %#v", path, manifest.ArtifactMetadata.Collected)
	return ""
}

func us008RequireCollectedPayload(t *testing.T, store sandboxexecution.Store, manifest *sandboxexecution.Manifest, path string) {
	t.Helper()
	if got := strings.TrimSpace(us008CollectedPayload(t, store, manifest, path)); got == "" {
		t.Fatalf("collected artifact %s payload is empty", path)
	}
}

func us008FactoryEvidence(t *testing.T, store factory.Store, record factory.RunRecord, events []factory.EventRecord, chunks []factory.LogChunk, rendered ...string) string {
	t.Helper()
	data, err := json.Marshal(struct {
		Run      factory.RunRecord     `json:"run"`
		Timeline []factory.EventRecord `json:"timeline"`
		Logs     []factory.LogChunk    `json:"logs"`
	}{
		Run:      record,
		Timeline: events,
		Logs:     chunks,
	})
	if err != nil {
		t.Fatalf("Marshal(factory evidence) error = %v", err)
	}
	evidence := string(data)
	for _, payload := range rendered {
		evidence += "\n" + payload
	}
	for _, artifact := range record.Artifacts {
		if strings.TrimSpace(artifact.StoredPath) == "" {
			continue
		}
		path, err := store.ResolveArtifactPath(record.RunID, artifact.StoredPath)
		if err != nil {
			t.Fatalf("ResolveArtifactPath(%s) error = %v", artifact.StoredPath, err)
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		evidence += "\n" + string(payload)
	}
	return evidence
}

func us008FactoryStatusJSON(t *testing.T, record factory.RunRecord, events []factory.EventRecord, handoff factory.HandoffSummary) string {
	t.Helper()
	var out bytes.Buffer
	safeHandoff := factoryStatusJSONHandoff(handoff)
	if err := renderFactoryStatusJSON(&out, record, events, safeHandoff); err != nil {
		t.Fatalf("renderFactoryStatusJSON() error = %v", err)
	}
	return out.String()
}

func us008FactoryArtifactsJSON(t *testing.T, record factory.RunRecord) string {
	t.Helper()
	var out bytes.Buffer
	if err := renderFactoryArtifactsJSON(&out, record); err != nil {
		t.Fatalf("renderFactoryArtifactsJSON() error = %v", err)
	}
	return out.String()
}

func us008FactoryLogsJSON(t *testing.T, runID string, chunks []factory.LogChunk) string {
	t.Helper()
	var out bytes.Buffer
	if err := renderFactoryLogsJSON(&out, runID, sanitizeFactoryLogChunks(chunks)); err != nil {
		t.Fatalf("renderFactoryLogsJSON() error = %v", err)
	}
	return out.String()
}

func us008RequireNoRawValues(t *testing.T, label, payload string, values ...string) {
	t.Helper()
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		if strings.Contains(payload, value) {
			t.Fatalf("%s leaked raw value %q:\n%s", label, value, payload)
		}
	}
}
