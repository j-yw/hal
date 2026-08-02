package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/spf13/cobra"
)

func TestL9RunAutoFactoryExposeExplicitTemplateFlags(t *testing.T) {
	for name, command := range map[string]*cobra.Command{
		"run":     runCmd,
		"auto":    autoCmd,
		"factory": factoryRunCmd,
	} {
		t.Run(name, func(t *testing.T) {
			for _, flag := range []string{sandboxTemplateFlagName, sandboxTemplateTrustFlagName} {
				if command.Flags().Lookup(flag) == nil {
					t.Fatalf("%s missing --%s", name, flag)
				}
			}
		})
	}
}

func TestL9TemplateFlagValidationFailsBeforeSelection(t *testing.T) {
	tests := []struct {
		name  string
		input sandboxTemplateFlagValues
		want  string
	}{
		{
			name: "template requires sandbox",
			input: sandboxTemplateFlagValues{
				Reference:        "registry.example/hal/template:latest",
				ReferenceChanged: true,
			},
			want: "--sandbox-template requires --sandbox",
		},
		{
			name: "trust requires template",
			input: sandboxTemplateFlagValues{
				Sandbox:      true,
				TrustMode:    "strict",
				TrustChanged: true,
			},
			want: "--sandbox-template-trust requires --sandbox-template",
		},
		{
			name: "empty template",
			input: sandboxTemplateFlagValues{
				Sandbox:          true,
				Reference:        " ",
				ReferenceChanged: true,
			},
			want: "--sandbox-template must not be empty",
		},
		{
			name: "unknown trust",
			input: sandboxTemplateFlagValues{
				Sandbox:          true,
				Reference:        "registry.example/hal/template:latest",
				ReferenceChanged: true,
				TrustMode:        "permissive",
				TrustChanged:     true,
			},
			want: "--sandbox-template-trust must be one of strict or advisory",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			_, err := prepareSandboxTemplateSelection(context.Background(), sandboxTemplateSelectionRequest{
				Flags: tt.input,
			}, sandboxTemplateSelectionDeps{
				NewWorkflow: func() (sandboxTemplateSelectionWorkflow, error) {
					called = true
					return nil, errors.New("must not construct")
				},
			})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if called {
				t.Fatal("invalid flags constructed selector")
			}
		})
	}
}

func TestL9DryRunAndNoTemplatePathsConstructNothing(t *testing.T) {
	for _, request := range []sandboxTemplateSelectionRequest{
		{
			Command: "run",
			DryRun:  true,
			Flags: sandboxTemplateFlagValues{
				Sandbox:          true,
				Reference:        "registry.example/hal/template:latest",
				ReferenceChanged: true,
			},
		},
		{Command: "run", Flags: sandboxTemplateFlagValues{Sandbox: true}},
		{Command: "auto", Flags: sandboxTemplateFlagValues{Sandbox: true}},
		{Command: "factory", Flags: sandboxTemplateFlagValues{Sandbox: true}},
	} {
		t.Run(request.Command, func(t *testing.T) {
			result, err := prepareSandboxTemplateSelection(context.Background(), request, sandboxTemplateSelectionDeps{
				ReadCredentialEnvironment: func(string) (string, bool) {
					panic("credential environment must not be read")
				},
				NewCache: func() (registryCache, error) {
					panic("cache must not be constructed")
				},
				NewHTTPClient: func() (registryHTTPClient, error) {
					panic("HTTP client must not be constructed")
				},
				NewWorkflow: func() (sandboxTemplateSelectionWorkflow, error) {
					panic("selector must not be constructed")
				},
			})
			if err != nil {
				t.Fatalf("prepare selection error = %v", err)
			}
			if request.DryRun {
				if result.Active || result.Resolved {
					t.Fatalf("dry-run selection = %#v, want unresolved inactive intent", result)
				}
			} else if result.Requested {
				t.Fatalf("no-template result = %#v, want compatibility no-op", result)
			}
		})
	}
}

func TestL9MalformedTemplateReferenceFailsBeforeAllSelectionDependencies(t *testing.T) {
	panicDeps := sandboxTemplateSelectionDeps{
		ReadCredentialEnvironment: func(string) (string, bool) { panic("credential environment read") },
		NewCache:                  func() (registryCache, error) { panic("cache constructed") },
		NewHTTPClient:             func() (registryHTTPClient, error) { panic("HTTP client constructed") },
		NewWorkflow:               func() (sandboxTemplateSelectionWorkflow, error) { panic("workflow constructed") },
	}
	for _, dryRun := range []bool{false, true} {
		for _, ref := range []string{
			"registry.example/hal/../template:latest",
			"registry.example/hal/template",
			"registry.example/hal/template:bad tag",
			" https://registry.example/hal/template:latest ",
			"registry.example:99999/hal/template:latest",
			"registry.example/hal/template:latest@sha256:" + strings.Repeat("a", 64),
			"registry.example/hal/template@SHA256:" + strings.Repeat("a", 64),
			"registry.example/hal/template@sha256:short",
		} {
			_, err := prepareSandboxTemplateSelection(context.Background(), sandboxTemplateSelectionRequest{
				Command: "run",
				DryRun:  dryRun,
				Flags: sandboxTemplateFlagValues{
					Sandbox:          true,
					Reference:        ref,
					ReferenceChanged: true,
				},
			}, panicDeps)
			if err == nil || err.Error() != string(registry.ErrorCodeInvalidReference) {
				t.Fatalf("dryRun=%v reference=%q error = %v, want invalid_reference", dryRun, ref, err)
			}
			if strings.Contains(err.Error(), ref) {
				t.Fatalf("validation error leaked reference %q", ref)
			}
		}
	}
}

func TestL9DigestPinnedCLIReferenceReachesSelectionAsNormalizedImmutableInput(t *testing.T) {
	const digestValue = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	workflow := &sandboxTemplateWorkflowStub{result: l9CommandSelectionResult(strings.Repeat("c", 64))}
	result, err := prepareSandboxTemplateSelection(context.Background(), sandboxTemplateSelectionRequest{
		Command: "run",
		Flags: sandboxTemplateFlagValues{
			Sandbox:          true,
			Reference:        "registry.example/hal/template@sha256:" + digestValue,
			ReferenceChanged: true,
		},
	}, sandboxTemplateSelectionDeps{
		NewWorkflow: func() (sandboxTemplateSelectionWorkflow, error) { return workflow, nil },
	})
	if err != nil {
		t.Fatalf("prepare digest-pinned selection error = %v", err)
	}
	if len(workflow.requests) != 1 ||
		workflow.requests[0].Source.Reference == nil ||
		workflow.requests[0].Source.Reference.Ref != "registry.example/hal/template" ||
		workflow.requests[0].Source.Reference.Digest == nil ||
		workflow.requests[0].Source.Reference.Digest.Algorithm != sandboxtemplate.DigestAlgorithmSHA256 ||
		workflow.requests[0].Source.Reference.Digest.Value != digestValue {
		t.Fatalf("selection request = %#v", workflow.requests)
	}
	if result.Reference != "" || result.Selection == nil {
		t.Fatalf("selection retained caller digest reference: %#v", result)
	}
}

func TestL9ProductionCredentialEnvironmentRequiresExactOriginAllowlist(t *testing.T) {
	lookups := []string{}
	lookup := func(key string) (string, bool) {
		lookups = append(lookups, key)
		switch key {
		case sandboxTemplateRegistryAuthOriginEnv:
			return "https://other.example", true
		case sandboxTemplateRegistryUsernameEnv, sandboxTemplateRegistryPasswordEnv, sandboxTemplateRegistryTokenOriginEnv:
			t.Fatalf("credential value %s read for non-allowlisted selected origin", key)
		}
		return "", false
	}
	provider, policies, err := productionSandboxTemplateRegistryAuth("https://registry.example", "registry.example", lookup)
	if err != nil {
		t.Fatalf("production auth error = %v", err)
	}
	if len(lookups) != 1 || lookups[0] != sandboxTemplateRegistryAuthOriginEnv {
		t.Fatalf("environment lookups = %#v, want allowlist only", lookups)
	}
	if policies["https://registry.example"].Origin != "https://registry.example" {
		t.Fatalf("default token policy = %#v", policies)
	}
	credential, err := provider.LookupCredential(context.Background(), registry.CredentialRequest{
		RegistryOrigin: "https://registry.example",
		TokenOrigin:    "https://registry.example",
	})
	if err != nil || credential != (registry.Credential{}) {
		t.Fatalf("anonymous exact-origin credential = %#v, %v", credential, err)
	}
}

func TestL9ProductionCredentialProviderPinsRegistryAndTokenOrigins(t *testing.T) {
	values := map[string]string{
		sandboxTemplateRegistryAuthOriginEnv:  "https://registry.example",
		sandboxTemplateRegistryUsernameEnv:    "fixture-user",
		sandboxTemplateRegistryPasswordEnv:    "fixture-password",
		sandboxTemplateRegistryTokenOriginEnv: "https://token.example",
	}
	provider, policies, err := productionSandboxTemplateRegistryAuth("https://registry.example", "registry.example", func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err != nil {
		t.Fatalf("production auth error = %v", err)
	}
	if got := policies["https://registry.example"]; got.Origin != "https://token.example" || got.Service != "registry.example" {
		t.Fatalf("token policy = %#v", got)
	}
	credential, err := provider.LookupCredential(context.Background(), registry.CredentialRequest{
		RegistryOrigin: "https://registry.example",
		TokenOrigin:    "https://token.example",
	})
	if err != nil || credential.Username != "fixture-user" || credential.Password != "fixture-password" {
		t.Fatalf("credential = %#v, %v", credential, err)
	}
	for _, request := range []registry.CredentialRequest{
		{RegistryOrigin: "https://evil.example", TokenOrigin: "https://token.example"},
		{RegistryOrigin: "https://registry.example", TokenOrigin: "https://evil.example"},
	} {
		if _, err := provider.LookupCredential(context.Background(), request); err == nil {
			t.Fatalf("credential provider accepted mismatched request %#v", request)
		}
	}
}

func TestL9ActualRunAutoFactoryPathsInjectSelectionBeforeExecutionConstruction(t *testing.T) {
	selectionFailure := errors.New("authentication_failed")
	templateDeps := sandboxTemplateSelectionDeps{
		NewWorkflow: func() (sandboxTemplateSelectionWorkflow, error) {
			return &sandboxTemplateWorkflowStub{err: selectionFailure}, nil
		},
	}
	t.Run("run", func(t *testing.T) {
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions"))
		var out bytes.Buffer
		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			Base:                   "main",
			BaseChanged:            true,
			SandboxTemplate:        "registry.example/hal/template:latest",
			SandboxTemplateChanged: true,
		}, &out, io.Discard, runSandboxDeps{
			templateSelection: templateDeps,
			defaultStore:      func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID:    func(time.Time) string { return "run-l9-selection-failure" },
			now:               func() time.Time { return time.Unix(1, 0) },
			workingDir:        func() (string, error) { return t.TempDir(), nil },
			resolveProvider:   func(string) (sandbox.Provider, error) { panic("provider constructed") },
			execute: func(context.Context, runSandboxRequest, io.Writer, io.Writer, runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
				panic("run execution constructed")
			},
		})
		if err == nil || !strings.Contains(err.Error(), "authentication_failed") {
			t.Fatalf("run error = %v", err)
		}
	})
	t.Run("auto", func(t *testing.T) {
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions"))
		var out bytes.Buffer
		err := runAutoSandboxWithWriter(context.Background(), nil, nil, t.TempDir(), autoSandboxOptions{
			Base:                   "main",
			BaseChanged:            true,
			SandboxTemplate:        "registry.example/hal/template:latest",
			SandboxTemplateChanged: true,
		}, &out, io.Discard, autoSandboxDeps{
			templateSelection: templateDeps,
			defaultStore:      func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID:    func(time.Time) string { return "auto-l9-selection-failure" },
			now:               func() time.Time { return time.Unix(1, 0) },
			resolveProvider:   func(string) (sandbox.Provider, error) { panic("provider constructed") },
			execute: func(context.Context, autoSandboxRequest, io.Writer, io.Writer, autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
				panic("auto execution constructed")
			},
		})
		if err == nil || !strings.Contains(err.Error(), "authentication_failed") {
			t.Fatalf("auto error = %v", err)
		}
	})
	t.Run("factory", func(t *testing.T) {
		store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
		if err := store.Ensure(); err != nil {
			t.Fatal(err)
		}
		policy := factory.DefaultFactoryPolicy()
		record := factory.RunRecord{RunID: "factory-l9-selection-failure", Policy: &policy}
		if err := store.SaveRun(&record); err != nil {
			t.Fatal(err)
		}
		_, err := executeFactoryRun(context.Background(), t.TempDir(), factoryRunRequest{
			BaseBranch: "main",
			Sandbox:    true,
			TemplateFlags: sandboxTemplateFlagValues{
				Sandbox:          true,
				Reference:        "registry.example/hal/template:latest",
				ReferenceChanged: true,
			},
		}, io.Discard, store, record, factoryRunDeps{
			templateSelection: templateDeps,
			now:               func() time.Time { return time.Unix(1, 0) },
			runPipeline: func(context.Context, factoryRunPipelineRequest) error {
				panic("factory pipeline constructed")
			},
			resolveProvider: func(string, string) (sandbox.Provider, error) { panic("provider constructed") },
		}, policy, "codex")
		if err == nil || !strings.Contains(err.Error(), "authentication_failed") {
			t.Fatalf("factory error = %v", err)
		}
	})
}

func TestL9ActualRunAndAutoPathsPersistExactSelectionWithoutCallerReference(t *testing.T) {
	const (
		digestValue     = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		referenceCanary = "registry.example/private-caller-canary:latest"
	)
	selected := l9CommandSelectionResult(digestValue)
	templateDeps := sandboxTemplateSelectionDeps{
		NewWorkflow: func() (sandboxTemplateSelectionWorkflow, error) {
			return &sandboxTemplateWorkflowStub{result: selected}, nil
		},
	}
	assertManifest := func(t *testing.T, manifest *sandboxexecution.Manifest, executionID, sandboxID, runtimeID string) {
		t.Helper()
		if manifest.ID != executionID || manifest.SandboxID != sandboxID ||
			manifest.Runtime == nil || manifest.Runtime.RuntimeID != runtimeID {
			t.Fatalf("manifest identity = %#v", manifest)
		}
		for name, lock := range map[string]*sandbox.SandboxTemplateLockMetadata{
			"execution": manifest.TemplateLock,
			"runtime":   manifest.Runtime.TemplateLock,
		} {
			if lock == nil || lock.TemplateReference == nil || lock.TemplateReference.DigestValue != digestValue {
				t.Fatalf("%s lock = %#v, want selected digest", name, lock)
			}
		}
		encoded, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), referenceCanary) ||
			strings.Contains(string(encoded), "fixture-password") {
			t.Fatalf("durable manifest leaked transient selection input: %s", encoded)
		}
	}
	t.Run("run", func(t *testing.T) {
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions"))
		projectDir := t.TempDir()
		target := l9CommandTarget("run-sandbox-l9", "run-runtime-l9")
		target.Runtime.TemplateLock = selectedTemplateConstructionLock(&selected)
		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			Base:                   "main",
			BaseChanged:            true,
			SandboxName:            target.Name,
			SandboxTemplate:        referenceCanary,
			SandboxTemplateChanged: true,
		}, io.Discard, io.Discard, runSandboxDeps{
			templateSelection: templateDeps,
			defaultStore:      func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID:    func(time.Time) string { return "run-execution-l9" },
			now:               runSandboxTestClock(time.Unix(1, 0), time.Unix(2, 0)),
			workingDir:        func() (string, error) { return projectDir, nil },
			repoRemote:        func(string) (string, error) { return "git@example.com:org/repo.git", nil },
			currentBranch:     func(string) (string, error) { return "feature/l9", nil },
			loadSandbox:       func(string) (*sandbox.SandboxState, error) { return target, nil },
			persistSandboxState: func(state *sandbox.SandboxState) error {
				if state.Runtime.TemplateLock == nil {
					t.Fatal("sandbox state persisted before template binding")
				}
				return nil
			},
			resolveRuntimeDriver: func(runtimeTarget sandboxruntime.Target) (sandboxruntime.Driver, error) {
				if runtimeTarget.Runtime.Metadata == nil ||
					runtimeTarget.Runtime.Metadata.TemplateLock == nil ||
					runtimeTarget.Runtime.Metadata.TemplateLock.TemplateReference == nil ||
					runtimeTarget.Runtime.Metadata.TemplateLock.TemplateReference.DigestValue != digestValue {
					t.Fatalf("run runtime constructor did not receive selected evidence: %#v", runtimeTarget.Runtime.Metadata)
				}
				return fakeRunSandboxRuntimeDriver{id: "microvm"}, nil
			},
			resolveProvider: func(string) (sandbox.Provider, error) {
				if target.Runtime.TemplateLock == nil {
					t.Fatal("run provider constructed without selected evidence")
				}
				return nil, errors.New("stop_after_binding")
			},
		})
		if err == nil || !strings.Contains(err.Error(), "stop_after_binding") {
			t.Fatalf("run error = %v, want stop_after_binding", err)
		}
		manifest, err := store.LoadManifest("run-execution-l9")
		if err != nil {
			t.Fatal(err)
		}
		assertManifest(t, manifest, "run-execution-l9", target.ID, target.Runtime.RuntimeID)
	})
	t.Run("auto", func(t *testing.T) {
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions"))
		projectDir := t.TempDir()
		target := l9CommandTarget("auto-sandbox-l9", "auto-runtime-l9")
		target.Runtime.TemplateLock = selectedTemplateConstructionLock(&selected)
		err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			Base:                   "main",
			BaseChanged:            true,
			SandboxName:            target.Name,
			SandboxTemplate:        referenceCanary,
			SandboxTemplateChanged: true,
		}, io.Discard, io.Discard, autoSandboxDeps{
			templateSelection: templateDeps,
			defaultStore:      func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID:    func(time.Time) string { return "auto-execution-l9" },
			now:               runSandboxTestClock(time.Unix(1, 0), time.Unix(2, 0)),
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return sandboxworkspace.Plan{
					Mode:        sandbox.SandboxWorkspaceModeClone,
					InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
					ProjectDir:  projectDir,
					Repository:  "git@example.com:org/repo.git",
					Branch:      "feature/l9",
					SyncRef:     "main",
				}, nil
			},
			loadSandbox: func(string) (*sandbox.SandboxState, error) { return target, nil },
			persistSandboxState: func(state *sandbox.SandboxState) error {
				if state.Runtime.TemplateLock == nil {
					t.Fatal("sandbox state persisted before template binding")
				}
				return nil
			},
			resolveRuntimeDriver: func(runtimeTarget sandboxruntime.Target) (sandboxruntime.Driver, error) {
				if runtimeTarget.Runtime.Metadata == nil ||
					runtimeTarget.Runtime.Metadata.TemplateLock == nil ||
					runtimeTarget.Runtime.Metadata.TemplateLock.TemplateReference == nil ||
					runtimeTarget.Runtime.Metadata.TemplateLock.TemplateReference.DigestValue != digestValue {
					t.Fatalf("auto runtime constructor did not receive selected evidence: %#v", runtimeTarget.Runtime.Metadata)
				}
				return fakeRunSandboxRuntimeDriver{id: "microvm"}, nil
			},
			resolveProvider: func(string) (sandbox.Provider, error) {
				if target.Runtime.TemplateLock == nil {
					t.Fatal("auto provider constructed without selected evidence")
				}
				return nil, errors.New("stop_after_binding")
			},
		})
		if err == nil || !strings.Contains(err.Error(), "stop_after_binding") {
			t.Fatalf("auto error = %v, want stop_after_binding", err)
		}
		manifest, err := store.LoadManifest("auto-execution-l9")
		if err != nil {
			t.Fatal(err)
		}
		assertManifest(t, manifest, "auto-execution-l9", target.ID, target.Runtime.RuntimeID)
	})
}

func TestL9FactoryExecutorBindsAndPersistsSelectionBeforeProviderConstruction(t *testing.T) {
	const digestValue = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	record := factory.RunRecord{
		RunID:      "factory-execution-l9",
		Status:     factory.RunStatusRunning,
		RepoRemote: "git@example.com:org/repo.git",
		BranchName: "feature/l9",
		BaseBranch: "main",
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatal(err)
	}
	target := l9CommandTarget("factory-sandbox-l9", "factory-runtime-l9")
	selected := l9CommandSelectionResult(digestValue)
	target.Runtime.TemplateLock = selectedTemplateConstructionLock(&selected)
	target.Name = "factory-sandbox-l9"
	target.Provider = "fixture"
	providerCalled := false
	err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
		ProjectDir:        t.TempDir(),
		RunRecord:         record,
		SandboxName:       target.Name,
		TemplateSelection: &selected,
		RemoteAuto:        factoryRunAutoRequest{BaseBranch: "main"},
		RemoteOutput:      io.Discard,
	}, factorySandboxExecutorDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return time.Unix(1, 0) },
		loadSandbox:  func(string) (*sandbox.SandboxState, error) { return target, nil },
		persistSandboxState: func(state *sandbox.SandboxState) error {
			if state.Runtime.TemplateLock == nil {
				t.Fatal("factory sandbox persisted before template binding")
			}
			return nil
		},
		resolveRuntimeDriver: func(runtimeTarget sandboxruntime.Target) (sandboxruntime.Driver, error) {
			if runtimeTarget.Runtime.Metadata == nil ||
				runtimeTarget.Runtime.Metadata.TemplateLock == nil ||
				runtimeTarget.Runtime.Metadata.TemplateLock.TemplateReference == nil ||
				runtimeTarget.Runtime.Metadata.TemplateLock.TemplateReference.DigestValue != digestValue {
				t.Fatalf("runtime constructor did not receive selected evidence: %#v", runtimeTarget.Runtime.Metadata)
			}
			return fakeFactorySandboxRuntimeDriver{}, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			providerCalled = true
			if target.Runtime.TemplateLock == nil {
				t.Fatal("provider constructed before template binding")
			}
			return nil, errors.New("stop_after_binding")
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error { return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "stop_after_binding") {
		t.Fatalf("factory executor error = %v", err)
	}
	if !providerCalled {
		t.Fatal("factory provider boundary was not reached")
	}
	stored, loadErr := store.LoadRun(record.RunID)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if stored.Sandbox == nil || stored.Sandbox.TemplateLock == nil ||
		stored.Sandbox.TemplateLock.TemplateReference == nil ||
		stored.Sandbox.TemplateLock.TemplateReference.DigestValue != digestValue {
		t.Fatalf("factory stored template lock = %#v", stored.Sandbox)
	}
	encoded, marshalErr := json.Marshal(stored)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if strings.Contains(string(encoded), "registry.example") || strings.Contains(string(encoded), "fixture-password") {
		t.Fatalf("factory record leaked transient selection input: %s", encoded)
	}
}

func TestL9ActualPathsRejectMissingOrTamperedTargetEvidenceBeforeConstruction(t *testing.T) {
	const digestValue = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	selected := l9CommandSelectionResultWithRuntimeImage(
		digestValue,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	templateDeps := sandboxTemplateSelectionDeps{
		NewWorkflow: func() (sandboxTemplateSelectionWorkflow, error) {
			return &sandboxTemplateWorkflowStub{result: selected}, nil
		},
	}
	targetForCase := func(t *testing.T, name, runtimeID, evidenceCase string) *sandbox.SandboxState {
		t.Helper()
		target := l9CommandTarget(name, runtimeID)
		target.Runtime.Image = selected.RuntimeImage
		switch evidenceCase {
		case "tampered":
			target.Runtime.TemplateLock = selectedTemplateConstructionLock(&selected)
			target.Runtime.TemplateLock.TemplateReference.DigestValue = strings.Repeat("f", 64)
		case "image_mismatch":
			target.Runtime.TemplateLock = selectedTemplateConstructionLock(&selected)
			target.Runtime.Image = "registry.example/hal/runtime@sha256:" + strings.Repeat("b", 64)
		}
		return target
	}
	for _, caseName := range []string{"missing", "tampered", "image_mismatch"} {
		t.Run("run/"+caseName, func(t *testing.T) {
			projectDir := t.TempDir()
			target := targetForCase(t, "run-"+caseName, "run-runtime-"+caseName, caseName)
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions"))
			err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
				Base:                   "main",
				BaseChanged:            true,
				SandboxName:            target.Name,
				SandboxTemplate:        "registry.example/hal/template:latest",
				SandboxTemplateChanged: true,
			}, io.Discard, io.Discard, runSandboxDeps{
				templateSelection: templateDeps,
				defaultStore: func() (sandboxexecution.Store, error) {
					return store, nil
				},
				newExecutionID: func(time.Time) string { return "run-" + caseName },
				now:            func() time.Time { return time.Unix(1, 0) },
				workingDir:     func() (string, error) { return projectDir, nil },
				repoRemote:     func(string) (string, error) { return "git@example.com:org/repo.git", nil },
				currentBranch:  func(string) (string, error) { return "feature/l9", nil },
				loadSandbox:    func(string) (*sandbox.SandboxState, error) { return target, nil },
				persistSandboxState: func(*sandbox.SandboxState) error {
					panic("tampered target persisted")
				},
				resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
					panic("runtime constructed for tampered target")
				},
				resolveProvider: func(string) (sandbox.Provider, error) {
					panic("provider constructed for tampered target")
				},
			})
			if err == nil || !strings.Contains(err.Error(), "selection_rejected") {
				t.Fatalf("run error = %v, want selection_rejected", err)
			}
			manifest, loadErr := store.LoadManifest("run-" + caseName)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if manifest.TemplateLock != nil || (manifest.Runtime != nil && manifest.Runtime.TemplateLock != nil) {
				t.Fatalf("run persisted rejected target evidence: %#v", manifest)
			}
		})
		t.Run("auto/"+caseName, func(t *testing.T) {
			projectDir := t.TempDir()
			target := targetForCase(t, "auto-"+caseName, "auto-runtime-"+caseName, caseName)
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions"))
			err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
				Base:                   "main",
				BaseChanged:            true,
				SandboxName:            target.Name,
				SandboxTemplate:        "registry.example/hal/template:latest",
				SandboxTemplateChanged: true,
			}, io.Discard, io.Discard, autoSandboxDeps{
				templateSelection: templateDeps,
				defaultStore: func() (sandboxexecution.Store, error) {
					return store, nil
				},
				newExecutionID: func(time.Time) string { return "auto-" + caseName },
				now:            func() time.Time { return time.Unix(1, 0) },
				planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
					return sandboxworkspace.Plan{
						Mode:        sandbox.SandboxWorkspaceModeClone,
						InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
						ProjectDir:  projectDir,
						Repository:  "git@example.com:org/repo.git",
						Branch:      "feature/l9",
						SyncRef:     "main",
					}, nil
				},
				loadSandbox: func(string) (*sandbox.SandboxState, error) { return target, nil },
				persistSandboxState: func(*sandbox.SandboxState) error {
					panic("tampered target persisted")
				},
				resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
					panic("runtime constructed for tampered target")
				},
				resolveProvider: func(string) (sandbox.Provider, error) {
					panic("provider constructed for tampered target")
				},
			})
			if err == nil || !strings.Contains(err.Error(), "selection_rejected") {
				t.Fatalf("auto error = %v, want selection_rejected", err)
			}
			manifest, loadErr := store.LoadManifest("auto-" + caseName)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if manifest.TemplateLock != nil || (manifest.Runtime != nil && manifest.Runtime.TemplateLock != nil) {
				t.Fatalf("auto persisted rejected target evidence: %#v", manifest)
			}
		})
		t.Run("factory/"+caseName, func(t *testing.T) {
			store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
			record := factory.RunRecord{
				RunID:      "factory-" + caseName,
				Status:     factory.RunStatusRunning,
				RepoRemote: "git@example.com:org/repo.git",
				BranchName: "feature/l9",
				BaseBranch: "main",
			}
			if err := store.SaveRun(&record); err != nil {
				t.Fatal(err)
			}
			target := targetForCase(t, "factory-"+caseName, "factory-runtime-"+caseName, caseName)
			target.Provider = "fixture"
			err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
				ProjectDir:        t.TempDir(),
				RunRecord:         record,
				SandboxName:       target.Name,
				TemplateSelection: &selected,
				RemoteAuto:        factoryRunAutoRequest{BaseBranch: "main"},
				RemoteOutput:      io.Discard,
			}, factorySandboxExecutorDeps{
				defaultStore: func() (factory.Store, error) { return store, nil },
				now:          func() time.Time { return time.Unix(1, 0) },
				loadSandbox:  func(string) (*sandbox.SandboxState, error) { return target, nil },
				persistSandboxState: func(*sandbox.SandboxState) error {
					panic("tampered target persisted")
				},
				resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
					panic("runtime constructed for tampered target")
				},
				resolveProvider: func(string) (sandbox.Provider, error) {
					panic("provider constructed for tampered target")
				},
				cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
					panic("cleanup constructed for tampered target")
				},
			})
			if err == nil || !strings.Contains(err.Error(), "selection_rejected") {
				t.Fatalf("factory error = %v, want selection_rejected", err)
			}
			stored, loadErr := store.LoadRun(record.RunID)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if stored.Sandbox != nil && stored.Sandbox.TemplateLock != nil {
				t.Fatalf("factory persisted rejected target evidence: %#v", stored.Sandbox)
			}
		})
	}
}

func TestL9ActualPathsPassSelectionEvidenceIntoProvisioning(t *testing.T) {
	const digestValue = "abababababababababababababababababababababababababababababababab"
	selected := l9CommandSelectionResultWithRuntimeImage(
		digestValue,
		"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
	)
	templateDeps := sandboxTemplateSelectionDeps{
		NewWorkflow: func() (sandboxTemplateSelectionWorkflow, error) {
			return &sandboxTemplateWorkflowStub{result: selected}, nil
		},
	}
	newProvision := func(t *testing.T, called *bool) func(context.Context, factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
		t.Helper()
		return func(_ context.Context, req factorySandboxProvisionRequest) (*sandbox.SandboxState, error) {
			*called = true
			if req.TemplateRuntimeDriver != "microvm" ||
				req.TemplateIsolationLevel != "vm" ||
				req.TemplateRuntimeImage != selected.RuntimeImage ||
				req.TemplateLock == nil ||
				req.TemplateLock.TemplateReference == nil ||
				req.TemplateLock.TemplateReference.DigestValue != digestValue {
				t.Fatalf("provision request missing selected evidence: %#v", req)
			}
			target := l9CommandTarget(req.Name, req.Name+"-runtime")
			target.Provider = "fixture"
			target.Runtime.Driver = req.TemplateRuntimeDriver
			target.Runtime.IsolationLevel = req.TemplateIsolationLevel
			target.Runtime.Image = req.TemplateRuntimeImage
			target.Runtime.TemplateLock = sandbox.SanitizeSandboxTemplateLockMetadata(req.TemplateLock)
			return target, nil
		}
	}
	assertRuntime := func(t *testing.T, target sandboxruntime.Target) {
		t.Helper()
		if target.Runtime.Metadata == nil ||
			target.Runtime.Metadata.TemplateLock == nil ||
			target.Runtime.Metadata.TemplateLock.TemplateReference == nil ||
			target.Runtime.Metadata.TemplateLock.TemplateReference.DigestValue != digestValue {
			t.Fatalf("runtime constructor missing selected evidence: %#v", target.Runtime.Metadata)
		}
		if target.Runtime.Image != selected.RuntimeImage {
			t.Fatalf("runtime constructor image = %q, want selected digest-pinned image", target.Runtime.Image)
		}
	}
	t.Run("run", func(t *testing.T) {
		projectDir := t.TempDir()
		provisioned := false
		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			Base:                   "main",
			BaseChanged:            true,
			SandboxName:            "run-provision-l9",
			SandboxTemplate:        "registry.example/hal/template:latest",
			SandboxTemplateChanged: true,
		}, io.Discard, io.Discard, runSandboxDeps{
			templateSelection: templateDeps,
			defaultStore: func() (sandboxexecution.Store, error) {
				return sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions")), nil
			},
			newExecutionID: func(time.Time) string { return "run-provision-l9" },
			now:            func() time.Time { return time.Unix(1, 0) },
			workingDir:     func() (string, error) { return projectDir, nil },
			repoRemote:     func(string) (string, error) { return "git@example.com:org/repo.git", nil },
			currentBranch:  func(string) (string, error) { return "feature/l9", nil },
			loadSandbox:    func(string) (*sandbox.SandboxState, error) { return nil, fs.ErrNotExist },
			provision:      newProvision(t, &provisioned),
			persistSandboxState: func(state *sandbox.SandboxState) error {
				if state.Runtime.TemplateLock == nil {
					t.Fatal("provisioned run target persisted without evidence")
				}
				return nil
			},
			resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
				assertRuntime(t, target)
				return fakeRunSandboxRuntimeDriver{id: "microvm"}, nil
			},
			resolveProvider: func(string) (sandbox.Provider, error) {
				return nil, errors.New("stop_after_binding")
			},
		})
		if err == nil || !strings.Contains(err.Error(), "stop_after_binding") || !provisioned {
			t.Fatalf("run error = %v, provisioned=%v", err, provisioned)
		}
	})
	t.Run("auto", func(t *testing.T) {
		projectDir := t.TempDir()
		provisioned := false
		err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			Base:                   "main",
			BaseChanged:            true,
			SandboxName:            "auto-provision-l9",
			SandboxTemplate:        "registry.example/hal/template:latest",
			SandboxTemplateChanged: true,
		}, io.Discard, io.Discard, autoSandboxDeps{
			templateSelection: templateDeps,
			defaultStore: func() (sandboxexecution.Store, error) {
				return sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions")), nil
			},
			newExecutionID: func(time.Time) string { return "auto-provision-l9" },
			now:            func() time.Time { return time.Unix(1, 0) },
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return sandboxworkspace.Plan{
					Mode:        sandbox.SandboxWorkspaceModeClone,
					InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
					ProjectDir:  projectDir,
					Repository:  "git@example.com:org/repo.git",
					Branch:      "feature/l9",
					SyncRef:     "main",
				}, nil
			},
			loadSandbox: func(string) (*sandbox.SandboxState, error) { return nil, fs.ErrNotExist },
			provision:   newProvision(t, &provisioned),
			persistSandboxState: func(state *sandbox.SandboxState) error {
				if state.Runtime.TemplateLock == nil {
					t.Fatal("provisioned auto target persisted without evidence")
				}
				return nil
			},
			resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
				assertRuntime(t, target)
				return fakeRunSandboxRuntimeDriver{id: "microvm"}, nil
			},
			resolveProvider: func(string) (sandbox.Provider, error) {
				return nil, errors.New("stop_after_binding")
			},
		})
		if err == nil || !strings.Contains(err.Error(), "stop_after_binding") || !provisioned {
			t.Fatalf("auto error = %v, provisioned=%v", err, provisioned)
		}
	})
	t.Run("factory", func(t *testing.T) {
		store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
		record := factory.RunRecord{
			RunID:      "factory-provision-l9",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@example.com:org/repo.git",
			BranchName: "feature/l9",
			BaseBranch: "main",
		}
		if err := store.SaveRun(&record); err != nil {
			t.Fatal(err)
		}
		provisioned := false
		err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
			ProjectDir:        t.TempDir(),
			RunRecord:         record,
			SandboxName:       "factory-provision-l9",
			TemplateSelection: &selected,
			RemoteAuto:        factoryRunAutoRequest{BaseBranch: "main"},
			RemoteOutput:      io.Discard,
		}, factorySandboxExecutorDeps{
			defaultStore: func() (factory.Store, error) { return store, nil },
			now:          func() time.Time { return time.Unix(1, 0) },
			loadSandbox:  func(string) (*sandbox.SandboxState, error) { return nil, fs.ErrNotExist },
			provision:    newProvision(t, &provisioned),
			persistSandboxState: func(state *sandbox.SandboxState) error {
				if state.Runtime.TemplateLock == nil {
					t.Fatal("provisioned factory target persisted without evidence")
				}
				return nil
			},
			resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
				assertRuntime(t, target)
				return fakeFactorySandboxRuntimeDriver{id: "microvm"}, nil
			},
			resolveProvider: func(string) (sandbox.Provider, error) {
				return nil, errors.New("stop_after_binding")
			},
			cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error { return nil },
		})
		if err == nil || !strings.Contains(err.Error(), "stop_after_binding") || !provisioned {
			t.Fatalf("factory error = %v, provisioned=%v", err, provisioned)
		}
	})
}

func TestL9ScheduledWorkerTargetCarriesSelectedTemplateConstruction(t *testing.T) {
	const (
		templateDigest = "8989898989898989898989898989898989898989898989898989898989898989"
		imageDigest    = "9090909090909090909090909090909090909090909090909090909090909090"
	)
	selected := l9CommandSelectionResultWithRuntimeImage(templateDigest, imageDigest)
	selected.RuntimeDriver = sandboxruntime.DriverRootlessPodman
	selected.IsolationLevel = sandbox.SandboxIsolationLevelContainer
	selected.Template.Runtime.Driver = sandboxruntime.DriverRootlessPodman
	selected.Template.Runtime.IsolationLevel = sandbox.SandboxIsolationLevelContainer
	lock := selectedTemplateConstructionLock(&selected)
	host := autoSandboxSchedulerLeaseHost("worker-l9-selected", "worker l9 selected")

	for _, purpose := range []string{
		sandbox.SandboxLeasePurposeRun,
		sandbox.SandboxLeasePurposeAuto,
		sandbox.SandboxLeasePurposeFactory,
	} {
		t.Run(purpose, func(t *testing.T) {
			target, err := resolveSandboxCommandExecutionTarget(
				context.Background(),
				sandboxCommandTargetRequest{
					Purpose: purpose, SandboxHostID: host.ID, SandboxRuntime: sandboxruntime.DriverRootlessPodman,
					Branch: "feature/l9", TemplateRuntimeDriver: selected.RuntimeDriver,
					TemplateIsolationLevel: selected.IsolationLevel, TemplateRuntimeImage: selected.RuntimeImage,
					TemplateLock: lock,
				},
				sandboxCommandTargetDeps{listHosts: func() ([]*sandbox.SandboxHost, error) {
					return []*sandbox.SandboxHost{host}, nil
				}},
				sandboxCommandScheduledTargetRequest{
					Purpose: purpose, SandboxHostID: host.ID, SandboxRuntime: sandboxruntime.DriverRootlessPodman,
					Branch: "feature/l9", RunID: "l9-scheduled-" + purpose,
				},
				sandboxCommandScheduledTargetDeps{
					listHosts:  func() ([]*sandbox.SandboxHost, error) { return []*sandbox.SandboxHost{host}, nil },
					listLeases: func() ([]*sandbox.SandboxLease, error) { return nil, nil },
					now:        func() time.Time { return time.Unix(1, 0) },
					acquireLease: func(req sandbox.SandboxLeaseAcquireRequest, ttl time.Duration) (*sandbox.SandboxLease, error) {
						return &sandbox.SandboxLease{
							ID: req.ID, ResourceKey: req.ResourceKey, Purpose: req.Purpose, RunID: req.RunID,
							Status: sandbox.SandboxLeaseStatusActive, AcquiredAt: time.Unix(1, 0), ExpiresAt: time.Unix(1, 0).Add(ttl),
						}, nil
					},
				},
			)
			if err != nil {
				t.Fatalf("resolve scheduled %s target: %v", purpose, err)
			}
			if target == nil || target.Runtime == nil ||
				target.Runtime.Driver != selected.RuntimeDriver ||
				target.Runtime.IsolationLevel != selected.IsolationLevel ||
				target.Runtime.Image != selected.RuntimeImage ||
				target.Runtime.TemplateLock == nil ||
				target.Runtime.TemplateLock.RuntimeImage == nil ||
				target.Runtime.TemplateLock.RuntimeImage.DigestValue != imageDigest {
				t.Fatalf("scheduled %s target lost selected construction: %#v", purpose, target)
			}
		})
	}
}

func TestL9ActualPathsRejectRuntimeReportedImageMismatchBeforeProviderAndProjection(t *testing.T) {
	const (
		templateDigest = "1212121212121212121212121212121212121212121212121212121212121212"
		imageDigest    = "3434343434343434343434343434343434343434343434343434343434343434"
	)
	selected := l9CommandSelectionResultWithRuntimeImage(templateDigest, imageDigest)
	templateDeps := sandboxTemplateSelectionDeps{
		NewWorkflow: func() (sandboxTemplateSelectionWorkflow, error) {
			return &sandboxTemplateWorkflowStub{result: selected}, nil
		},
	}
	newStoppedTarget := func(name string) *sandbox.SandboxState {
		target := l9CommandTarget(name, name+"-runtime")
		target.Status = sandbox.StatusStopped
		target.Provider = "fixture"
		target.Runtime.Image = selected.RuntimeImage
		target.Runtime.TemplateLock = selectedTemplateConstructionLock(&selected)
		return target
	}
	mismatchedRuntimeTarget := func(target sandboxruntime.Target) *sandboxruntime.Target {
		target.Status = sandbox.StatusRunning
		target.Runtime.Image = "registry.example/hal/runtime@sha256:" + strings.Repeat("5", 64)
		return &target
	}
	t.Run("run", func(t *testing.T) {
		projectDir := t.TempDir()
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions"))
		target := newStoppedTarget("run-runtime-image-mismatch")
		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			Base:                   "main",
			BaseChanged:            true,
			SandboxName:            target.Name,
			SandboxTemplate:        "registry.example/hal/template:latest",
			SandboxTemplateChanged: true,
		}, io.Discard, io.Discard, runSandboxDeps{
			templateSelection: templateDeps,
			defaultStore:      func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID:    func(time.Time) string { return "run-runtime-image-mismatch" },
			now:               func() time.Time { return time.Unix(1, 0) },
			workingDir:        func() (string, error) { return projectDir, nil },
			repoRemote:        func(string) (string, error) { return "git@example.com:org/repo.git", nil },
			currentBranch:     func(string) (string, error) { return "feature/l9", nil },
			loadSandbox:       func(string) (*sandbox.SandboxState, error) { return target, nil },
			resolveRuntimeDriver: func(runtimeTarget sandboxruntime.Target) (sandboxruntime.Driver, error) {
				if runtimeTarget.Runtime.Image != selected.RuntimeImage {
					t.Fatalf("run runtime constructor image = %q", runtimeTarget.Runtime.Image)
				}
				return fakeRunSandboxRuntimeDriver{
					id: "microvm",
					start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
						return mismatchedRuntimeTarget(req.Target), nil
					},
				}, nil
			},
			resolveProvider:     func(string) (sandbox.Provider, error) { panic("provider constructed after image mismatch") },
			persistSandboxState: func(*sandbox.SandboxState) error { panic("image mismatch persisted") },
		})
		if err == nil || !strings.Contains(err.Error(), "selection_rejected") {
			t.Fatalf("run error = %v, want selection_rejected", err)
		}
		manifest, loadErr := store.LoadManifest("run-runtime-image-mismatch")
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if manifest.TemplateLock != nil || manifest.Runtime != nil {
			t.Fatalf("run projected trust for mismatched runtime image: %#v", manifest)
		}
	})
	t.Run("auto", func(t *testing.T) {
		projectDir := t.TempDir()
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions"))
		target := newStoppedTarget("auto-runtime-image-mismatch")
		err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			Base:                   "main",
			BaseChanged:            true,
			SandboxName:            target.Name,
			SandboxTemplate:        "registry.example/hal/template:latest",
			SandboxTemplateChanged: true,
		}, io.Discard, io.Discard, autoSandboxDeps{
			templateSelection: templateDeps,
			defaultStore:      func() (sandboxexecution.Store, error) { return store, nil },
			newExecutionID:    func(time.Time) string { return "auto-runtime-image-mismatch" },
			now:               func() time.Time { return time.Unix(1, 0) },
			planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
				return sandboxworkspace.Plan{
					Mode:        sandbox.SandboxWorkspaceModeClone,
					InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
					ProjectDir:  projectDir,
					Repository:  "git@example.com:org/repo.git",
					Branch:      "feature/l9",
					SyncRef:     "main",
				}, nil
			},
			loadSandbox: func(string) (*sandbox.SandboxState, error) { return target, nil },
			resolveRuntimeDriver: func(runtimeTarget sandboxruntime.Target) (sandboxruntime.Driver, error) {
				if runtimeTarget.Runtime.Image != selected.RuntimeImage {
					t.Fatalf("auto runtime constructor image = %q", runtimeTarget.Runtime.Image)
				}
				return fakeRunSandboxRuntimeDriver{
					id: "microvm",
					start: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
						return mismatchedRuntimeTarget(req.Target), nil
					},
				}, nil
			},
			resolveProvider:     func(string) (sandbox.Provider, error) { panic("provider constructed after image mismatch") },
			persistSandboxState: func(*sandbox.SandboxState) error { panic("image mismatch persisted") },
		})
		if err == nil || !strings.Contains(err.Error(), "selection_rejected") {
			t.Fatalf("auto error = %v, want selection_rejected", err)
		}
		manifest, loadErr := store.LoadManifest("auto-runtime-image-mismatch")
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if manifest.TemplateLock != nil || manifest.Runtime != nil {
			t.Fatalf("auto projected trust for mismatched runtime image: %#v", manifest)
		}
	})
	t.Run("factory", func(t *testing.T) {
		store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
		record := factory.RunRecord{
			RunID:      "factory-runtime-image-mismatch",
			Status:     factory.RunStatusRunning,
			RepoRemote: "git@example.com:org/repo.git",
			BranchName: "feature/l9",
			BaseBranch: "main",
		}
		if err := store.SaveRun(&record); err != nil {
			t.Fatal(err)
		}
		target := newStoppedTarget("factory-runtime-image-mismatch")
		err := runFactorySandboxExecutorWithDeps(context.Background(), factorySandboxExecutorRequest{
			ProjectDir:        t.TempDir(),
			RunRecord:         record,
			SandboxName:       target.Name,
			TemplateSelection: &selected,
			RemoteAuto:        factoryRunAutoRequest{BaseBranch: "main"},
			RemoteOutput:      io.Discard,
		}, factorySandboxExecutorDeps{
			defaultStore: func() (factory.Store, error) { return store, nil },
			now:          func() time.Time { return time.Unix(1, 0) },
			loadSandbox:  func(string) (*sandbox.SandboxState, error) { return target, nil },
			resolveRuntimeDriver: func(runtimeTarget sandboxruntime.Target) (sandboxruntime.Driver, error) {
				if runtimeTarget.Runtime.Image != selected.RuntimeImage {
					t.Fatalf("factory runtime constructor image = %q", runtimeTarget.Runtime.Image)
				}
				return fakeFactorySandboxRuntimeDriver{
					id: "microvm",
					startFn: func(_ context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
						return mismatchedRuntimeTarget(req.Target), nil
					},
				}, nil
			},
			resolveProvider:     func(string) (sandbox.Provider, error) { panic("provider constructed after image mismatch") },
			persistSandboxState: func(*sandbox.SandboxState) error { panic("image mismatch persisted") },
			cleanupSandbox:      func(context.Context, factorySandboxCleanupRequest) error { return nil },
		})
		if err == nil || !strings.Contains(err.Error(), "selection_rejected") {
			t.Fatalf("factory error = %v, want selection_rejected", err)
		}
		stored, loadErr := store.LoadRun(record.RunID)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		if stored.Sandbox != nil && stored.Sandbox.TemplateLock != nil {
			t.Fatalf("factory projected trust for mismatched runtime image: %#v", stored.Sandbox)
		}
	})
}

func TestL9ActualDryRunPathsDoNotConstructSelectionDependencies(t *testing.T) {
	referenceCanary := "registry.example/private-preview-canary@sha256:" + strings.Repeat("6", 64)
	panicDeps := sandboxTemplateSelectionDeps{
		ReadCredentialEnvironment: func(string) (string, bool) { panic("credential environment read") },
		NewCache:                  func() (registryCache, error) { panic("cache constructed") },
		NewHTTPClient:             func() (registryHTTPClient, error) { panic("HTTP client constructed") },
		NewWorkflow:               func() (sandboxTemplateSelectionWorkflow, error) { panic("workflow constructed") },
	}
	projectDir := t.TempDir()
	runDeps := forbiddenRunSandboxDryRunDeps(projectDir)
	runDeps.templateSelection = panicDeps
	var runOut bytes.Buffer
	if err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		DryRun:                 true,
		DryRunChanged:          true,
		Base:                   "main",
		BaseChanged:            true,
		SandboxTemplate:        referenceCanary,
		SandboxTemplateChanged: true,
	}, &runOut, io.Discard, runDeps); err != nil {
		t.Fatalf("run dry-run error = %v", err)
	}
	if !strings.Contains(runOut.String(), "Template intent: sourceKind=oci_artifact, trustMode=strict, requested=true, resolved=false, active=false") ||
		!strings.Contains(runOut.String(), "template_acquisition") {
		t.Fatalf("run dry-run template intent = %q", runOut.String())
	}
	if strings.Contains(runOut.String(), referenceCanary) || strings.Contains(runOut.String(), "registry.example") {
		t.Fatalf("run dry-run leaked caller reference: %q", runOut.String())
	}
	autoDeps := forbiddenAutoSandboxDryRunDeps()
	autoDeps.templateSelection = panicDeps
	var autoOut bytes.Buffer
	if err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		DryRun:                 true,
		DryRunChanged:          true,
		JSON:                   true,
		JSONChanged:            true,
		Base:                   "main",
		BaseChanged:            true,
		SandboxTemplate:        referenceCanary,
		SandboxTemplateChanged: true,
	}, &autoOut, io.Discard, autoDeps); err != nil {
		t.Fatalf("auto dry-run error = %v", err)
	}
	var envelope struct {
		SandboxPreview sandboxDryRunPreview `json:"sandboxPreview"`
	}
	if err := json.Unmarshal(autoOut.Bytes(), &envelope); err != nil {
		t.Fatalf("decode auto dry-run preview: %v\n%s", err, autoOut.String())
	}
	preview := envelope.SandboxPreview
	if preview.Template == nil ||
		preview.Template.SourceKind != "oci_artifact" ||
		preview.Template.TrustMode != "strict" ||
		!preview.Template.Requested ||
		preview.Template.Resolved ||
		preview.Template.Active {
		t.Fatalf("auto dry-run template intent = %#v", preview.Template)
	}
	if strings.Contains(autoOut.String(), referenceCanary) || strings.Contains(autoOut.String(), "registry.example") {
		t.Fatalf("auto dry-run leaked caller reference: %q", autoOut.String())
	}

	const malformedCanary = "registry.example/private/../credential-canary:latest"
	var invalidOut bytes.Buffer
	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		DryRun:                 true,
		DryRunChanged:          true,
		JSON:                   true,
		JSONChanged:            true,
		Base:                   "main",
		BaseChanged:            true,
		SandboxTemplate:        malformedCanary,
		SandboxTemplateChanged: true,
	}, &invalidOut, io.Discard, runDeps)
	if err == nil || !strings.Contains(err.Error(), "exit code 2") {
		t.Fatalf("invalid run dry-run error = %v, want validation exit", err)
	}
	if !strings.Contains(invalidOut.String(), string(registry.ErrorCodeInvalidReference)) ||
		strings.Contains(invalidOut.String(), malformedCanary) ||
		strings.Contains(invalidOut.String(), "credential-canary") {
		t.Fatalf("invalid dry-run output is not sanitized: %q", invalidOut.String())
	}
}

func l9CommandSelectionResult(digestValue string) selection.Result {
	digest := &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     digestValue,
	}
	return selection.Result{
		ManifestDigest: digest,
		RuntimeDriver:  "microvm",
		IsolationLevel: "vm",
		Template: sandboxtemplate.Template{
			Metadata: sandboxtemplate.TemplateMetadata{
				Reference: &sandboxtemplate.ImmutableRef{
					Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
					Digest: digest,
				},
			},
			Runtime: &sandboxtemplate.RuntimeRequirements{
				Driver:         "microvm",
				IsolationLevel: "vm",
			},
		},
		Lock: acquisition.TemplateLock{
			SourceKind:    acquisition.SourceKindOCIArtifact,
			ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
			Status:        acquisition.LockStatusLocked,
			References: []acquisition.ReferenceLock{{
				Field:  "metadata.reference",
				Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
				Status: acquisition.LockStatusLocked,
				Digest: digest,
			}},
		},
		Trust: acquisition.TrustPolicyResult{
			Mode:     acquisition.TrustPolicyModeStrict,
			Decision: acquisition.TrustPolicyDecisionTrusted,
		},
		RuntimeMetadata: &sandboxruntime.RuntimeTemplateLockMetadata{
			TemplateReference: &sandboxruntime.RuntimeTemplateLockEntryMetadata{
				SourceKind:      "template_reference",
				ReferenceKind:   "oci_artifact",
				Status:          "locked",
				DigestAlgorithm: "sha256",
				DigestValue:     digestValue,
			},
			TrustPolicy: &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{
				Mode:            "strict",
				Decision:        "trusted",
				SourceKind:      "oci_artifact",
				ReferenceKind:   "oci_artifact",
				Status:          "locked",
				DigestAlgorithm: "sha256",
				DigestValue:     digestValue,
			},
		},
	}
}

func l9CommandSelectionResultWithRuntimeImage(templateDigest, imageDigest string) selection.Result {
	result := l9CommandSelectionResult(templateDigest)
	const imageReference = "registry.example/hal/runtime"
	digest := &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     imageDigest,
	}
	result.RuntimeImage = imageReference + "@sha256:" + imageDigest
	result.Template.Runtime.Image = &sandboxtemplate.ImmutableRef{
		Kind:   sandboxtemplate.ReferenceKindOCIImage,
		Ref:    imageReference,
		Digest: digest,
	}
	result.Lock.References = append(result.Lock.References, acquisition.ReferenceLock{
		Field:  "runtime.image",
		Kind:   sandboxtemplate.ReferenceKindOCIImage,
		Status: acquisition.LockStatusLocked,
		Digest: digest,
	})
	result.RuntimeMetadata.RuntimeImage = &sandboxruntime.RuntimeTemplateLockEntryMetadata{
		SourceKind:      "runtime_image",
		ReferenceKind:   "oci_image",
		Status:          "locked",
		DigestAlgorithm: "sha256",
		DigestValue:     imageDigest,
	}
	return result
}

func l9CommandTarget(sandboxID, runtimeID string) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:     sandboxID,
		Name:   sandboxID,
		Status: sandbox.StatusRunning,
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         "microvm",
			IsolationLevel: "vm",
			RuntimeID:      runtimeID,
		},
	}
}

func TestL9EverySelectionFailurePrecedesProviderWorkerAndRuntimeConstruction(t *testing.T) {
	failures := []error{
		errors.New("invalid_reference"),
		errors.New("registry_unavailable"),
		errors.New("authentication_failed"),
		errors.New("request_timeout"),
		errors.New("manifest_digest_mismatch"),
		errors.New("tag_mutated"),
		errors.New("layer_digest_mismatch"),
		errors.New("cache_invalid"),
		errors.New("selection_rejected"),
	}
	for _, command := range []string{"run", "auto", "factory"} {
		for _, failure := range failures {
			t.Run(command+"/"+failure.Error(), func(t *testing.T) {
				workflow := &sandboxTemplateWorkflowStub{err: failure}
				_, err := executeSandboxTemplateSelectionBeforeConstruction(context.Background(), sandboxTemplateConstructionRequest{
					Command: command,
					Selection: sandboxTemplateSelectionRequest{
						Command: command,
						Flags: sandboxTemplateFlagValues{
							Sandbox:          true,
							Reference:        "registry.example/hal/template:latest",
							ReferenceChanged: true,
						},
					},
				}, sandboxTemplateConstructionDeps{
					Selection: sandboxTemplateSelectionDeps{
						NewWorkflow: func() (sandboxTemplateSelectionWorkflow, error) { return workflow, nil },
					},
					ResolveTarget:     func() { panic("target resolution after selection failure") },
					ConstructProvider: func() { panic("provider construction after selection failure") },
					ConstructWorker:   func() { panic("worker construction after selection failure") },
					ConstructRuntime:  func() { panic("runtime construction after selection failure") },
				})
				if err == nil {
					t.Fatal("error = nil")
				}
			})
		}
	}
}

func TestL9TemplateRuntimeConflictFailsBeforeConstruction(t *testing.T) {
	workflow := &sandboxTemplateWorkflowStub{result: selection.Result{RuntimeDriver: "microvm"}}
	_, err := executeSandboxTemplateSelectionBeforeConstruction(context.Background(), sandboxTemplateConstructionRequest{
		Command:          "run",
		RequestedRuntime: "rootless_podman",
		Selection: sandboxTemplateSelectionRequest{
			Command: "run",
			Flags: sandboxTemplateFlagValues{
				Sandbox:          true,
				Reference:        "registry.example/hal/template:latest",
				ReferenceChanged: true,
			},
		},
	}, sandboxTemplateConstructionDeps{
		Selection: sandboxTemplateSelectionDeps{
			NewWorkflow: func() (sandboxTemplateSelectionWorkflow, error) { return workflow, nil },
		},
		ResolveTarget:     func() { panic("target resolution after runtime conflict") },
		ConstructProvider: func() { panic("provider construction after runtime conflict") },
		ConstructWorker:   func() { panic("worker construction after runtime conflict") },
		ConstructRuntime:  func() { panic("runtime construction after runtime conflict") },
	})
	if err == nil || !strings.Contains(err.Error(), "selection_rejected") {
		t.Fatalf("error = %v, want selection_rejected", err)
	}
}

func TestL9CommandWiringCallsSelectionBeforeTargetAndConstructors(t *testing.T) {
	files := map[string][]string{
		"run":     {"run_sandbox.go"},
		"auto":    {"auto_sandbox.go"},
		"factory": {"factory.go", "factory_sandbox_executor.go"},
	}
	for command, commandFiles := range files {
		var text string
		for _, file := range commandFiles {
			content, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			text += string(content)
		}
		selectAt := strings.Index(text, "executeSandboxTemplateSelectionBeforeConstruction")
		if selectAt < 0 {
			t.Fatalf("%s missing shared L9 selection boundary", command)
		}
		for _, later := range []string{"resolveProvider", "resolveWorkerRuntime", "resolveRuntimeDriver"} {
			at := strings.Index(text[selectAt:], later)
			if at < 0 {
				t.Fatalf("%s does not prove %s occurs after selection", command, later)
			}
		}
	}
}

func TestL9ExactManifestDigestPropagatesIntoExecutionSandboxAndRuntimeBindings(t *testing.T) {
	digest := &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     strings.Repeat("a", 64),
	}
	runtimeLock := &sandboxruntime.RuntimeTemplateLockMetadata{
		TemplateReference: &sandboxruntime.RuntimeTemplateLockEntryMetadata{
			SourceKind:      "template_reference",
			ReferenceKind:   "oci_artifact",
			DigestAlgorithm: "sha256",
			DigestValue:     digest.Value,
			Status:          "locked",
		},
		TrustPolicy: &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{
			Mode:            "strict",
			Decision:        "trusted",
			SourceKind:      "oci_artifact",
			ReferenceKind:   "oci_artifact",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     digest.Value,
		},
	}
	workflow := &sandboxTemplateWorkflowStub{result: selection.Result{
		ManifestDigest:  digest,
		RuntimeDriver:   "microvm",
		IsolationLevel:  "vm",
		RuntimeMetadata: runtimeLock,
		Template: sandboxtemplate.Template{
			Metadata: sandboxtemplate.TemplateMetadata{
				Reference: &sandboxtemplate.ImmutableRef{
					Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
					Digest: digest,
				},
			},
			Runtime: &sandboxtemplate.RuntimeRequirements{
				Driver:         "microvm",
				IsolationLevel: "vm",
			},
		},
		Lock: acquisition.TemplateLock{
			SourceKind:    acquisition.SourceKindOCIArtifact,
			ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
			Status:        acquisition.LockStatusLocked,
			References: []acquisition.ReferenceLock{{
				Field:  "metadata.reference",
				Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
				Status: acquisition.LockStatusLocked,
				Digest: digest,
			}},
		},
		Trust: acquisition.TrustPolicyResult{
			Mode:     acquisition.TrustPolicyModeStrict,
			Decision: acquisition.TrustPolicyDecisionTrusted,
		},
	}}
	result, err := executeSandboxTemplateSelectionBeforeConstruction(context.Background(), sandboxTemplateConstructionRequest{
		Command:          "run",
		ExecutionID:      "run-l9",
		SandboxID:        "sandbox-l9",
		RuntimeID:        "runtime-l9",
		RequestedRuntime: "microvm",
		Selection: sandboxTemplateSelectionRequest{
			Command: "run",
			Flags: sandboxTemplateFlagValues{
				Sandbox:          true,
				Reference:        "registry.example/hal/template:latest",
				ReferenceChanged: true,
			},
		},
	}, sandboxTemplateConstructionDeps{
		Selection: sandboxTemplateSelectionDeps{
			NewWorkflow: func() (sandboxTemplateSelectionWorkflow, error) { return workflow, nil },
		},
	})
	if err != nil {
		t.Fatalf("execute selection error = %v", err)
	}
	for name, lock := range map[string]*sandboxruntime.RuntimeTemplateLockMetadata{
		"execution": result.ExecutionTemplateLock,
		"sandbox":   result.SandboxTemplateLock,
		"runtime":   result.RuntimeTemplateLock,
	} {
		if lock == nil || lock.TemplateReference == nil || lock.TemplateReference.DigestValue != digest.Value {
			t.Fatalf("%s template lock = %#v, want selected manifest digest", name, lock)
		}
	}
	if result.ExecutionID != "run-l9" || result.SandboxID != "sandbox-l9" || result.RuntimeID != "runtime-l9" {
		t.Fatalf("bound identities = %#v", result)
	}
}

type sandboxTemplateWorkflowStub struct {
	result   selection.Result
	err      error
	requests []selection.Request
}

func (s *sandboxTemplateWorkflowStub) Select(_ context.Context, request selection.Request) (selection.Result, error) {
	s.requests = append(s.requests, request)
	return s.result, s.err
}
