package cmd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
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
	files := []string{"run_sandbox.go", "auto_sandbox.go", "factory.go"}
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(content)
		selectAt := strings.Index(text, "executeSandboxTemplateSelectionBeforeConstruction")
		if selectAt < 0 {
			t.Fatalf("%s missing shared L9 selection boundary", file)
		}
		for _, later := range []string{"resolveProvider", "resolveWorkerRuntime", "resolveRuntimeDriver"} {
			at := strings.Index(text[selectAt:], later)
			if at < 0 {
				t.Fatalf("%s does not prove %s occurs after selection", file, later)
			}
		}
	}
}

type sandboxTemplateWorkflowStub struct {
	result selection.Result
	err    error
}

func (s *sandboxTemplateWorkflowStub) Select(context.Context, selection.Request) (selection.Result, error) {
	return s.result, s.err
}
