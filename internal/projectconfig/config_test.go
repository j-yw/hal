package projectconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadMissingConfigReturnsEmptyDefaults(t *testing.T) {
	cfg, err := Load(t.TempDir())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Factory.Base.Set {
		t.Fatalf("Factory.Base.Set = true, want false")
	}
	if cfg.Sandbox.SyncOut.Set {
		t.Fatalf("Sandbox.SyncOut.Set = true, want false")
	}
	if cfg.Run.Timeout.Set {
		t.Fatalf("Run.Timeout.Set = true, want false")
	}
	if cfg.CI.Merge.Strategy.Set {
		t.Fatalf("CI.Merge.Strategy.Set = true, want false")
	}
}

func TestLoadValidFactoryAndSandboxDefaults(t *testing.T) {
	dir := writeProjectConfig(t, `
factory:
  defaults:
    base: main
    executor: sandbox
    sandboxName: build-box
    sandboxHost: worker-1
    sandboxRuntime: rootless_podman
    publishFrom: auto
    secretEnv:
      - GITHUB_TOKEN
      - OPENAI_API_KEY
sandbox:
  defaults:
    name: build-box
    host: worker-1
    runtime: microvm
    workspaceMode: clone
    syncOut: true
    apply: false
`)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertStringValue(t, "factory base", cfg.Factory.Base, "main")
	assertStringValue(t, "factory executor", cfg.Factory.Executor, "sandbox")
	assertStringValue(t, "factory sandbox name", cfg.Factory.SandboxName, "build-box")
	assertStringValue(t, "factory sandbox host", cfg.Factory.SandboxHost, "worker-1")
	assertStringValue(t, "factory sandbox runtime", cfg.Factory.SandboxRuntime, "rootless_podman")
	assertStringValue(t, "factory publish from", cfg.Factory.PublishFrom, "auto")
	if !cfg.Factory.SecretEnv.Set {
		t.Fatal("Factory.SecretEnv.Set = false, want true")
	}
	assertStringSlice(t, cfg.Factory.SecretEnv.Value, []string{"GITHUB_TOKEN", "OPENAI_API_KEY"})

	assertStringValue(t, "sandbox name", cfg.Sandbox.Name, "build-box")
	assertStringValue(t, "sandbox host", cfg.Sandbox.Host, "worker-1")
	assertStringValue(t, "sandbox runtime", cfg.Sandbox.Runtime, "microvm")
	assertStringValue(t, "sandbox workspace mode", cfg.Sandbox.WorkspaceMode, "clone")
	assertBoolValue(t, "sandbox sync out", cfg.Sandbox.SyncOut, true)
	assertBoolValue(t, "sandbox apply", cfg.Sandbox.Apply, false)
}

func TestLoadSetMarkersForExplicitZeroValues(t *testing.T) {
	dir := writeProjectConfig(t, `
factory:
  defaults:
    base: ""
    secretEnv: []
sandbox:
  defaults:
    apply: false
run:
  parallel: 0
auto:
  parallel: 0
ci:
  status:
    wait: false
  fix:
    maxAttempts: 0
  merge:
    deleteBranch: false
    allowNoChecks: false
`)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertStringValue(t, "factory explicit empty base", cfg.Factory.Base, "")
	if !cfg.Factory.SecretEnv.Set || len(cfg.Factory.SecretEnv.Value) != 0 {
		t.Fatalf("Factory.SecretEnv = %#v, want explicit empty slice", cfg.Factory.SecretEnv)
	}
	assertBoolValue(t, "sandbox apply", cfg.Sandbox.Apply, false)
	assertIntValue(t, "run parallel", cfg.Run.Parallel, 0)
	assertIntValue(t, "auto parallel", cfg.Auto.Parallel, 0)
	assertBoolValue(t, "ci status wait", cfg.CI.Status.Wait, false)
	assertIntValue(t, "ci fix max attempts", cfg.CI.Fix.MaxAttempts, 0)
	assertBoolValue(t, "ci merge delete branch", cfg.CI.Merge.DeleteBranch, false)
	assertBoolValue(t, "ci merge allow no checks", cfg.CI.Merge.AllowNoChecks, false)

	if got := cfg.Factory.Base.Or("fallback"); got != "" {
		t.Fatalf("Factory.Base.Or() = %q, want explicit empty string", got)
	}
	if got := cfg.Sandbox.Name.Or("fallback"); got != "fallback" {
		t.Fatalf("Sandbox.Name.Or() = %q, want fallback", got)
	}
}

func TestLoadDurations(t *testing.T) {
	dir := writeProjectConfig(t, `
run:
  timeout: 45m
ci:
  status:
    timeout: 30m
    poll: 15s
    noChecksGrace: 90s
`)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertDurationValue(t, "run timeout", cfg.Run.Timeout, 45*time.Minute)
	assertDurationValue(t, "ci status timeout", cfg.CI.Status.Timeout, 30*time.Minute)
	assertDurationValue(t, "ci status poll", cfg.CI.Status.Poll, 15*time.Second)
	assertDurationValue(t, "ci status no checks grace", cfg.CI.Status.NoChecksGrace, 90*time.Second)
}

func TestLoadValidRunAutoAndCIDefaults(t *testing.T) {
	dir := writeProjectConfig(t, `
run:
  base: release
  timeout: 20m
  parallel: 2
auto:
  base: develop
  parallel: 3
ci:
  status:
    wait: true
    timeout: 30m
    poll: 20s
    noChecksGrace: 2m
  fix:
    maxAttempts: 4
  merge:
    strategy: REBASE
    deleteBranch: true
    allowNoChecks: true
`)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertStringValue(t, "run base", cfg.Run.Base, "release")
	assertDurationValue(t, "run timeout", cfg.Run.Timeout, 20*time.Minute)
	assertIntValue(t, "run parallel", cfg.Run.Parallel, 2)
	assertStringValue(t, "auto base", cfg.Auto.Base, "develop")
	assertIntValue(t, "auto parallel", cfg.Auto.Parallel, 3)
	assertBoolValue(t, "ci status wait", cfg.CI.Status.Wait, true)
	assertDurationValue(t, "ci status timeout", cfg.CI.Status.Timeout, 30*time.Minute)
	assertDurationValue(t, "ci status poll", cfg.CI.Status.Poll, 20*time.Second)
	assertDurationValue(t, "ci status no checks grace", cfg.CI.Status.NoChecksGrace, 2*time.Minute)
	assertIntValue(t, "ci fix max attempts", cfg.CI.Fix.MaxAttempts, 4)
	assertStringValue(t, "ci merge strategy", cfg.CI.Merge.Strategy, "rebase")
	assertBoolValue(t, "ci merge delete branch", cfg.CI.Merge.DeleteBranch, true)
	assertBoolValue(t, "ci merge allow no checks", cfg.CI.Merge.AllowNoChecks, true)
}

func TestLoadIgnoresExistingFactoryAndSandboxSiblingSections(t *testing.T) {
	dir := writeProjectConfig(t, `
factory:
  executor: remote
  policy:
    publish: pr
    sandboxRuntime: docker
  defaults:
    executor: local
sandbox:
  runtime: docker
  networkPolicy:
    preset: deny_by_default
  secrets:
    requestedModes: [env]
  defaults:
    runtime: ssh_machine
`)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	assertStringValue(t, "factory executor", cfg.Factory.Executor, "local")
	assertStringValue(t, "sandbox runtime", cfg.Sandbox.Runtime, "ssh_machine")
	if cfg.Factory.PublishFrom.Set {
		t.Fatalf("Factory.PublishFrom.Set = true from sibling policy, want false")
	}
	if cfg.Sandbox.WorkspaceMode.Set {
		t.Fatalf("Sandbox.WorkspaceMode.Set = true from sibling sandbox config, want false")
	}
}

func TestLoadInvalidEnumValues(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "factory executor",
			yaml: `
factory:
  defaults:
    executor: remote
`,
			wantErr: "factory.defaults.executor",
		},
		{
			name: "factory publish from",
			yaml: `
factory:
  defaults:
    publishFrom: laptop
`,
			wantErr: "factory.defaults.publishFrom",
		},
		{
			name: "factory sandbox runtime",
			yaml: `
factory:
  defaults:
    sandboxRuntime: docker
`,
			wantErr: "factory.defaults.sandboxRuntime",
		},
		{
			name: "sandbox runtime",
			yaml: `
sandbox:
  defaults:
    runtime: docker
`,
			wantErr: "sandbox.defaults.runtime",
		},
		{
			name: "sandbox workspace mode direct",
			yaml: `
sandbox:
  defaults:
    workspaceMode: direct
`,
			wantErr: "sandbox.defaults.workspaceMode direct is not supported",
		},
		{
			name: "ci merge strategy",
			yaml: `
ci:
  merge:
    strategy: fast-forward
`,
			wantErr: "ci.merge.strategy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := writeProjectConfig(t, tt.yaml)
			_, err := Load(dir)
			if err == nil {
				t.Fatal("Load() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load() error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoadInvalidDuration(t *testing.T) {
	dir := writeProjectConfig(t, `
run:
  timeout: forever
`)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	if got, want := err.Error(), "run.timeout must be a duration"; !strings.Contains(got, want) {
		t.Fatalf("Load() error = %q, want containing %q", got, want)
	}
}

func TestLoadInvalidYAMLReturnsParseError(t *testing.T) {
	dir := writeProjectConfig(t, `
factory:
  defaults:
    base: [
`)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	if got, want := err.Error(), "parse project config"; !strings.Contains(got, want) {
		t.Fatalf("Load() error = %q, want containing %q", got, want)
	}
}

func TestLoadSecretEnvOnlyAcceptsNamesWithoutLeakingValues(t *testing.T) {
	secretAssignment := "GITHUB_TOKEN=ghp_raw_secret_value"
	dir := writeProjectConfig(t, `
factory:
  defaults:
    secretEnv:
      - `+secretAssignment+`
`)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() error = nil, want error")
	}
	if got, want := err.Error(), "factory.defaults.secretEnv[0] must be an environment variable name"; got != want {
		t.Fatalf("Load() error = %q, want %q", got, want)
	}
	if strings.Contains(err.Error(), secretAssignment) || strings.Contains(err.Error(), "ghp_raw_secret_value") {
		t.Fatalf("Load() error leaked secret assignment: %q", err.Error())
	}
}

func writeProjectConfig(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte(strings.TrimLeft(content, "\n")), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return dir
}

func assertStringValue(t *testing.T, label string, got Value[string], want string) {
	t.Helper()
	if !got.Set || got.Value != want {
		t.Fatalf("%s = %#v, want set value %q", label, got, want)
	}
}

func assertBoolValue(t *testing.T, label string, got Value[bool], want bool) {
	t.Helper()
	if !got.Set || got.Value != want {
		t.Fatalf("%s = %#v, want set value %t", label, got, want)
	}
}

func assertIntValue(t *testing.T, label string, got Value[int], want int) {
	t.Helper()
	if !got.Set || got.Value != want {
		t.Fatalf("%s = %#v, want set value %d", label, got, want)
	}
}

func assertDurationValue(t *testing.T, label string, got Value[time.Duration], want time.Duration) {
	t.Helper()
	if !got.Set || got.Value != want {
		t.Fatalf("%s = %#v, want set value %s", label, got, want)
	}
}

func assertStringSlice(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("slice length = %d, want %d (%#v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("slice[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
