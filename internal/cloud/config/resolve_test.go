package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolve_CloudDisabled_ReturnsLocalDefaults(t *testing.T) {
	// Golden test: when cloud is disabled, resolver returns cloudEnabled=false
	// and preserves hard defaults for local execution.
	rc, err := Resolve(ResolveInput{
		CloudEnabled: false,
		WorkflowKind: "run",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.CloudEnabled {
		t.Error("CloudEnabled should be false")
	}
	if rc.WorkflowKind != "run" {
		t.Errorf("WorkflowKind = %q, want %q", rc.WorkflowKind, "run")
	}
	if rc.Mode != ModeUntilComplete {
		t.Errorf("Mode = %q, want %q", rc.Mode, ModeUntilComplete)
	}
	if rc.Engine != "claude" {
		t.Errorf("Engine = %q, want %q", rc.Engine, "claude")
	}
	if rc.Base != "main" {
		t.Errorf("Base = %q, want %q", rc.Base, "main")
	}
	if rc.PullPolicy != PullPolicyAll {
		t.Errorf("PullPolicy = %q, want %q", rc.PullPolicy, PullPolicyAll)
	}
	if !rc.Wait {
		t.Error("Wait should be true for local mode")
	}
	// Cloud-specific fields should be empty when disabled.
	if rc.Endpoint != "" {
		t.Errorf("Endpoint = %q, want empty", rc.Endpoint)
	}
	if rc.Repo != "" {
		t.Errorf("Repo = %q, want empty", rc.Repo)
	}
	if rc.AuthProfile != "" {
		t.Errorf("AuthProfile = %q, want empty", rc.AuthProfile)
	}
	if rc.Scope != "" {
		t.Errorf("Scope = %q, want empty", rc.Scope)
	}
}

func TestResolve_CloudDisabled_AllWorkflowKinds(t *testing.T) {
	// Golden test: all three workflow kinds produce the same local defaults
	// when cloud is disabled.
	for _, kind := range []string{"run", "auto", "review"} {
		t.Run(kind, func(t *testing.T) {
			rc, err := Resolve(ResolveInput{
				CloudEnabled: false,
				WorkflowKind: kind,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rc.CloudEnabled {
				t.Error("CloudEnabled should be false")
			}
			if rc.WorkflowKind != kind {
				t.Errorf("WorkflowKind = %q, want %q", rc.WorkflowKind, kind)
			}
			if rc.Mode != ModeUntilComplete {
				t.Errorf("Mode = %q, want %q", rc.Mode, ModeUntilComplete)
			}
			if rc.Engine != "claude" {
				t.Errorf("Engine = %q, want %q", rc.Engine, "claude")
			}
			if rc.Base != "main" {
				t.Errorf("Base = %q, want %q", rc.Base, "main")
			}
			if rc.PullPolicy != PullPolicyAll {
				t.Errorf("PullPolicy = %q, want %q", rc.PullPolicy, PullPolicyAll)
			}
		})
	}
}

func TestResolve_CloudDisabled_IgnoresCLIAndEnv(t *testing.T) {
	// Golden test: when cloud is disabled, CLI flags and env vars are ignored.
	rc, err := Resolve(ResolveInput{
		CloudEnabled: false,
		WorkflowKind: "auto",
		CLIFlags: &CLIFlags{
			Mode:     "bounded_batch",
			Endpoint: "https://cli.example.com",
			Engine:   "codex",
		},
		Getenv: func(key string) string {
			if key == EnvCloudEngine {
				return "pi"
			}
			return ""
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.CloudEnabled {
		t.Error("CloudEnabled should be false")
	}
	// Should return local defaults, not CLI/env overrides.
	if rc.Mode != ModeUntilComplete {
		t.Errorf("Mode = %q, want %q (hard default, not CLI override)", rc.Mode, ModeUntilComplete)
	}
	if rc.Engine != "claude" {
		t.Errorf("Engine = %q, want %q (hard default, not env override)", rc.Engine, "claude")
	}
}

func TestResolve_HardDefaults(t *testing.T) {
	// When cloud is enabled but no sources provide values, hard defaults apply.
	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "run",
		Getenv:       func(string) string { return "" },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rc.CloudEnabled {
		t.Error("CloudEnabled should be true")
	}
	if rc.Mode != ModeUntilComplete {
		t.Errorf("Mode = %q, want %q", rc.Mode, ModeUntilComplete)
	}
	if rc.Engine != "claude" {
		t.Errorf("Engine = %q, want %q", rc.Engine, "claude")
	}
	if rc.Base != "main" {
		t.Errorf("Base = %q, want %q", rc.Base, "main")
	}
	if rc.PullPolicy != PullPolicyAll {
		t.Errorf("PullPolicy = %q, want %q", rc.PullPolicy, PullPolicyAll)
	}
	if !rc.Wait {
		t.Error("Wait should default to true")
	}
}

func TestResolve_CLIOverridesAll(t *testing.T) {
	// CLI flags have highest precedence — they override env, yaml, and defaults.
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	writeCloudYAML(t, halDir, `
defaultProfile: default
profiles:
  default:
    mode: bounded_batch
    endpoint: https://yaml.example.com
    repo: yaml/repo
    base: yaml-base
    engine: codex
    authProfile: yaml-auth
    scope: yaml-scope
    wait: false
    pullPolicy: state
`)
	waitTrue := true
	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "auto",
		HalDir:       halDir,
		CLIFlags: &CLIFlags{
			Mode:        ModeUntilComplete,
			Endpoint:    "https://cli.example.com",
			Repo:        "cli/repo",
			Base:        "cli-base",
			Engine:      "pi",
			AuthProfile: "cli-auth",
			Scope:       "cli-scope",
			Wait:        &waitTrue,
			PullPolicy:  PullPolicyReports,
		},
		Getenv: func(key string) string {
			envs := map[string]string{
				EnvCloudMode:        "bounded_batch",
				EnvCloudEndpoint:    "https://env.example.com",
				EnvCloudRepo:        "env/repo",
				EnvCloudBase:        "env-base",
				EnvCloudEngine:      "codex",
				EnvCloudAuthProfile: "env-auth",
				EnvCloudScope:       "env-scope",
				EnvCloudWait:        "false",
				EnvCloudPullPolicy:  "state",
			}
			return envs[key]
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Mode != ModeUntilComplete {
		t.Errorf("Mode = %q, want %q (CLI)", rc.Mode, ModeUntilComplete)
	}
	if rc.Endpoint != "https://cli.example.com" {
		t.Errorf("Endpoint = %q, want CLI value", rc.Endpoint)
	}
	if rc.Repo != "cli/repo" {
		t.Errorf("Repo = %q, want CLI value", rc.Repo)
	}
	if rc.Base != "cli-base" {
		t.Errorf("Base = %q, want CLI value", rc.Base)
	}
	if rc.Engine != "pi" {
		t.Errorf("Engine = %q, want CLI value", rc.Engine)
	}
	if rc.AuthProfile != "cli-auth" {
		t.Errorf("AuthProfile = %q, want CLI value", rc.AuthProfile)
	}
	if rc.Scope != "cli-scope" {
		t.Errorf("Scope = %q, want CLI value", rc.Scope)
	}
	if !rc.Wait {
		t.Error("Wait should be true (CLI override)")
	}
	if rc.PullPolicy != PullPolicyReports {
		t.Errorf("PullPolicy = %q, want CLI value", rc.PullPolicy)
	}
}

func TestResolve_EnvOverridesYAML(t *testing.T) {
	// Process env overrides cloud.yaml when no CLI flags are set.
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	writeCloudYAML(t, halDir, `
defaultProfile: default
profiles:
  default:
    mode: bounded_batch
    endpoint: https://yaml.example.com
    engine: codex
    authProfile: yaml-auth
`)
	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "review",
		HalDir:       halDir,
		Getenv: func(key string) string {
			envs := map[string]string{
				EnvCloudMode:        ModeUntilComplete,
				EnvCloudEndpoint:    "https://env.example.com",
				EnvCloudEngine:      "pi",
				EnvCloudAuthProfile: "env-auth",
			}
			return envs[key]
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Mode != ModeUntilComplete {
		t.Errorf("Mode = %q, want %q (env)", rc.Mode, ModeUntilComplete)
	}
	if rc.Endpoint != "https://env.example.com" {
		t.Errorf("Endpoint = %q, want env value", rc.Endpoint)
	}
	if rc.Engine != "pi" {
		t.Errorf("Engine = %q, want env value", rc.Engine)
	}
	if rc.AuthProfile != "env-auth" {
		t.Errorf("AuthProfile = %q, want env value", rc.AuthProfile)
	}
}

func TestResolve_YAMLOverridesDefaults(t *testing.T) {
	// cloud.yaml profile overrides hard defaults when no CLI or env are set.
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	waitFalse := false
	_ = waitFalse
	writeCloudYAML(t, halDir, `
defaultProfile: default
profiles:
  default:
    mode: bounded_batch
    endpoint: https://yaml.example.com
    repo: yaml/repo
    base: develop
    engine: codex
    authProfile: yaml-auth
    scope: yaml-scope
    wait: false
    pullPolicy: reports
`)
	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "run",
		HalDir:       halDir,
		Getenv:       func(string) string { return "" },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Mode != ModeBoundedBatch {
		t.Errorf("Mode = %q, want %q (YAML)", rc.Mode, ModeBoundedBatch)
	}
	if rc.Endpoint != "https://yaml.example.com" {
		t.Errorf("Endpoint = %q, want YAML value", rc.Endpoint)
	}
	if rc.Repo != "yaml/repo" {
		t.Errorf("Repo = %q, want YAML value", rc.Repo)
	}
	if rc.Base != "develop" {
		t.Errorf("Base = %q, want YAML value", rc.Base)
	}
	if rc.Engine != "codex" {
		t.Errorf("Engine = %q, want YAML value", rc.Engine)
	}
	if rc.AuthProfile != "yaml-auth" {
		t.Errorf("AuthProfile = %q, want YAML value", rc.AuthProfile)
	}
	if rc.Scope != "yaml-scope" {
		t.Errorf("Scope = %q, want YAML value", rc.Scope)
	}
	if rc.Wait {
		t.Error("Wait should be false (YAML explicit false)")
	}
	if rc.PullPolicy != PullPolicyReports {
		t.Errorf("PullPolicy = %q, want YAML value", rc.PullPolicy)
	}
}

func TestResolve_InferredDefaultsFallback(t *testing.T) {
	// Inferred defaults (e.g., from git) fill in when YAML and env are empty.
	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "auto",
		Getenv:       func(string) string { return "" },
		InferredDefaults: &InferredDefaults{
			Repo: "inferred/repo",
			Base: "feature-branch",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Repo != "inferred/repo" {
		t.Errorf("Repo = %q, want inferred value", rc.Repo)
	}
	if rc.Base != "feature-branch" {
		t.Errorf("Base = %q, want inferred value", rc.Base)
	}
	// Engine and mode should fall back to hard defaults.
	if rc.Engine != "claude" {
		t.Errorf("Engine = %q, want hard default", rc.Engine)
	}
	if rc.Mode != ModeUntilComplete {
		t.Errorf("Mode = %q, want hard default", rc.Mode)
	}
}

func TestResolve_InferredOverriddenByYAML(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	writeCloudYAML(t, halDir, `
defaultProfile: default
profiles:
  default:
    repo: yaml/repo
    base: yaml-base
`)
	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "run",
		HalDir:       halDir,
		Getenv:       func(string) string { return "" },
		InferredDefaults: &InferredDefaults{
			Repo: "inferred/repo",
			Base: "inferred-base",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Repo != "yaml/repo" {
		t.Errorf("Repo = %q, want YAML value over inferred", rc.Repo)
	}
	if rc.Base != "yaml-base" {
		t.Errorf("Base = %q, want YAML value over inferred", rc.Base)
	}
}

func TestResolve_NamedProfile(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	writeCloudYAML(t, halDir, `
defaultProfile: dev
profiles:
  dev:
    endpoint: https://dev.example.com
    engine: claude
  prod:
    endpoint: https://prod.example.com
    engine: codex
`)
	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "run",
		ProfileName:  "prod",
		HalDir:       halDir,
		Getenv:       func(string) string { return "" },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Endpoint != "https://prod.example.com" {
		t.Errorf("Endpoint = %q, want prod profile value", rc.Endpoint)
	}
	if rc.Engine != "codex" {
		t.Errorf("Engine = %q, want prod profile value", rc.Engine)
	}
}

func TestResolve_MissingCloudYAML(t *testing.T) {
	// Missing cloud.yaml should not error — just skip that tier.
	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "run",
		HalDir:       filepath.Join(t.TempDir(), "nonexistent"),
		Getenv:       func(string) string { return "" },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fall back to hard defaults.
	if rc.Mode != ModeUntilComplete {
		t.Errorf("Mode = %q, want hard default", rc.Mode)
	}
	if rc.Engine != "claude" {
		t.Errorf("Engine = %q, want hard default", rc.Engine)
	}
}

func TestResolve_EmptyHalDir(t *testing.T) {
	// Empty HalDir skips cloud.yaml loading entirely.
	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "review",
		HalDir:       "",
		Getenv:       func(string) string { return "" },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Engine != "claude" {
		t.Errorf("Engine = %q, want hard default", rc.Engine)
	}
}

func TestResolve_WaitPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		cliWait  *bool
		envWait  string
		yamlWait *bool
		want     bool
	}{
		{
			name:     "CLI true overrides all",
			cliWait:  boolPtr(true),
			envWait:  "false",
			yamlWait: boolPtr(false),
			want:     true,
		},
		{
			name:     "CLI false overrides all",
			cliWait:  boolPtr(false),
			envWait:  "true",
			yamlWait: boolPtr(true),
			want:     false,
		},
		{
			name:     "env overrides yaml",
			cliWait:  nil,
			envWait:  "false",
			yamlWait: boolPtr(true),
			want:     false,
		},
		{
			name:     "yaml overrides default",
			cliWait:  nil,
			envWait:  "",
			yamlWait: boolPtr(false),
			want:     false,
		},
		{
			name:     "hard default is true",
			cliWait:  nil,
			envWait:  "",
			yamlWait: nil,
			want:     true,
		},
		{
			name:     "env yes is true",
			cliWait:  nil,
			envWait:  "yes",
			yamlWait: nil,
			want:     true,
		},
		{
			name:     "env 1 is true",
			cliWait:  nil,
			envWait:  "1",
			yamlWait: nil,
			want:     true,
		},
		{
			name:     "env 0 is false",
			cliWait:  nil,
			envWait:  "0",
			yamlWait: nil,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cli *CLIFlags
			if tt.cliWait != nil {
				cli = &CLIFlags{Wait: tt.cliWait}
			}

			var yaml *Profile
			if tt.yamlWait != nil {
				yaml = &Profile{Wait: tt.yamlWait}
			}

			got := resolveWait(cli, func(key string) string {
				if key == EnvCloudWait {
					return tt.envWait
				}
				return ""
			}, yaml)

			if got != tt.want {
				t.Errorf("resolveWait() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolve_DotenvLoading(t *testing.T) {
	// .env values should fill in when process env is empty.
	dir := t.TempDir()
	dotenvPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(dotenvPath, []byte("HAL_CLOUD_ENGINE=pi\nHAL_CLOUD_REPO=dotenv/repo\n"), 0644); err != nil {
		t.Fatal(err)
	}

	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "run",
		Getenv:       os.Getenv, // real os.Getenv — .env should load into process
		DotenvPath:   dotenvPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// godotenv.Load is non-overriding, so if HAL_CLOUD_ENGINE was already set,
	// the dotenv value won't override. Since we're in a test, the env var is
	// likely not set, so we expect the dotenv value.
	// Clean up env vars set by godotenv.
	t.Cleanup(func() {
		os.Unsetenv("HAL_CLOUD_ENGINE")
		os.Unsetenv("HAL_CLOUD_REPO")
	})

	if rc.Engine != "pi" {
		t.Errorf("Engine = %q, want %q (from .env)", rc.Engine, "pi")
	}
	if rc.Repo != "dotenv/repo" {
		t.Errorf("Repo = %q, want %q (from .env)", rc.Repo, "dotenv/repo")
	}
}

func TestResolve_ProcessEnvOverridesDotenv(t *testing.T) {
	// Process env should take precedence over .env values.
	dir := t.TempDir()
	dotenvPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(dotenvPath, []byte("HAL_CLOUD_ENGINE=from-dotenv\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Set process env before loading .env — godotenv.Load won't override.
	os.Setenv("HAL_CLOUD_ENGINE", "from-process-env")
	t.Cleanup(func() {
		os.Unsetenv("HAL_CLOUD_ENGINE")
	})

	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "run",
		Getenv:       os.Getenv,
		DotenvPath:   dotenvPath,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Engine != "from-process-env" {
		t.Errorf("Engine = %q, want %q (process env over .env)", rc.Engine, "from-process-env")
	}
}

func TestResolve_MissingDotenv(t *testing.T) {
	// Missing .env should not error.
	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "run",
		Getenv:       func(string) string { return "" },
		DotenvPath:   filepath.Join(t.TempDir(), "nonexistent.env"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Engine != "claude" {
		t.Errorf("Engine = %q, want hard default", rc.Engine)
	}
}

func TestResolve_InvalidCloudYAML(t *testing.T) {
	// Invalid cloud.yaml should return an error (not silently skip).
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	writeCloudYAML(t, halDir, `
defaultProfile: nonexistent
profiles:
  default:
    mode: invalid_mode
`)
	_, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "run",
		HalDir:       halDir,
		Getenv:       func(string) string { return "" },
	})
	if err == nil {
		t.Fatal("expected error for invalid cloud.yaml")
	}
}

func TestResolve_SameShapeForAllWorkflowKinds(t *testing.T) {
	// The resolver returns the same resolved config shape regardless of
	// workflow kind — only the WorkflowKind field differs.
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	writeCloudYAML(t, halDir, `
defaultProfile: default
profiles:
  default:
    mode: bounded_batch
    endpoint: https://cloud.example.com
    repo: org/repo
    engine: codex
    authProfile: ap-123
    scope: prd-001
`)

	var results []*ResolvedConfig
	for _, kind := range []string{"run", "auto", "review"} {
		rc, err := Resolve(ResolveInput{
			CloudEnabled: true,
			WorkflowKind: kind,
			HalDir:       halDir,
			Getenv:       func(string) string { return "" },
		})
		if err != nil {
			t.Fatalf("unexpected error for %s: %v", kind, err)
		}
		results = append(results, rc)
	}

	// All fields except WorkflowKind should be identical.
	for i := 1; i < len(results); i++ {
		if results[i].Mode != results[0].Mode {
			t.Errorf("Mode differs between %s and %s", results[0].WorkflowKind, results[i].WorkflowKind)
		}
		if results[i].Endpoint != results[0].Endpoint {
			t.Errorf("Endpoint differs between %s and %s", results[0].WorkflowKind, results[i].WorkflowKind)
		}
		if results[i].Repo != results[0].Repo {
			t.Errorf("Repo differs between %s and %s", results[0].WorkflowKind, results[i].WorkflowKind)
		}
		if results[i].Engine != results[0].Engine {
			t.Errorf("Engine differs between %s and %s", results[0].WorkflowKind, results[i].WorkflowKind)
		}
		if results[i].AuthProfile != results[0].AuthProfile {
			t.Errorf("AuthProfile differs between %s and %s", results[0].WorkflowKind, results[i].WorkflowKind)
		}
		if results[i].Wait != results[0].Wait {
			t.Errorf("Wait differs between %s and %s", results[0].WorkflowKind, results[i].WorkflowKind)
		}
		if results[i].PullPolicy != results[0].PullPolicy {
			t.Errorf("PullPolicy differs between %s and %s", results[0].WorkflowKind, results[i].WorkflowKind)
		}
	}
}

func TestResolve_PartialCLIOverride(t *testing.T) {
	// CLI sets some fields; others fall through to YAML and then defaults.
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	writeCloudYAML(t, halDir, `
defaultProfile: default
profiles:
  default:
    mode: bounded_batch
    endpoint: https://yaml.example.com
    engine: codex
    repo: yaml/repo
`)
	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "run",
		HalDir:       halDir,
		CLIFlags: &CLIFlags{
			Engine: "pi",
			// Only engine is overridden by CLI.
		},
		Getenv: func(string) string { return "" },
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Engine != "pi" {
		t.Errorf("Engine = %q, want %q (CLI)", rc.Engine, "pi")
	}
	if rc.Mode != ModeBoundedBatch {
		t.Errorf("Mode = %q, want %q (YAML fallback)", rc.Mode, ModeBoundedBatch)
	}
	if rc.Endpoint != "https://yaml.example.com" {
		t.Errorf("Endpoint = %q, want YAML value", rc.Endpoint)
	}
	if rc.Repo != "yaml/repo" {
		t.Errorf("Repo = %q, want YAML value", rc.Repo)
	}
	if rc.Base != "main" {
		t.Errorf("Base = %q, want hard default", rc.Base)
	}
}

func TestResolve_NilGetenvUsesOsGetenv(t *testing.T) {
	// nil Getenv should fall back to os.Getenv.
	os.Setenv("HAL_CLOUD_ENGINE", "test-engine")
	t.Cleanup(func() { os.Unsetenv("HAL_CLOUD_ENGINE") })

	rc, err := Resolve(ResolveInput{
		CloudEnabled: true,
		WorkflowKind: "run",
		Getenv:       nil, // should use os.Getenv
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.Engine != "test-engine" {
		t.Errorf("Engine = %q, want %q (from os.Getenv)", rc.Engine, "test-engine")
	}
}

func TestParseBool(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"1", true},
		{"yes", true},
		{"Yes", true},
		{"false", false},
		{"0", false},
		{"no", false},
		{"", false},
		{"  true  ", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseBool(tt.input)
			if got != tt.want {
				t.Errorf("parseBool(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// writeCloudYAML writes a cloud.yaml file in the given halDir.
func writeCloudYAML(t *testing.T, halDir, content string) {
	t.Helper()
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(halDir, CloudConfigFile)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
