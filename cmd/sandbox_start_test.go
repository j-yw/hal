package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

// uuidV7Pattern matches the 8-4-4-4-12 hex format of a UUIDv7.
var uuidV7Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// mockProvider implements sandbox.Provider for testing.
type mockProvider struct {
	createResult *sandbox.SandboxResult
	createErr    error
	createCalls  []mockCreateCall
}

type mockCreateCall struct {
	Name string
	Env  map[string]string
}

func (m *mockProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	m.createCalls = append(m.createCalls, mockCreateCall{Name: name, Env: env})
	return m.createResult, m.createErr
}

func (m *mockProvider) Stop(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func (m *mockProvider) Delete(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func (m *mockProvider) SSH(info *sandbox.ConnectInfo) (*exec.Cmd, error) {
	return nil, nil
}

func (m *mockProvider) Exec(info *sandbox.ConnectInfo, args []string) (*exec.Cmd, error) {
	return nil, nil
}

func (m *mockProvider) Status(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func setupStartTest(t *testing.T, dir string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Isolate global registry writes during tests
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(dir, "globalcfg"))
	// Write a minimal config
	sandboxCfg := &compound.SandboxConfig{
		Provider: "daytona",
		Env:      map[string]string{},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}
}

func fakeBranchResolver(branch string, err error) branchResolver {
	return func() (string, error) {
		return branch, err
	}
}

func TestRunSandboxStart_Success(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "hal-feature-auth", ID: "ws-123", IP: "10.0.0.1"},
	}

	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "", nil, autoShutdownOpts{}, &out, mock, fakeBranchResolver("hal/feature-auth", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}
	if mock.createCalls[0].Name != "hal-feature-auth" {
		t.Errorf("Create name = %q, want %q", mock.createCalls[0].Name, "hal-feature-auth")
	}

	// Verify global registry entry was created
	instance, err := sandbox.LoadInstance("hal-feature-auth")
	if err != nil {
		t.Fatalf("failed to load from global registry: %v", err)
	}
	if instance.Name != "hal-feature-auth" {
		t.Errorf("instance.Name = %q, want %q", instance.Name, "hal-feature-auth")
	}
	if !uuidV7Pattern.MatchString(instance.ID) {
		t.Errorf("instance.ID = %q, want UUIDv7 format", instance.ID)
	}
	if instance.Status != sandbox.StatusRunning {
		t.Errorf("instance.Status = %q, want %q", instance.Status, sandbox.StatusRunning)
	}
	if instance.Provider != "daytona" {
		t.Errorf("instance.Provider = %q, want %q", instance.Provider, "daytona")
	}
	if instance.WorkspaceID != "ws-123" {
		t.Errorf("instance.WorkspaceID = %q, want %q", instance.WorkspaceID, "ws-123")
	}
	if instance.IP != "10.0.0.1" {
		t.Errorf("instance.IP = %q, want %q", instance.IP, "10.0.0.1")
	}
	if instance.CreatedAt.IsZero() {
		t.Error("instance.CreatedAt should not be zero")
	}

	// Backward compat: local state also saved
	halDir := filepath.Join(dir, template.HalDir)
	state, err := sandbox.LoadState(halDir)
	if err != nil {
		t.Fatalf("failed to load local state: %v", err)
	}
	if state.Name != "hal-feature-auth" {
		t.Errorf("state.Name = %q, want %q", state.Name, "hal-feature-auth")
	}

	// Verify output mentions provider
	if !strings.Contains(out.String(), "Sandbox started") {
		t.Errorf("output missing 'Sandbox started': %q", out.String())
	}
}

func TestRunSandboxStart_ExplicitName(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "my-sandbox"},
	}

	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "my-sandbox", nil, autoShutdownOpts{}, &out, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}
	if mock.createCalls[0].Name != "my-sandbox" {
		t.Errorf("Create name = %q, want %q", mock.createCalls[0].Name, "my-sandbox")
	}

	// Verify global registry entry
	instance, err := sandbox.LoadInstance("my-sandbox")
	if err != nil {
		t.Fatalf("failed to load from global registry: %v", err)
	}
	if instance.Name != "my-sandbox" {
		t.Errorf("instance.Name = %q, want %q", instance.Name, "my-sandbox")
	}
	if instance.Status != sandbox.StatusRunning {
		t.Errorf("instance.Status = %q, want %q", instance.Status, sandbox.StatusRunning)
	}
}

func TestRunSandboxStart_EnvVarsFromConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(dir, "globalcfg"))
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	sandboxCfg := &compound.SandboxConfig{
		Provider: "daytona",
		Env: map[string]string{
			"GIT_TOKEN": "ghp_from_config",
			"API_KEY":   "sk-from-config",
		},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb"},
	}

	// CLI env overrides config
	cliEnv := map[string]string{"API_KEY": "sk-from-cli"}

	err := runSandboxStartWithDeps(dir, "sb", cliEnv, autoShutdownOpts{}, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}
	env := mock.createCalls[0].Env
	if env["GIT_TOKEN"] != "ghp_from_config" {
		t.Errorf("GIT_TOKEN = %q, want from config", env["GIT_TOKEN"])
	}
	if env["API_KEY"] != "sk-from-cli" {
		t.Errorf("API_KEY = %q, want from CLI override", env["API_KEY"])
	}
}

func TestRunSandboxStart_LockdownRequiresAuthKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(dir, "globalcfg"))
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	sandboxCfg := &compound.SandboxConfig{
		Provider:          "daytona",
		Env:               map[string]string{},
		TailscaleLockdown: true,
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	mock := &mockProvider{createResult: &sandbox.SandboxResult{Name: "sb"}}
	err := runSandboxStartWithDeps(dir, "sb", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "tailscale lockdown requires TAILSCALE_AUTHKEY") {
		t.Errorf("error %q should mention missing TAILSCALE_AUTHKEY", err.Error())
	}
	if len(mock.createCalls) != 0 {
		t.Fatalf("expected provider.Create not to be called, got %d calls", len(mock.createCalls))
	}
}

func TestRunSandboxStart_ProviderAndIPSaved(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	// Isolate global registry
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(dir, "globalcfg"))
	sandboxCfg := &compound.SandboxConfig{
		Provider: "hetzner",
		Env:      map[string]string{},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "my-server", IP: "10.0.0.42"},
	}

	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "my-server", nil, autoShutdownOpts{}, &out, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify global registry entry
	instance, err := sandbox.LoadInstance("my-server")
	if err != nil {
		t.Fatalf("failed to load from global registry: %v", err)
	}
	if instance.Provider != "hetzner" {
		t.Errorf("instance.Provider = %q, want %q", instance.Provider, "hetzner")
	}
	if instance.IP != "10.0.0.42" {
		t.Errorf("instance.IP = %q, want %q", instance.IP, "10.0.0.42")
	}
	if !uuidV7Pattern.MatchString(instance.ID) {
		t.Errorf("instance.ID = %q, want UUIDv7 format", instance.ID)
	}
	if instance.Status != sandbox.StatusRunning {
		t.Errorf("instance.Status = %q, want %q", instance.Status, sandbox.StatusRunning)
	}

	// Backward compat: local state also has the fields
	state, err := sandbox.LoadState(halDir)
	if err != nil {
		t.Fatalf("failed to load local state: %v", err)
	}
	if state.Provider != "hetzner" {
		t.Errorf("state.Provider = %q, want %q", state.Provider, "hetzner")
	}
	if state.IP != "10.0.0.42" {
		t.Errorf("state.IP = %q, want %q", state.IP, "10.0.0.42")
	}

	if !strings.Contains(out.String(), "hetzner") {
		t.Errorf("output should mention provider: %q", out.String())
	}
}

func TestRunSandboxStart_CreateFailure(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createErr: fmt.Errorf("quota exceeded"),
	}

	err := runSandboxStartWithDeps(dir, "sb", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "sandbox creation failed") {
		t.Errorf("error %q should contain 'sandbox creation failed'", err.Error())
	}
}

func TestRunSandboxStart_BranchFailure(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{}

	err := runSandboxStartWithDeps(dir, "", nil, autoShutdownOpts{}, io.Discard, mock, fakeBranchResolver("", fmt.Errorf("not on a branch")))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "could not determine sandbox name from git branch") {
		t.Errorf("error %q missing branch failure text", err.Error())
	}
}

func TestRunSandboxStart_HalDirMissing(t *testing.T) {
	dir := t.TempDir()

	err := runSandboxStartWithDeps(dir, "sb", nil, autoShutdownOpts{}, io.Discard, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), ".hal/ not found") {
		t.Errorf("error %q should mention .hal/", err.Error())
	}
}

func TestRunSandboxStart_ResolvesLightsailProviderConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(dir, "globalcfg"))
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	sandboxCfg := &compound.SandboxConfig{
		Provider: "lightsail",
		Env:      map[string]string{},
		Lightsail: compound.LightsailConfig{
			Region:           "us-east-1",
			AvailabilityZone: "us-east-1b",
			Bundle:           "small_3_0",
			KeyPairName:      "hal-keypair",
		},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	originalResolveProvider := resolveSandboxProvider
	t.Cleanup(func() {
		resolveSandboxProvider = originalResolveProvider
	})

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb"},
	}

	var gotProvider string
	var gotCfg sandbox.ProviderConfig
	resolveSandboxProvider = func(provider string, cfg sandbox.ProviderConfig) (sandbox.Provider, error) {
		gotProvider = provider
		gotCfg = cfg
		return mock, nil
	}

	if err := runSandboxStartWithDeps(dir, "sb", nil, autoShutdownOpts{}, io.Discard, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotProvider != "lightsail" {
		t.Errorf("provider = %q, want %q", gotProvider, "lightsail")
	}
	if gotCfg.LightsailRegion != "us-east-1" {
		t.Errorf("LightsailRegion = %q, want %q", gotCfg.LightsailRegion, "us-east-1")
	}
	if gotCfg.LightsailAvailabilityZone != "us-east-1b" {
		t.Errorf("LightsailAvailabilityZone = %q, want %q", gotCfg.LightsailAvailabilityZone, "us-east-1b")
	}
	if gotCfg.LightsailBundle != "small_3_0" {
		t.Errorf("LightsailBundle = %q, want %q", gotCfg.LightsailBundle, "small_3_0")
	}
	if gotCfg.LightsailKeyPairName != "hal-keypair" {
		t.Errorf("LightsailKeyPairName = %q, want %q", gotCfg.LightsailKeyPairName, "hal-keypair")
	}
}

func TestRunSandboxAutoMigrate_WarnsOnError(t *testing.T) {
	originalMigrate := sandboxMigrate
	t.Cleanup(func() {
		sandboxMigrate = originalMigrate
	})

	sandboxMigrate = func(projectDir string) error {
		if projectDir != "./project" {
			t.Fatalf("projectDir = %q, want %q", projectDir, "./project")
		}
		return fmt.Errorf("boom")
	}

	var out bytes.Buffer
	if err := runSandboxAutoMigrate("./project", &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := "warning: sandbox migration failed: boom\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}

func TestRunSandboxAutoMigrate_NoOutputOnSuccess(t *testing.T) {
	originalMigrate := sandboxMigrate
	t.Cleanup(func() {
		sandboxMigrate = originalMigrate
	})

	sandboxMigrate = func(projectDir string) error {
		if projectDir != "./project" {
			t.Fatalf("projectDir = %q, want %q", projectDir, "./project")
		}
		return nil
	}

	var out bytes.Buffer
	if err := runSandboxAutoMigrate("./project", &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if out.Len() != 0 {
		t.Fatalf("expected no output, got %q", out.String())
	}
}

func TestRunSandboxStart_AutoMigrateFailureWarnsAndContinues(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	originalMigrate := sandboxMigrate
	t.Cleanup(func() {
		sandboxMigrate = originalMigrate
	})

	sandboxMigrate = func(projectDir string) error {
		if projectDir != dir {
			t.Fatalf("projectDir = %q, want %q", projectDir, dir)
		}
		return fmt.Errorf("migration unavailable")
	}

	mock := &mockProvider{createResult: &sandbox.SandboxResult{Name: "sb"}}

	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "sb", nil, autoShutdownOpts{}, &out, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected provider.Create to be called once, got %d", len(mock.createCalls))
	}

	output := out.String()
	warn := "warning: sandbox migration failed: migration unavailable"
	if !strings.Contains(output, warn) {
		t.Fatalf("output missing warning %q: %q", warn, output)
	}

	warnIdx := strings.Index(output, warn)
	startIdx := strings.Index(output, "Starting sandbox")
	if warnIdx == -1 || startIdx == -1 || warnIdx > startIdx {
		t.Fatalf("warning should appear before sandbox creation output: %q", output)
	}
}

func TestRunSandboxStart_GlobalConfigSizeDefaults(t *testing.T) {
	dir := t.TempDir()
	globalDir := filepath.Join(dir, "globalcfg")
	t.Setenv("HAL_CONFIG_HOME", globalDir)

	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Local config has provider set but no size
	sandboxCfg := &compound.SandboxConfig{
		Provider: "hetzner",
		Env:      map[string]string{},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	// Global config has size defaults
	globalCfg := &sandbox.GlobalConfig{
		Provider: "hetzner",
		Hetzner: sandbox.HetznerGlobalConfig{
			ServerType: "cx22",
			SSHKey:     "my-global-key",
		},
	}
	if err := sandbox.SaveGlobalConfig(globalCfg); err != nil {
		t.Fatal(err)
	}

	originalResolveProvider := resolveSandboxProvider
	t.Cleanup(func() {
		resolveSandboxProvider = originalResolveProvider
	})

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb"},
	}

	var gotCfg sandbox.ProviderConfig
	resolveSandboxProvider = func(provider string, cfg sandbox.ProviderConfig) (sandbox.Provider, error) {
		gotCfg = cfg
		return mock, nil
	}

	if err := runSandboxStartWithDeps(dir, "sb", nil, autoShutdownOpts{}, io.Discard, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Size fields should come from global config
	if gotCfg.HetznerServerType != "cx22" {
		t.Errorf("HetznerServerType = %q, want %q (from global config)", gotCfg.HetznerServerType, "cx22")
	}
	if gotCfg.HetznerSSHKey != "my-global-key" {
		t.Errorf("HetznerSSHKey = %q, want %q (from global config)", gotCfg.HetznerSSHKey, "my-global-key")
	}
}

func TestRunSandboxStart_LocalConfigOverridesGlobalSize(t *testing.T) {
	dir := t.TempDir()
	globalDir := filepath.Join(dir, "globalcfg")
	t.Setenv("HAL_CONFIG_HOME", globalDir)

	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Local config has an explicit size
	sandboxCfg := &compound.SandboxConfig{
		Provider: "hetzner",
		Env:      map[string]string{},
		Hetzner: compound.HetznerConfig{
			ServerType: "cx42",
		},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	// Global config has a different size default
	globalCfg := &sandbox.GlobalConfig{
		Provider: "hetzner",
		Hetzner: sandbox.HetznerGlobalConfig{
			ServerType: "cx22",
		},
	}
	if err := sandbox.SaveGlobalConfig(globalCfg); err != nil {
		t.Fatal(err)
	}

	originalResolveProvider := resolveSandboxProvider
	t.Cleanup(func() {
		resolveSandboxProvider = originalResolveProvider
	})

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb"},
	}

	var gotCfg sandbox.ProviderConfig
	resolveSandboxProvider = func(provider string, cfg sandbox.ProviderConfig) (sandbox.Provider, error) {
		gotCfg = cfg
		return mock, nil
	}

	if err := runSandboxStartWithDeps(dir, "sb", nil, autoShutdownOpts{}, io.Discard, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Local config should take priority over global
	if gotCfg.HetznerServerType != "cx42" {
		t.Errorf("HetznerServerType = %q, want %q (local override)", gotCfg.HetznerServerType, "cx42")
	}
}

func TestSandboxStartCommandFlags(t *testing.T) {
	if sandboxStartCmd.Flags().Lookup("name") == nil {
		t.Fatal("--name flag should exist")
	}
	if sandboxStartCmd.Flags().Lookup("env") == nil {
		t.Fatal("--env flag should exist")
	}
	if sandboxStartCmd.Flags().Lookup("auto-shutdown") == nil {
		t.Fatal("--auto-shutdown flag should exist")
	}
	if sandboxStartCmd.Flags().Lookup("no-auto-shutdown") == nil {
		t.Fatal("--no-auto-shutdown flag should exist")
	}
	if sandboxStartCmd.Flags().Lookup("idle-hours") == nil {
		t.Fatal("--idle-hours flag should exist")
	}
}

func TestResolveAutoShutdown(t *testing.T) {
	boolPtr := func(v bool) *bool { return &v }
	intPtr := func(v int) *int { return &v }

	tests := []struct {
		name             string
		globalCfg        *sandbox.GlobalConfig
		opts             autoShutdownOpts
		wantAutoShutdown bool
		wantIdleHours    int
	}{
		{
			name:             "defaults from global config",
			globalCfg:        &sandbox.GlobalConfig{Defaults: sandbox.GlobalDefaults{AutoShutdown: true, IdleHours: 48}},
			opts:             autoShutdownOpts{},
			wantAutoShutdown: true,
			wantIdleHours:    48,
		},
		{
			name:             "nil global config uses hardcoded defaults",
			globalCfg:        nil,
			opts:             autoShutdownOpts{},
			wantAutoShutdown: true,
			wantIdleHours:    48,
		},
		{
			name:             "global config with autoShutdown false",
			globalCfg:        &sandbox.GlobalConfig{Defaults: sandbox.GlobalDefaults{AutoShutdown: false, IdleHours: 24}},
			opts:             autoShutdownOpts{},
			wantAutoShutdown: false,
			wantIdleHours:    24,
		},
		{
			name:             "--auto-shutdown flag overrides config",
			globalCfg:        &sandbox.GlobalConfig{Defaults: sandbox.GlobalDefaults{AutoShutdown: false, IdleHours: 48}},
			opts:             autoShutdownOpts{autoShutdown: boolPtr(true)},
			wantAutoShutdown: true,
			wantIdleHours:    48,
		},
		{
			name:             "--no-auto-shutdown takes precedence over --auto-shutdown",
			globalCfg:        &sandbox.GlobalConfig{Defaults: sandbox.GlobalDefaults{AutoShutdown: true, IdleHours: 48}},
			opts:             autoShutdownOpts{autoShutdown: boolPtr(true), noAutoShutdown: boolPtr(true)},
			wantAutoShutdown: false,
			wantIdleHours:    48,
		},
		{
			name:             "--no-auto-shutdown disables auto-shutdown",
			globalCfg:        &sandbox.GlobalConfig{Defaults: sandbox.GlobalDefaults{AutoShutdown: true, IdleHours: 48}},
			opts:             autoShutdownOpts{noAutoShutdown: boolPtr(true)},
			wantAutoShutdown: false,
			wantIdleHours:    48,
		},
		{
			name:             "--idle-hours flag overrides config",
			globalCfg:        &sandbox.GlobalConfig{Defaults: sandbox.GlobalDefaults{AutoShutdown: true, IdleHours: 48}},
			opts:             autoShutdownOpts{idleHours: intPtr(24)},
			wantAutoShutdown: true,
			wantIdleHours:    24,
		},
		{
			name:             "all flags set together",
			globalCfg:        &sandbox.GlobalConfig{Defaults: sandbox.GlobalDefaults{AutoShutdown: false, IdleHours: 48}},
			opts:             autoShutdownOpts{autoShutdown: boolPtr(true), idleHours: intPtr(12)},
			wantAutoShutdown: true,
			wantIdleHours:    12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAuto, gotHours := resolveAutoShutdown(tt.globalCfg, tt.opts)
			if gotAuto != tt.wantAutoShutdown {
				t.Errorf("autoShutdown = %v, want %v", gotAuto, tt.wantAutoShutdown)
			}
			if gotHours != tt.wantIdleHours {
				t.Errorf("idleHours = %d, want %d", gotHours, tt.wantIdleHours)
			}
		})
	}
}

func TestInjectAutoShutdownEnv(t *testing.T) {
	t.Run("auto-shutdown enabled injects both vars", func(t *testing.T) {
		env := map[string]string{"EXISTING": "val"}
		injectAutoShutdownEnv(env, true, 48)

		if env["HAL_AUTO_SHUTDOWN"] != "true" {
			t.Errorf("HAL_AUTO_SHUTDOWN = %q, want %q", env["HAL_AUTO_SHUTDOWN"], "true")
		}
		if env["HAL_IDLE_HOURS"] != "48" {
			t.Errorf("HAL_IDLE_HOURS = %q, want %q", env["HAL_IDLE_HOURS"], "48")
		}
		if env["EXISTING"] != "val" {
			t.Errorf("EXISTING = %q, want %q", env["EXISTING"], "val")
		}
	})

	t.Run("auto-shutdown disabled injects false and no idle hours", func(t *testing.T) {
		env := map[string]string{"HAL_IDLE_HOURS": "leftover"}
		injectAutoShutdownEnv(env, false, 48)

		if env["HAL_AUTO_SHUTDOWN"] != "false" {
			t.Errorf("HAL_AUTO_SHUTDOWN = %q, want %q", env["HAL_AUTO_SHUTDOWN"], "false")
		}
		if _, ok := env["HAL_IDLE_HOURS"]; ok {
			t.Errorf("HAL_IDLE_HOURS should not be present when auto-shutdown is disabled, got %q", env["HAL_IDLE_HOURS"])
		}
	})

	t.Run("custom idle hours", func(t *testing.T) {
		env := make(map[string]string)
		injectAutoShutdownEnv(env, true, 24)

		if env["HAL_IDLE_HOURS"] != "24" {
			t.Errorf("HAL_IDLE_HOURS = %q, want %q", env["HAL_IDLE_HOURS"], "24")
		}
	})
}

func TestRunSandboxStart_AutoShutdownDefaultsInjected(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-1"},
	}

	// Default: no flags set, global config defaults (autoShutdown=true, idleHours=48)
	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "sb", nil, autoShutdownOpts{}, &out, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}
	env := mock.createCalls[0].Env
	if env["HAL_AUTO_SHUTDOWN"] != "true" {
		t.Errorf("HAL_AUTO_SHUTDOWN = %q, want %q", env["HAL_AUTO_SHUTDOWN"], "true")
	}
	if env["HAL_IDLE_HOURS"] != "48" {
		t.Errorf("HAL_IDLE_HOURS = %q, want %q", env["HAL_IDLE_HOURS"], "48")
	}

	// Verify persisted state has auto-shutdown values
	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("failed to load instance: %v", err)
	}
	if !instance.AutoShutdown {
		t.Error("instance.AutoShutdown should be true")
	}
	if instance.IdleHours != 48 {
		t.Errorf("instance.IdleHours = %d, want 48", instance.IdleHours)
	}
}

func TestRunSandboxStart_NoAutoShutdownFlag(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-1"},
	}

	noAuto := true
	opts := autoShutdownOpts{noAutoShutdown: &noAuto}

	err := runSandboxStartWithDeps(dir, "sb", nil, opts, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	env := mock.createCalls[0].Env
	if env["HAL_AUTO_SHUTDOWN"] != "false" {
		t.Errorf("HAL_AUTO_SHUTDOWN = %q, want %q", env["HAL_AUTO_SHUTDOWN"], "false")
	}
	if _, ok := env["HAL_IDLE_HOURS"]; ok {
		t.Errorf("HAL_IDLE_HOURS should not be present when --no-auto-shutdown, got %q", env["HAL_IDLE_HOURS"])
	}

	// Verify persisted state reflects disabled auto-shutdown
	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("failed to load instance: %v", err)
	}
	if instance.AutoShutdown {
		t.Error("instance.AutoShutdown should be false")
	}
}

func TestRunSandboxStart_AutoShutdownFlagOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	globalDir := filepath.Join(dir, "globalcfg")
	t.Setenv("HAL_CONFIG_HOME", globalDir)

	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	sandboxCfg := &compound.SandboxConfig{
		Provider: "daytona",
		Env:      map[string]string{},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	// Global config has auto-shutdown disabled
	globalCfg := &sandbox.GlobalConfig{
		Provider: "daytona",
		Defaults: sandbox.GlobalDefaults{AutoShutdown: false, IdleHours: 24},
	}
	if err := sandbox.SaveGlobalConfig(globalCfg); err != nil {
		t.Fatal(err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-1"},
	}

	// --auto-shutdown flag should override the global config
	autoOn := true
	opts := autoShutdownOpts{autoShutdown: &autoOn}

	err := runSandboxStartWithDeps(dir, "sb", nil, opts, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	env := mock.createCalls[0].Env
	if env["HAL_AUTO_SHUTDOWN"] != "true" {
		t.Errorf("HAL_AUTO_SHUTDOWN = %q, want %q", env["HAL_AUTO_SHUTDOWN"], "true")
	}
	// idle-hours should still come from global config
	if env["HAL_IDLE_HOURS"] != "24" {
		t.Errorf("HAL_IDLE_HOURS = %q, want %q (from global config)", env["HAL_IDLE_HOURS"], "24")
	}
}

func TestRunSandboxStart_IdleHoursFlagOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	globalDir := filepath.Join(dir, "globalcfg")
	t.Setenv("HAL_CONFIG_HOME", globalDir)

	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	sandboxCfg := &compound.SandboxConfig{
		Provider: "daytona",
		Env:      map[string]string{},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	// Global config has default 48 hours
	globalCfg := &sandbox.GlobalConfig{
		Provider: "daytona",
		Defaults: sandbox.GlobalDefaults{AutoShutdown: true, IdleHours: 48},
	}
	if err := sandbox.SaveGlobalConfig(globalCfg); err != nil {
		t.Fatal(err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-1"},
	}

	// --idle-hours flag should override the global config
	hours := 12
	opts := autoShutdownOpts{idleHours: &hours}

	err := runSandboxStartWithDeps(dir, "sb", nil, opts, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	env := mock.createCalls[0].Env
	if env["HAL_AUTO_SHUTDOWN"] != "true" {
		t.Errorf("HAL_AUTO_SHUTDOWN = %q, want %q", env["HAL_AUTO_SHUTDOWN"], "true")
	}
	if env["HAL_IDLE_HOURS"] != "12" {
		t.Errorf("HAL_IDLE_HOURS = %q, want %q", env["HAL_IDLE_HOURS"], "12")
	}

	// Verify persisted state
	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("failed to load instance: %v", err)
	}
	if instance.IdleHours != 12 {
		t.Errorf("instance.IdleHours = %d, want 12", instance.IdleHours)
	}
}

func TestRunSandboxStart_AutoShutdownEnvPersistedInState(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-1"},
	}

	hours := 72
	autoOn := true
	opts := autoShutdownOpts{autoShutdown: &autoOn, idleHours: &hours}

	err := runSandboxStartWithDeps(dir, "sb", nil, opts, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("failed to load instance: %v", err)
	}
	if !instance.AutoShutdown {
		t.Error("instance.AutoShutdown should be true")
	}
	if instance.IdleHours != 72 {
		t.Errorf("instance.IdleHours = %d, want 72", instance.IdleHours)
	}
}
