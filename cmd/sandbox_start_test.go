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
	deleteCalls  []mockDeleteCall
	deleteErr    error
}

type mockCreateCall struct {
	Name string
	Env  map[string]string
}

type mockDeleteCall struct {
	Info *sandbox.ConnectInfo
}

func (m *mockProvider) Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	m.createCalls = append(m.createCalls, mockCreateCall{Name: name, Env: env})
	return m.createResult, m.createErr
}

func (m *mockProvider) Stop(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func (m *mockProvider) Delete(ctx context.Context, info *sandbox.ConnectInfo, out io.Writer) error {
	m.deleteCalls = append(m.deleteCalls, mockDeleteCall{Info: info})
	return m.deleteErr
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
	err := runSandboxStartWithDeps(dir, "", 0, false, "", "", nil, autoShutdownOpts{}, &out, mock, fakeBranchResolver("hal/feature-auth", nil))
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
	err := runSandboxStartWithDeps(dir, "my-sandbox", 0, false, "", "", nil, autoShutdownOpts{}, &out, mock, nil)
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

	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", cliEnv, autoShutdownOpts{}, io.Discard, mock, nil)
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
	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, autoShutdownOpts{}, io.Discard, mock, nil)
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
	err := runSandboxStartWithDeps(dir, "my-server", 0, false, "", "", nil, autoShutdownOpts{}, &out, mock, nil)
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

	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, autoShutdownOpts{}, io.Discard, mock, nil)
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

	err := runSandboxStartWithDeps(dir, "", 0, false, "", "", nil, autoShutdownOpts{}, io.Discard, mock, fakeBranchResolver("", fmt.Errorf("not on a branch")))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "could not determine sandbox name from git branch") {
		t.Errorf("error %q missing branch failure text", err.Error())
	}
}

func TestRunSandboxStart_HalDirMissing(t *testing.T) {
	dir := t.TempDir()

	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, autoShutdownOpts{}, io.Discard, nil, nil)
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

	if err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, autoShutdownOpts{}, io.Discard, nil, nil); err != nil {
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

	sandboxMigrate = func(projectDir string, _ io.Writer) error {
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

	sandboxMigrate = func(projectDir string, _ io.Writer) error {
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

	sandboxMigrate = func(projectDir string, _ io.Writer) error {
		if projectDir != dir {
			t.Fatalf("projectDir = %q, want %q", projectDir, dir)
		}
		return fmt.Errorf("migration unavailable")
	}

	mock := &mockProvider{createResult: &sandbox.SandboxResult{Name: "sb"}}

	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, autoShutdownOpts{}, &out, mock, nil)
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

	if err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, autoShutdownOpts{}, io.Discard, nil, nil); err != nil {
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

	if err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, autoShutdownOpts{}, io.Discard, nil, nil); err != nil {
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
	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, autoShutdownOpts{}, &out, mock, nil)
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

	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, opts, io.Discard, mock, nil)
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

	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, opts, io.Discard, mock, nil)
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

	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, opts, io.Discard, mock, nil)
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

	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, opts, io.Discard, mock, nil)
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

// --- Batch creation tests (US-019) ---

func TestBatchPreflight_Success(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", dir)

	targets, err := batchPreflight("worker", 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"worker-01", "worker-02", "worker-03"}
	if len(targets) != len(want) {
		t.Fatalf("got %d targets, want %d", len(targets), len(want))
	}
	for i, name := range targets {
		if name != want[i] {
			t.Errorf("targets[%d] = %q, want %q", i, name, want[i])
		}
	}
}

func TestBatchPreflight_CollisionDetected(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", dir)

	// Pre-register worker-02 in the global registry
	existing := &sandbox.SandboxState{
		Name:   "worker-02",
		Status: sandbox.StatusRunning,
	}
	if err := sandbox.SaveInstance(existing); err != nil {
		t.Fatalf("setup: save existing instance: %v", err)
	}

	_, err := batchPreflight("worker", 3)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "batch preflight failed") {
		t.Errorf("error %q should contain 'batch preflight failed'", err.Error())
	}
	if !strings.Contains(err.Error(), "worker-02") {
		t.Errorf("error %q should list colliding name 'worker-02'", err.Error())
	}
}

func TestBatchPreflight_MultipleCollisions(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", dir)

	// Pre-register worker-01 and worker-03
	for _, name := range []string{"worker-01", "worker-03"} {
		existing := &sandbox.SandboxState{
			Name:   name,
			Status: sandbox.StatusRunning,
		}
		if err := sandbox.SaveInstance(existing); err != nil {
			t.Fatalf("setup: save %s: %v", name, err)
		}
	}

	_, err := batchPreflight("worker", 3)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "worker-01") {
		t.Errorf("error %q should list 'worker-01'", err.Error())
	}
	if !strings.Contains(err.Error(), "worker-03") {
		t.Errorf("error %q should list 'worker-03'", err.Error())
	}
}

func TestBatchPreflight_InvalidBaseName(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", dir)

	_, err := batchPreflight("INVALID", 3)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "generating batch names") {
		t.Errorf("error %q should contain 'generating batch names'", err.Error())
	}
}

func TestRunSandboxStart_BatchCreatesAll(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{ID: "ws-batch", IP: "10.0.0.1"},
	}

	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "worker", 3, false, "", "", nil, autoShutdownOpts{}, &out, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have called Create 3 times
	if len(mock.createCalls) != 3 {
		t.Fatalf("expected 3 Create calls, got %d", len(mock.createCalls))
	}

	// Verify each target name
	wantNames := []string{"worker-01", "worker-02", "worker-03"}
	for i, call := range mock.createCalls {
		if call.Name != wantNames[i] {
			t.Errorf("createCalls[%d].Name = %q, want %q", i, call.Name, wantNames[i])
		}
	}

	// Verify all are in the global registry
	for _, name := range wantNames {
		instance, err := sandbox.LoadInstance(name)
		if err != nil {
			t.Errorf("instance %q not in registry: %v", name, err)
			continue
		}
		if instance.Status != sandbox.StatusRunning {
			t.Errorf("instance %q status = %q, want %q", name, instance.Status, sandbox.StatusRunning)
		}
	}

	// Verify output mentions batch creation
	output := out.String()
	if !strings.Contains(output, "Creating 3 sandboxes") {
		t.Errorf("output should mention batch count: %q", output)
	}
}

func TestRunSandboxStart_BatchPreflightBlocksCreate(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	// Pre-register worker-02 to trigger collision
	existing := &sandbox.SandboxState{
		Name:   "worker-02",
		Status: sandbox.StatusRunning,
	}
	if err := sandbox.SaveInstance(existing); err != nil {
		t.Fatalf("setup: save existing: %v", err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{ID: "ws-batch"},
	}

	err := runSandboxStartWithDeps(dir, "worker", 3, false, "", "", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "batch preflight failed") {
		t.Errorf("error %q should contain 'batch preflight failed'", err.Error())
	}

	// provider.Create should NOT have been called
	if len(mock.createCalls) != 0 {
		t.Errorf("expected 0 Create calls (preflight should block), got %d", len(mock.createCalls))
	}
}

func TestRunSandboxStart_CountOneIsSingle(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-1"},
	}

	var out bytes.Buffer
	// count=1 should behave as single sandbox creation
	err := runSandboxStartWithDeps(dir, "sb", 1, false, "", "", nil, autoShutdownOpts{}, &out, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}
	if mock.createCalls[0].Name != "sb" {
		t.Errorf("Create name = %q, want %q", mock.createCalls[0].Name, "sb")
	}

	// Should be in registry as "sb", not "sb-01"
	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("instance not in registry: %v", err)
	}
	if instance.Name != "sb" {
		t.Errorf("instance.Name = %q, want %q", instance.Name, "sb")
	}
}

func TestSandboxStartCommandCountFlag(t *testing.T) {
	if sandboxStartCmd.Flags().Lookup("count") == nil {
		t.Fatal("--count flag should exist")
	}
}

func TestRunSandboxStart_BatchNameFromBranch(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{ID: "ws-batch"},
	}

	var out bytes.Buffer
	// No explicit name; branch provides the base
	err := runSandboxStartWithDeps(dir, "", 2, false, "", "", nil, autoShutdownOpts{}, &out, mock, fakeBranchResolver("hal/api-service", nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 2 {
		t.Fatalf("expected 2 Create calls, got %d", len(mock.createCalls))
	}
	if mock.createCalls[0].Name != "hal-api-service-01" {
		t.Errorf("createCalls[0].Name = %q, want %q", mock.createCalls[0].Name, "hal-api-service-01")
	}
	if mock.createCalls[1].Name != "hal-api-service-02" {
		t.Errorf("createCalls[1].Name = %q, want %q", mock.createCalls[1].Name, "hal-api-service-02")
	}
}

// --- Flag wiring tests (US-020) ---

func TestSandboxStartCommandAllFlags(t *testing.T) {
	flags := []string{"name", "count", "size", "repo", "env", "auto-shutdown", "no-auto-shutdown", "idle-hours"}
	for _, name := range flags {
		if sandboxStartCmd.Flags().Lookup(name) == nil {
			t.Errorf("--%s flag should exist", name)
		}
	}
	// Verify short flags
	if sandboxStartCmd.Flags().ShorthandLookup("n") == nil {
		t.Error("-n shorthand should exist for --name")
	}
	if sandboxStartCmd.Flags().ShorthandLookup("s") == nil {
		t.Error("-s shorthand should exist for --size")
	}
	if sandboxStartCmd.Flags().ShorthandLookup("r") == nil {
		t.Error("-r shorthand should exist for --repo")
	}
	if sandboxStartCmd.Flags().ShorthandLookup("e") == nil {
		t.Error("-e shorthand should exist for --env")
	}
	// Verify usage text is non-empty
	for _, name := range flags {
		f := sandboxStartCmd.Flags().Lookup(name)
		if f.Usage == "" {
			t.Errorf("--%s flag should have a usage description", name)
		}
	}
}

func TestRunSandboxStart_SizeOverridesHetzner(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(dir, "globalcfg"))
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	sandboxCfg := &compound.SandboxConfig{
		Provider: "hetzner",
		Env:      map[string]string{},
		Hetzner:  compound.HetznerConfig{ServerType: "cx22"},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	originalResolveProvider := resolveSandboxProvider
	t.Cleanup(func() { resolveSandboxProvider = originalResolveProvider })

	mock := &mockProvider{createResult: &sandbox.SandboxResult{Name: "sb"}}
	var gotCfg sandbox.ProviderConfig
	resolveSandboxProvider = func(provider string, cfg sandbox.ProviderConfig) (sandbox.Provider, error) {
		gotCfg = cfg
		return mock, nil
	}

	// --size cx42 should override config's cx22
	if err := runSandboxStartWithDeps(dir, "sb", 0, false, "cx42", "", nil, autoShutdownOpts{}, io.Discard, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotCfg.HetznerServerType != "cx42" {
		t.Errorf("HetznerServerType = %q, want %q (from --size override)", gotCfg.HetznerServerType, "cx42")
	}

	// Verify size is persisted in state
	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("failed to load instance: %v", err)
	}
	if instance.Size != "cx42" {
		t.Errorf("instance.Size = %q, want %q", instance.Size, "cx42")
	}
}

func TestRunSandboxStart_SizeOverridesDigitalOcean(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(dir, "globalcfg"))
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	sandboxCfg := &compound.SandboxConfig{
		Provider:     "digitalocean",
		Env:          map[string]string{},
		DigitalOcean: compound.DigitalOceanConfig{Size: "s-1vcpu-1gb"},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	originalResolveProvider := resolveSandboxProvider
	t.Cleanup(func() { resolveSandboxProvider = originalResolveProvider })

	mock := &mockProvider{createResult: &sandbox.SandboxResult{Name: "sb"}}
	var gotCfg sandbox.ProviderConfig
	resolveSandboxProvider = func(provider string, cfg sandbox.ProviderConfig) (sandbox.Provider, error) {
		gotCfg = cfg
		return mock, nil
	}

	if err := runSandboxStartWithDeps(dir, "sb", 0, false, "s-2vcpu-4gb", "", nil, autoShutdownOpts{}, io.Discard, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotCfg.DigitalOceanSize != "s-2vcpu-4gb" {
		t.Errorf("DigitalOceanSize = %q, want %q (from --size override)", gotCfg.DigitalOceanSize, "s-2vcpu-4gb")
	}
}

func TestRunSandboxStart_SizeOverridesLightsail(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", filepath.Join(dir, "globalcfg"))
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	sandboxCfg := &compound.SandboxConfig{
		Provider:  "lightsail",
		Env:       map[string]string{},
		Lightsail: compound.LightsailConfig{Bundle: "small_3_0"},
	}
	if err := compound.SaveSandboxConfig(dir, sandboxCfg); err != nil {
		t.Fatal(err)
	}

	originalResolveProvider := resolveSandboxProvider
	t.Cleanup(func() { resolveSandboxProvider = originalResolveProvider })

	mock := &mockProvider{createResult: &sandbox.SandboxResult{Name: "sb"}}
	var gotCfg sandbox.ProviderConfig
	resolveSandboxProvider = func(provider string, cfg sandbox.ProviderConfig) (sandbox.Provider, error) {
		gotCfg = cfg
		return mock, nil
	}

	if err := runSandboxStartWithDeps(dir, "sb", 0, false, "medium_3_0", "", nil, autoShutdownOpts{}, io.Discard, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if gotCfg.LightsailBundle != "medium_3_0" {
		t.Errorf("LightsailBundle = %q, want %q (from --size override)", gotCfg.LightsailBundle, "medium_3_0")
	}
}

func TestRunSandboxStart_RepoStoredInState(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-1"},
	}

	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "github.com/org/repo", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("failed to load instance: %v", err)
	}
	if instance.Repo != "github.com/org/repo" {
		t.Errorf("instance.Repo = %q, want %q", instance.Repo, "github.com/org/repo")
	}
}

func TestRunSandboxStart_NoRepoByDefault(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-1"},
	}

	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("failed to load instance: %v", err)
	}
	if instance.Repo != "" {
		t.Errorf("instance.Repo = %q, want empty string (no --repo)", instance.Repo)
	}
}

func TestRunSandboxStart_NoSizeByDefault(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-1"},
	}

	err := runSandboxStartWithDeps(dir, "sb", 0, false, "", "", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("failed to load instance: %v", err)
	}
	if instance.Size != "" {
		t.Errorf("instance.Size = %q, want empty string (no --size)", instance.Size)
	}
}

func TestRunSandboxStart_SizeAndRepoTogether(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-1"},
	}

	err := runSandboxStartWithDeps(dir, "sb", 0, false, "cx42", "github.com/org/app", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("failed to load instance: %v", err)
	}
	if instance.Size != "cx42" {
		t.Errorf("instance.Size = %q, want %q", instance.Size, "cx42")
	}
	if instance.Repo != "github.com/org/app" {
		t.Errorf("instance.Repo = %q, want %q", instance.Repo, "github.com/org/app")
	}
}

func TestRunSandboxStart_SizePersistedInBatchState(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{ID: "ws-batch"},
	}

	err := runSandboxStartWithDeps(dir, "worker", 2, false, "cx42", "github.com/org/app", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify both batch instances have size and repo persisted
	for _, name := range []string{"worker-01", "worker-02"} {
		instance, err := sandbox.LoadInstance(name)
		if err != nil {
			t.Fatalf("failed to load instance %q: %v", name, err)
		}
		if instance.Size != "cx42" {
			t.Errorf("%s: Size = %q, want %q", name, instance.Size, "cx42")
		}
		if instance.Repo != "github.com/org/app" {
			t.Errorf("%s: Repo = %q, want %q", name, instance.Repo, "github.com/org/app")
		}
	}
}

func TestRunSandboxStart_ViaRunSandboxStart(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-1"},
	}

	deps := &sandboxStartDeps{
		provider:  mock,
		getBranch: nil,
	}

	var out bytes.Buffer
	err := runSandboxStart(dir, "sb", 0, false, "cx42", "github.com/org/repo", nil, autoShutdownOpts{}, &out, deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}

	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("failed to load instance: %v", err)
	}
	if instance.Size != "cx42" {
		t.Errorf("instance.Size = %q, want %q", instance.Size, "cx42")
	}
	if instance.Repo != "github.com/org/repo" {
		t.Errorf("instance.Repo = %q, want %q", instance.Repo, "github.com/org/repo")
	}
}

func TestRunSandboxStart_ViaRunSandboxStartNilDeps(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	// With nil deps, runSandboxStart passes nil provider and nil getBranch
	// This should fail trying to resolve provider since no daytona config
	err := runSandboxStart(dir, "sb", 0, false, "", "", nil, autoShutdownOpts{}, io.Discard, nil)
	// Expected: resolving provider errors because daytona config is incomplete
	if err == nil {
		t.Fatal("expected error with nil deps (no provider configured), got nil")
	}
}

func TestApplySizeOverride(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		size     string
		check    func(t *testing.T, cfg *compound.SandboxConfig)
	}{
		{
			name:     "hetzner sets ServerType",
			provider: "hetzner",
			size:     "cx42",
			check: func(t *testing.T, cfg *compound.SandboxConfig) {
				if cfg.Hetzner.ServerType != "cx42" {
					t.Errorf("Hetzner.ServerType = %q, want %q", cfg.Hetzner.ServerType, "cx42")
				}
			},
		},
		{
			name:     "digitalocean sets Size",
			provider: "digitalocean",
			size:     "s-2vcpu-4gb",
			check: func(t *testing.T, cfg *compound.SandboxConfig) {
				if cfg.DigitalOcean.Size != "s-2vcpu-4gb" {
					t.Errorf("DigitalOcean.Size = %q, want %q", cfg.DigitalOcean.Size, "s-2vcpu-4gb")
				}
			},
		},
		{
			name:     "lightsail sets Bundle",
			provider: "lightsail",
			size:     "medium_3_0",
			check: func(t *testing.T, cfg *compound.SandboxConfig) {
				if cfg.Lightsail.Bundle != "medium_3_0" {
					t.Errorf("Lightsail.Bundle = %q, want %q", cfg.Lightsail.Bundle, "medium_3_0")
				}
			},
		},
		{
			name:     "daytona is no-op",
			provider: "daytona",
			size:     "large",
			check: func(t *testing.T, cfg *compound.SandboxConfig) {
				// Daytona does not have a size field; verify no panic and no side effects
				if cfg.Hetzner.ServerType != "" || cfg.DigitalOcean.Size != "" || cfg.Lightsail.Bundle != "" {
					t.Error("unexpected side effect on non-active provider fields")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &compound.SandboxConfig{Provider: tt.provider}
			applySizeOverride(cfg, tt.size)
			tt.check(t, cfg)
		})
	}
}

// --- Collision and --force tests (US-035) ---

func TestRunSandboxStart_CollisionWithoutForce(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	// Pre-register a sandbox with the same name
	existing := &sandbox.SandboxState{
		Name:     "my-sandbox",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	if err := sandbox.SaveInstance(existing); err != nil {
		t.Fatalf("setup: save existing instance: %v", err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "my-sandbox", ID: "ws-new"},
	}

	err := runSandboxStartWithDeps(dir, "my-sandbox", 0, false, "", "", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Exact error message required by acceptance criteria
	want := `sandbox "my-sandbox" already exists`
	if err.Error() != want {
		t.Errorf("error = %q, want exact %q", err.Error(), want)
	}

	// provider.Create should NOT have been called
	if len(mock.createCalls) != 0 {
		t.Errorf("expected 0 Create calls, got %d", len(mock.createCalls))
	}

	// provider.Delete should NOT have been called
	if len(mock.deleteCalls) != 0 {
		t.Errorf("expected 0 Delete calls, got %d", len(mock.deleteCalls))
	}
}

func TestRunSandboxStart_ForceReplaceSuccess(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	// Pre-register a sandbox with the same name
	existing := &sandbox.SandboxState{
		ID:          "old-id-1234",
		Name:        "my-sandbox",
		Provider:    "daytona",
		WorkspaceID: "ws-old",
		IP:          "10.0.0.1",
		Status:      sandbox.StatusRunning,
	}
	if err := sandbox.SaveInstance(existing); err != nil {
		t.Fatalf("setup: save existing instance: %v", err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "my-sandbox", ID: "ws-new", IP: "10.0.0.2"},
	}

	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "my-sandbox", 0, true, "", "", nil, autoShutdownOpts{}, &out, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// provider.Delete should have been called once with old sandbox info
	if len(mock.deleteCalls) != 1 {
		t.Fatalf("expected 1 Delete call, got %d", len(mock.deleteCalls))
	}
	if mock.deleteCalls[0].Info.Name != "my-sandbox" {
		t.Errorf("Delete info.Name = %q, want %q", mock.deleteCalls[0].Info.Name, "my-sandbox")
	}

	// provider.Create should have been called once
	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}
	if mock.createCalls[0].Name != "my-sandbox" {
		t.Errorf("Create name = %q, want %q", mock.createCalls[0].Name, "my-sandbox")
	}

	// Registry should have the NEW entry
	instance, err := sandbox.LoadInstance("my-sandbox")
	if err != nil {
		t.Fatalf("failed to load from registry: %v", err)
	}
	if instance.ID == "old-id-1234" {
		t.Error("instance.ID should be a new UUIDv7, not the old ID")
	}
	if !uuidV7Pattern.MatchString(instance.ID) {
		t.Errorf("instance.ID = %q, want UUIDv7 format", instance.ID)
	}
	if instance.WorkspaceID != "ws-new" {
		t.Errorf("instance.WorkspaceID = %q, want %q", instance.WorkspaceID, "ws-new")
	}
	if instance.IP != "10.0.0.2" {
		t.Errorf("instance.IP = %q, want %q", instance.IP, "10.0.0.2")
	}
	if instance.Status != sandbox.StatusRunning {
		t.Errorf("instance.Status = %q, want %q", instance.Status, sandbox.StatusRunning)
	}

	// Output should mention replacement
	output := out.String()
	if !strings.Contains(output, "Replacing existing sandbox") {
		t.Errorf("output should mention replacement: %q", output)
	}
	if !strings.Contains(output, "Sandbox started") {
		t.Errorf("output should confirm new sandbox started: %q", output)
	}
}

func TestRunSandboxStart_ForceDeleteFails(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	// Pre-register a sandbox with the same name
	existing := &sandbox.SandboxState{
		ID:       "old-id",
		Name:     "my-sandbox",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	if err := sandbox.SaveInstance(existing); err != nil {
		t.Fatalf("setup: save existing instance: %v", err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "my-sandbox", ID: "ws-new"},
		deleteErr:    fmt.Errorf("provider API error"),
	}

	err := runSandboxStartWithDeps(dir, "my-sandbox", 0, true, "", "", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "force-delete of existing sandbox") {
		t.Errorf("error %q should mention force-delete failure", err.Error())
	}
	if !strings.Contains(err.Error(), "provider API error") {
		t.Errorf("error %q should contain original error", err.Error())
	}

	// provider.Create should NOT have been called
	if len(mock.createCalls) != 0 {
		t.Errorf("expected 0 Create calls after failed force-delete, got %d", len(mock.createCalls))
	}

	// Existing entry should still be in the registry
	instance, err := sandbox.LoadInstance("my-sandbox")
	if err != nil {
		t.Fatalf("existing entry should remain in registry: %v", err)
	}
	if instance.ID != "old-id" {
		t.Errorf("existing entry should be unchanged, ID = %q, want %q", instance.ID, "old-id")
	}
}

func TestRunSandboxStart_ForceNewID(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	oldID := "01234567-89ab-7cde-8f01-234567890abc"
	existing := &sandbox.SandboxState{
		ID:       oldID,
		Name:     "dev",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	if err := sandbox.SaveInstance(existing); err != nil {
		t.Fatalf("setup: save existing: %v", err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "dev", ID: "ws-new"},
	}

	err := runSandboxStartWithDeps(dir, "dev", 0, true, "", "", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	instance, err := sandbox.LoadInstance("dev")
	if err != nil {
		t.Fatalf("failed to load from registry: %v", err)
	}

	// New entry must have a different UUIDv7 ID
	if instance.ID == oldID {
		t.Error("force-replaced sandbox should have a new ID, got the old one")
	}
	if !uuidV7Pattern.MatchString(instance.ID) {
		t.Errorf("instance.ID = %q, want UUIDv7 format", instance.ID)
	}
}

func TestRunSandboxStart_NoCollisionNoForce(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "fresh-sandbox", ID: "ws-1"},
	}

	var out bytes.Buffer
	// No existing sandbox, no --force — should succeed normally
	err := runSandboxStartWithDeps(dir, "fresh-sandbox", 0, false, "", "", nil, autoShutdownOpts{}, &out, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}
	if len(mock.deleteCalls) != 0 {
		t.Errorf("expected 0 Delete calls (no collision), got %d", len(mock.deleteCalls))
	}

	instance, err := sandbox.LoadInstance("fresh-sandbox")
	if err != nil {
		t.Fatalf("instance should be in registry: %v", err)
	}
	if instance.Name != "fresh-sandbox" {
		t.Errorf("instance.Name = %q, want %q", instance.Name, "fresh-sandbox")
	}
}

func TestRunSandboxStart_ForceNoExistingIsNoop(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "new-sandbox", ID: "ws-1"},
	}

	// --force with no existing sandbox should still create normally
	err := runSandboxStartWithDeps(dir, "new-sandbox", 0, true, "", "", nil, autoShutdownOpts{}, io.Discard, mock, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}
	// No delete needed since nothing exists
	if len(mock.deleteCalls) != 0 {
		t.Errorf("expected 0 Delete calls (nothing to replace), got %d", len(mock.deleteCalls))
	}
}

func TestSandboxStartCommandForceFlag(t *testing.T) {
	f := sandboxStartCmd.Flags().Lookup("force")
	if f == nil {
		t.Fatal("--force flag should exist")
	}
	if f.Usage == "" {
		t.Error("--force flag should have a usage description")
	}
	if sandboxStartCmd.Flags().ShorthandLookup("f") == nil {
		t.Error("-f shorthand should exist for --force")
	}
}

func TestRunSandboxStart_ForceViaRunSandboxStart(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir)

	// Pre-register existing sandbox
	existing := &sandbox.SandboxState{
		ID:       "old-id",
		Name:     "sb",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	if err := sandbox.SaveInstance(existing); err != nil {
		t.Fatalf("setup: save existing: %v", err)
	}

	mock := &mockProvider{
		createResult: &sandbox.SandboxResult{Name: "sb", ID: "ws-new"},
	}
	deps := &sandboxStartDeps{provider: mock}

	var out bytes.Buffer
	err := runSandboxStart(dir, "sb", 0, true, "", "", nil, autoShutdownOpts{}, &out, deps)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(mock.deleteCalls) != 1 {
		t.Fatalf("expected 1 Delete call, got %d", len(mock.deleteCalls))
	}
	if len(mock.createCalls) != 1 {
		t.Fatalf("expected 1 Create call, got %d", len(mock.createCalls))
	}

	instance, err := sandbox.LoadInstance("sb")
	if err != nil {
		t.Fatalf("failed to load from registry: %v", err)
	}
	if instance.ID == "old-id" {
		t.Error("should have new ID after force-replace")
	}
}
