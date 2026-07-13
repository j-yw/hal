package cmd

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
)

func TestResolveFactoryAutoExecutionProfileUsesHostEffectiveConfig(t *testing.T) {
	profile, err := resolveFactoryAutoExecutionProfile("/workspace/game", " Pi ", factoryRunDeps{
		loadAutoConfig: func(dir string) (*compound.AutoConfig, error) {
			if dir != "/workspace/game" {
				t.Fatalf("load auto config dir = %q", dir)
			}
			cfg := compound.DefaultAutoConfig()
			cfg.MaxIterations = 7
			return &cfg, nil
		},
		loadEngineConfig: func(dir, engineName string) *engine.EngineConfig {
			if dir != "/workspace/game" || engineName != "pi" {
				t.Fatalf("load engine config = %q/%q", dir, engineName)
			}
			return &engine.EngineConfig{
				Provider: " xai ",
				Model:    " grok-4.5 ",
				Timeout:  90 * time.Second,
			}
		},
	})
	if err != nil {
		t.Fatalf("resolveFactoryAutoExecutionProfile() error = %v", err)
	}
	want := factoryAutoExecutionProfile{
		Engine:        "pi",
		Provider:      "xai",
		Model:         "grok-4.5",
		Timeout:       90 * time.Second,
		MaxIterations: 7,
	}
	if *profile != want {
		t.Fatalf("profile = %#v, want %#v", *profile, want)
	}
}

func TestResolveFactoryAutoExecutionProfileUsesAutoDefaults(t *testing.T) {
	profile, err := resolveFactoryAutoExecutionProfile(t.TempDir(), "codex", factoryRunDeps{
		loadAutoConfig:   compound.LoadConfig,
		loadEngineConfig: func(string, string) *engine.EngineConfig { return nil },
	})
	if err != nil {
		t.Fatalf("resolveFactoryAutoExecutionProfile() error = %v", err)
	}
	if profile.Engine != "codex" || profile.MaxIterations != compound.DefaultAutoConfig().MaxIterations {
		t.Fatalf("profile = %#v, want codex with default max iterations", profile)
	}
	if profile.Provider != "" || profile.Model != "" || profile.Timeout != 0 {
		t.Fatalf("profile engine overrides = %#v, want unset", profile)
	}
}

func TestValidateFactoryAutoExecutionProfileRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		profile factoryAutoExecutionProfile
		want    string
	}{
		{name: "missing engine", profile: factoryAutoExecutionProfile{MaxIterations: 1}, want: "engine is required"},
		{name: "provider control", profile: factoryAutoExecutionProfile{Engine: "pi", Provider: "xai\nleak", MaxIterations: 1}, want: "provider is invalid"},
		{name: "model too long", profile: factoryAutoExecutionProfile{Engine: "pi", Model: strings.Repeat("m", factoryExecutionProfileMaxStringBytes+1), MaxIterations: 1}, want: "model is invalid"},
		{name: "negative timeout", profile: factoryAutoExecutionProfile{Engine: "pi", Timeout: -time.Second, MaxIterations: 1}, want: "timeout must be greater than 0"},
		{name: "missing max iterations", profile: factoryAutoExecutionProfile{Engine: "pi"}, want: "max iterations must be greater than 0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFactoryAutoExecutionProfile(tt.profile)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validate error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestFactoryAutoExecutionProfileFromEnvRequiresMarker(t *testing.T) {
	values := map[string]string{
		autoFactoryExecutionProfileEngineEnv:        "pi",
		autoFactoryExecutionProfileProviderEnv:      "xai",
		autoFactoryExecutionProfileModelEnv:         "grok-4.5",
		autoFactoryExecutionProfileTimeoutEnv:       "2m",
		autoFactoryExecutionProfileMaxIterationsEnv: "4",
	}
	lookup := func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
	profile, err := factoryAutoExecutionProfileFromEnv(lookup)
	if err != nil || profile != nil {
		t.Fatalf("profile without marker = %#v, err=%v; want nil", profile, err)
	}

	values[autoFactoryExecutionProfileMarkerEnv] = "1"
	profile, err = factoryAutoExecutionProfileFromEnv(lookup)
	if err != nil {
		t.Fatalf("profile with marker error = %v", err)
	}
	want := factoryAutoExecutionProfile{Engine: "pi", Provider: "xai", Model: "grok-4.5", Timeout: 2 * time.Minute, MaxIterations: 4}
	if *profile != want {
		t.Fatalf("profile = %#v, want %#v", *profile, want)
	}
}

func TestApplyFactoryAutoExecutionProfileOverridesRemoteConfigExactly(t *testing.T) {
	autoConfig := compound.DefaultAutoConfig()
	remoteConfig := &engine.EngineConfig{
		Provider: "stale-provider",
		Model:    "stale-model",
		Timeout:  8 * time.Hour,
	}
	profile := &factoryAutoExecutionProfile{
		Engine:        "pi",
		Provider:      "xai",
		Model:         "grok-4.5",
		Timeout:       45 * time.Second,
		MaxIterations: 5,
	}
	got, err := applyFactoryAutoExecutionProfile(&autoConfig, remoteConfig, "pi", profile)
	if err != nil {
		t.Fatalf("applyFactoryAutoExecutionProfile() error = %v", err)
	}
	if *got != (engine.EngineConfig{Provider: "xai", Model: "grok-4.5", Timeout: 45 * time.Second}) {
		t.Fatalf("engine config = %#v, want exact host profile", got)
	}
	if autoConfig.MaxIterations != 5 {
		t.Fatalf("auto max iterations = %d, want 5", autoConfig.MaxIterations)
	}
}

func TestApplyFactoryAutoExecutionProfileClearsStaleRemoteOverridesForHostDefaults(t *testing.T) {
	autoConfig := compound.DefaultAutoConfig()
	remoteConfig := &engine.EngineConfig{Provider: "stale-provider", Model: "stale-model", Timeout: time.Hour}
	profile := &factoryAutoExecutionProfile{Engine: "pi", MaxIterations: 3}

	got, err := applyFactoryAutoExecutionProfile(&autoConfig, remoteConfig, "pi", profile)
	if err != nil {
		t.Fatalf("applyFactoryAutoExecutionProfile() error = %v", err)
	}
	if got != nil {
		t.Fatalf("engine config = %#v, want nil engine defaults", got)
	}
	if autoConfig.MaxIterations != 3 {
		t.Fatalf("auto max iterations = %d, want 3", autoConfig.MaxIterations)
	}
}

func TestApplyFactoryAutoExecutionProfileWithoutMarkerPreservesLocalConfig(t *testing.T) {
	autoConfig := compound.DefaultAutoConfig()
	localConfig := &engine.EngineConfig{Provider: "xai", Model: "local-model", Timeout: time.Minute}
	got, err := applyFactoryAutoExecutionProfile(&autoConfig, localConfig, "pi", nil)
	if err != nil {
		t.Fatalf("applyFactoryAutoExecutionProfile() error = %v", err)
	}
	if got != localConfig {
		t.Fatalf("engine config pointer changed without factory profile")
	}
	if autoConfig.MaxIterations != compound.DefaultAutoConfig().MaxIterations {
		t.Fatalf("local auto max iterations changed to %d", autoConfig.MaxIterations)
	}
}

func TestRunAutoWithDirRejectsInvalidFactoryExecutionProfileAsJSONConfigError(t *testing.T) {
	t.Setenv(autoFactoryExecutionProfileMarkerEnv, "1")
	t.Setenv(autoFactoryExecutionProfileEngineEnv, "pi")
	t.Setenv(autoFactoryExecutionProfileMaxIterationsEnv, "0")

	cmd, out := newAutoTestCommand(t)
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json flag: %v", err)
	}
	err := runAutoWithDir(cmd, nil, t.TempDir())
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitCodeValidation {
		t.Fatalf("runAutoWithDir() error = %#v, want validation exit", err)
	}
	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal auto JSON: %v\n%s", err, out.String())
	}
	if result.OK || !strings.Contains(result.Error, "max iterations must be greater than 0") {
		t.Fatalf("auto result = %#v, want config validation failure", result)
	}
}

func TestRunAutoWithDirIgnoresFactoryOverrideVariablesWithoutMarker(t *testing.T) {
	t.Setenv(autoFactoryExecutionProfileMarkerEnv, "")
	t.Setenv(autoFactoryExecutionProfileEngineEnv, "pi")
	t.Setenv(autoFactoryExecutionProfileMaxIterationsEnv, "not-an-integer")

	cmd, _ := newAutoTestCommand(t)
	err := runAutoWithDir(cmd, nil, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "no auto source found") {
		t.Fatalf("runAutoWithDir() error = %v, want ordinary local source error", err)
	}
}
