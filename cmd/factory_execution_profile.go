package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
)

const (
	autoFactoryExecutionProfileMarkerEnv        = "HAL_FACTORY_EXECUTION_PROFILE"
	autoFactoryExecutionProfileEngineEnv        = "HAL_FACTORY_ENGINE"
	autoFactoryExecutionProfileProviderEnv      = "HAL_FACTORY_ENGINE_PROVIDER"
	autoFactoryExecutionProfileModelEnv         = "HAL_FACTORY_ENGINE_MODEL"
	autoFactoryExecutionProfileTimeoutEnv       = "HAL_FACTORY_ENGINE_TIMEOUT"
	autoFactoryExecutionProfileMaxIterationsEnv = "HAL_FACTORY_AUTO_MAX_ITERATIONS"

	factoryExecutionProfileMaxStringBytes = 256
)

// factoryAutoExecutionProfile is the narrow, non-secret configuration contract
// carried from a factory host into its sandboxed hal auto process.
type factoryAutoExecutionProfile struct {
	Engine        string
	Provider      string
	Model         string
	Timeout       time.Duration
	MaxIterations int
}

func resolveFactoryAutoExecutionProfile(dir, engineName string, deps factoryRunDeps) (*factoryAutoExecutionProfile, error) {
	loadAutoConfig := deps.loadAutoConfig
	if loadAutoConfig == nil {
		loadAutoConfig = defaultFactoryRunDeps.loadAutoConfig
	}
	autoConfig, err := loadAutoConfig(dir)
	if err != nil {
		return nil, factoryRunRedactedError{
			message: "load factory auto execution profile from .hal/config.yaml: invalid configuration",
			cause:   err,
		}
	}
	if autoConfig == nil {
		return nil, fmt.Errorf("load factory auto execution profile: config is required")
	}

	profile := factoryAutoExecutionProfile{
		Engine:        normalizeFactoryRunEngineName(engineName),
		MaxIterations: autoConfig.MaxIterations,
	}
	loadEngineConfig := deps.loadEngineConfig
	if loadEngineConfig == nil {
		loadEngineConfig = defaultFactoryRunDeps.loadEngineConfig
	}
	if engineConfig := loadEngineConfig(dir, profile.Engine); engineConfig != nil {
		profile.Provider = strings.TrimSpace(engineConfig.Provider)
		profile.Model = strings.TrimSpace(engineConfig.Model)
		profile.Timeout = engineConfig.Timeout
	}
	if err := validateFactoryAutoExecutionProfile(profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func validateFactoryAutoExecutionProfile(profile factoryAutoExecutionProfile) error {
	if err := validateFactoryExecutionProfileString("engine", profile.Engine, true); err != nil {
		return err
	}
	if err := validateFactoryExecutionProfileString("provider", profile.Provider, false); err != nil {
		return err
	}
	if err := validateFactoryExecutionProfileString("model", profile.Model, false); err != nil {
		return err
	}
	if profile.Timeout < 0 {
		return fmt.Errorf("factory execution profile timeout must be greater than 0 when set")
	}
	if profile.MaxIterations <= 0 {
		return fmt.Errorf("factory execution profile max iterations must be greater than 0")
	}
	return nil
}

func validateFactoryExecutionProfileString(field, value string, required bool) error {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return fmt.Errorf("factory execution profile %s is required", field)
		}
		return nil
	}
	if len(value) > factoryExecutionProfileMaxStringBytes || !utf8.ValidString(value) {
		return fmt.Errorf("factory execution profile %s is invalid", field)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("factory execution profile %s is invalid", field)
		}
	}
	return nil
}

func factoryAutoExecutionProfileFromEnv(lookupEnv func(string) (string, bool)) (*factoryAutoExecutionProfile, error) {
	if lookupEnv == nil {
		return nil, nil
	}
	marker, set := lookupEnv(autoFactoryExecutionProfileMarkerEnv)
	if !set || strings.TrimSpace(marker) == "" {
		return nil, nil
	}
	if strings.TrimSpace(marker) != "1" {
		return nil, fmt.Errorf("%s must be 1", autoFactoryExecutionProfileMarkerEnv)
	}

	profile := factoryAutoExecutionProfile{}
	profile.Engine = lookupFactoryExecutionProfileEnv(lookupEnv, autoFactoryExecutionProfileEngineEnv)
	profile.Provider = lookupFactoryExecutionProfileEnv(lookupEnv, autoFactoryExecutionProfileProviderEnv)
	profile.Model = lookupFactoryExecutionProfileEnv(lookupEnv, autoFactoryExecutionProfileModelEnv)

	timeoutValue := lookupFactoryExecutionProfileEnv(lookupEnv, autoFactoryExecutionProfileTimeoutEnv)
	if timeoutValue != "" {
		timeout, err := time.ParseDuration(timeoutValue)
		if err != nil || timeout <= 0 {
			return nil, fmt.Errorf("%s must be a positive duration", autoFactoryExecutionProfileTimeoutEnv)
		}
		profile.Timeout = timeout
	}
	maxIterationsValue := lookupFactoryExecutionProfileEnv(lookupEnv, autoFactoryExecutionProfileMaxIterationsEnv)
	maxIterations, err := strconv.Atoi(maxIterationsValue)
	if err != nil {
		return nil, fmt.Errorf("%s must be a positive integer", autoFactoryExecutionProfileMaxIterationsEnv)
	}
	profile.MaxIterations = maxIterations

	if err := validateFactoryAutoExecutionProfile(profile); err != nil {
		return nil, err
	}
	return &profile, nil
}

func lookupFactoryExecutionProfileEnv(lookupEnv func(string) (string, bool), key string) string {
	value, _ := lookupEnv(key)
	return strings.TrimSpace(value)
}

func applyFactoryAutoExecutionProfile(autoConfig *compound.AutoConfig, engineConfig *engine.EngineConfig, selectedEngine string, profile *factoryAutoExecutionProfile) (*engine.EngineConfig, error) {
	if profile == nil {
		return engineConfig, nil
	}
	if err := validateFactoryAutoExecutionProfile(*profile); err != nil {
		return nil, err
	}
	selectedEngine = normalizeFactoryRunEngineName(selectedEngine)
	if selectedEngine != profile.Engine {
		return nil, fmt.Errorf("factory execution profile engine %q does not match selected engine %q", profile.Engine, selectedEngine)
	}
	if autoConfig == nil {
		return nil, fmt.Errorf("factory execution profile auto config is required")
	}
	autoConfig.MaxIterations = profile.MaxIterations

	// A factory profile is authoritative. Values omitted on the host mean use
	// engine defaults, not stale engine overrides from the remote checkout.
	merged := &engine.EngineConfig{}
	if profile.Provider != "" {
		merged.Provider = profile.Provider
	}
	if profile.Model != "" {
		merged.Model = profile.Model
	}
	if profile.Timeout > 0 {
		merged.Timeout = profile.Timeout
	}
	if merged.Provider == "" && merged.Model == "" && merged.Timeout == 0 {
		return nil, nil
	}
	return merged, nil
}

func factoryAutoExecutionProfileEnv(profile *factoryAutoExecutionProfile) []string {
	if profile == nil {
		return nil
	}
	env := []string{
		autoFactoryExecutionProfileMarkerEnv + "=" + shellQuote("1"),
		autoFactoryExecutionProfileEngineEnv + "=" + shellQuote(profile.Engine),
		autoFactoryExecutionProfileMaxIterationsEnv + "=" + shellQuote(strconv.Itoa(profile.MaxIterations)),
	}
	if profile.Provider != "" {
		env = append(env, autoFactoryExecutionProfileProviderEnv+"="+shellQuote(profile.Provider))
	}
	if profile.Model != "" {
		env = append(env, autoFactoryExecutionProfileModelEnv+"="+shellQuote(profile.Model))
	}
	if profile.Timeout > 0 {
		env = append(env, autoFactoryExecutionProfileTimeoutEnv+"="+shellQuote(profile.Timeout.String()))
	}
	return env
}
