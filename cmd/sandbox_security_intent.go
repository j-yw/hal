package cmd

import (
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

type configuredSandboxSecuritySettings struct {
	Request           sandbox.SecurityEvaluationRequest
	ReadinessGateMode sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode
}

func loadConfiguredSandboxSecurityRequest(projectDir, runtimeDriver string) (sandbox.SecurityEvaluationRequest, error) {
	settings, err := loadConfiguredSandboxSecuritySettings(projectDir, runtimeDriver)
	if err != nil {
		return sandbox.SecurityEvaluationRequest{}, err
	}
	return settings.Request, nil
}

func loadConfiguredSandboxSecuritySettings(projectDir, runtimeDriver string) (configuredSandboxSecuritySettings, error) {
	cfg, err := compound.LoadSandboxConfig(projectDir)
	if err != nil {
		return configuredSandboxSecuritySettings{}, sanitizeSandboxSecurityConfigLoadError(projectDir, err)
	}
	return configuredSandboxSecuritySettings{
		Request:           sandboxSecurityRequestFromConfig(cfg, runtimeDriver),
		ReadinessGateMode: sandboxSecurityReadinessGateModeFromConfig(cfg),
	}, nil
}

func sandboxSecurityRequestFromConfig(cfg *compound.SandboxConfig, runtimeDriver string) sandbox.SecurityEvaluationRequest {
	intent := sandbox.SandboxSecurityIntent{
		RuntimeDriver:         runtimeDriver,
		CompatibilityAuthSync: true,
	}
	if cfg != nil {
		if cfg.NetworkPolicy != nil {
			networkPolicy := sandbox.CloneSandboxNetworkPolicyIntent(*cfg.NetworkPolicy)
			intent.NetworkPolicy = &networkPolicy
		}
		if cfg.Secrets != nil {
			intent.Secrets = &sandbox.SandboxSecretDeliveryIntent{
				RequestedModes: append([]string(nil), cfg.Secrets.RequestedModes...),
				ActiveModes:    append([]string(nil), cfg.Secrets.ActiveModes...),
			}
		}
	}
	return sandbox.MapSandboxSecurityIntent(intent)
}

func sandboxSecurityReadinessGateModeFromConfig(cfg *compound.SandboxConfig) sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode {
	if cfg == nil {
		return ""
	}
	return cfg.SecurityReadinessGatePolicyMode
}

func sandboxSecurityRequestOrDefault(req sandbox.SecurityEvaluationRequest, runtimeDriver string) sandbox.SecurityEvaluationRequest {
	if !emptySandboxSecurityEvaluationRequest(req) {
		return req
	}
	return sandboxSecurityRequestFromConfig(nil, runtimeDriver)
}

func emptySandboxSecurityEvaluationRequest(req sandbox.SecurityEvaluationRequest) bool {
	return strings.TrimSpace(req.RuntimeDriver) == "" &&
		strings.TrimSpace(req.RequestedNetworkPolicy) == "" &&
		req.RequestedNetworkPolicyIntent == nil &&
		req.NetworkPolicyCapability == nil &&
		len(req.RequestedSecretModes) == 0 &&
		len(req.ActiveSecretModes) == 0 &&
		!req.CompatibilityAuthSync
}

type safeSandboxSecurityConfigLoadError struct {
	message string
	cause   error
}

func (e safeSandboxSecurityConfigLoadError) Error() string {
	return e.message
}

func (e safeSandboxSecurityConfigLoadError) Unwrap() error {
	return e.cause
}

func sanitizeSandboxSecurityConfigLoadError(projectDir string, err error) error {
	if err == nil {
		return nil
	}
	message := sanitizeCredentialedRemoteReferences(err.Error())
	configPath := filepath.Join(projectDir, template.HalDir, template.ConfigFile)
	displayPath := filepath.ToSlash(filepath.Join(template.HalDir, template.ConfigFile))
	message = replacePathVariants(message, configPath, displayPath)
	if projectDir != "" {
		message = replacePathVariants(message, filepath.Clean(projectDir), "[project]")
	}
	if strings.TrimSpace(message) == "" {
		message = "sandbox security config load failed"
	}
	return safeSandboxSecurityConfigLoadError{message: message, cause: err}
}

func replacePathVariants(value, rawPath, replacement string) string {
	rawPath = strings.TrimSpace(rawPath)
	if rawPath == "" {
		return value
	}
	value = strings.ReplaceAll(value, rawPath, replacement)
	if slashPath := filepath.ToSlash(rawPath); slashPath != rawPath {
		value = strings.ReplaceAll(value, slashPath, replacement)
	}
	return value
}
