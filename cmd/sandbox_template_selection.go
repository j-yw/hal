package cmd

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
)

const (
	sandboxTemplateFlagName         = "sandbox-template"
	sandboxTemplateTrustFlagName    = "sandbox-template-trust"
	defaultSandboxTemplateTrustMode = "strict"

	sandboxTemplateRegistryAuthOriginEnv  = "HAL_SANDBOX_TEMPLATE_REGISTRY_AUTH_ORIGIN"
	sandboxTemplateRegistryUsernameEnv    = "HAL_SANDBOX_TEMPLATE_REGISTRY_USERNAME"
	sandboxTemplateRegistryPasswordEnv    = "HAL_SANDBOX_TEMPLATE_REGISTRY_PASSWORD"
	sandboxTemplateRegistryTokenOriginEnv = "HAL_SANDBOX_TEMPLATE_REGISTRY_TOKEN_ORIGIN"
)

type registryCache = registry.Cache
type registryHTTPClient = registry.HTTPDoer

type sandboxTemplateFlagValues struct {
	Sandbox          bool
	Reference        string
	ReferenceChanged bool
	TrustMode        string
	TrustChanged     bool
}

type sandboxTemplateSelectionRequest struct {
	Command string
	DryRun  bool
	Flags   sandboxTemplateFlagValues
}

type sandboxTemplateSelectionWorkflow interface {
	Select(context.Context, selection.Request) (selection.Result, error)
}

type sandboxTemplateSelectionDeps struct {
	ReadCredentialEnvironment func(string) (string, bool)
	NewCache                  func() (registryCache, error)
	NewHTTPClient             func() (registryHTTPClient, error)
	NewWorkflow               func() (sandboxTemplateSelectionWorkflow, error)
}

type sandboxTemplateSelectionResult struct {
	Requested bool
	Active    bool
	Resolved  bool
	Selection *selection.Result
	Reference string
	TrustMode acquisition.TrustPolicyMode
}

func prepareSandboxTemplateSelection(ctx context.Context, request sandboxTemplateSelectionRequest, deps sandboxTemplateSelectionDeps) (sandboxTemplateSelectionResult, error) {
	flags, err := validateSandboxTemplateFlagValues(request.Flags)
	if err != nil {
		return sandboxTemplateSelectionResult{}, err
	}
	if !flags.ReferenceChanged {
		return sandboxTemplateSelectionResult{}, nil
	}
	reference := sandboxtemplate.ImmutableRef{
		Kind: sandboxtemplate.ReferenceKindOCIArtifact,
		Ref:  flags.Reference,
	}
	if _, err := registry.ValidateReference(reference); err != nil {
		return sandboxTemplateSelectionResult{}, err
	}
	mode := acquisition.TrustPolicyModeStrict
	if flags.TrustChanged {
		mode = acquisition.TrustPolicyMode(flags.TrustMode)
	}
	result := sandboxTemplateSelectionResult{
		Requested: true,
		Reference: flags.Reference,
		TrustMode: mode,
	}
	if request.DryRun {
		return result, nil
	}
	newWorkflow := deps.NewWorkflow
	if newWorkflow == nil {
		newWorkflow = func() (sandboxTemplateSelectionWorkflow, error) {
			return newProductionSandboxTemplateSelectionWorkflow(flags.Reference, deps)
		}
	}
	workflow, err := newWorkflow()
	if err != nil || workflow == nil {
		return sandboxTemplateSelectionResult{}, errors.New("selection_rejected")
	}
	selected, err := workflow.Select(ctx, selection.Request{
		Source: acquisition.TemplateSource{
			Kind:      acquisition.SourceKindOCIArtifact,
			Reference: &reference,
		},
		TrustMode: mode,
	})
	if err != nil {
		return sandboxTemplateSelectionResult{}, err
	}
	result.Active = true
	result.Resolved = true
	result.Reference = ""
	result.Selection = &selected
	return result, nil
}

func validateSandboxTemplateFlagValues(flags sandboxTemplateFlagValues) (sandboxTemplateFlagValues, error) {
	if flags.ReferenceChanged && !flags.Sandbox {
		return sandboxTemplateFlagValues{}, errors.New("--sandbox-template requires --sandbox")
	}
	if flags.TrustChanged && !flags.ReferenceChanged {
		return sandboxTemplateFlagValues{}, errors.New("--sandbox-template-trust requires --sandbox-template")
	}
	if flags.ReferenceChanged {
		if strings.TrimSpace(flags.Reference) == "" {
			return sandboxTemplateFlagValues{}, errors.New("--sandbox-template must not be empty")
		}
	}
	if flags.TrustChanged {
		flags.TrustMode = strings.TrimSpace(strings.ToLower(flags.TrustMode))
		if flags.TrustMode != string(acquisition.TrustPolicyModeStrict) &&
			flags.TrustMode != string(acquisition.TrustPolicyModeAdvisory) {
			return sandboxTemplateFlagValues{}, errors.New("--sandbox-template-trust must be one of strict or advisory")
		}
	}
	return flags, nil
}

type sandboxTemplateConstructionRequest struct {
	Command          string
	ExecutionID      string
	SandboxID        string
	RuntimeID        string
	RequestedRuntime string
	Selection        sandboxTemplateSelectionRequest
}

type sandboxTemplateConstructionDeps struct {
	Selection         sandboxTemplateSelectionDeps
	ResolveTarget     func()
	ConstructProvider func()
	ConstructWorker   func()
	ConstructRuntime  func()
}

type sandboxTemplateConstructionResult struct {
	Selection             *selection.Result
	ExecutionID           string
	SandboxID             string
	RuntimeID             string
	ExecutionTemplateLock *sandboxruntime.RuntimeTemplateLockMetadata
	SandboxTemplateLock   *sandboxruntime.RuntimeTemplateLockMetadata
	RuntimeTemplateLock   *sandboxruntime.RuntimeTemplateLockMetadata
}

func executeSandboxTemplateSelectionBeforeConstruction(ctx context.Context, request sandboxTemplateConstructionRequest, deps sandboxTemplateConstructionDeps) (sandboxTemplateConstructionResult, error) {
	prepared, err := prepareSandboxTemplateSelection(ctx, request.Selection, deps.Selection)
	if err != nil {
		return sandboxTemplateConstructionResult{}, err
	}
	if prepared.Selection == nil {
		return sandboxTemplateConstructionResult{}, nil
	}
	selected := *prepared.Selection
	if requested := strings.TrimSpace(request.RequestedRuntime); requested != "" &&
		requested != strings.TrimSpace(selected.RuntimeDriver) {
		return sandboxTemplateConstructionResult{}, errors.New("selection_rejected")
	}
	result := sandboxTemplateConstructionResult{Selection: &selected}
	if request.ExecutionID != "" || request.SandboxID != "" || request.RuntimeID != "" {
		binding, bindErr := selection.Bind(selected, selection.BindingRequest{
			ExecutionID:    request.ExecutionID,
			SandboxID:      request.SandboxID,
			RuntimeID:      request.RuntimeID,
			RuntimeDriver:  selected.RuntimeDriver,
			IsolationLevel: selected.IsolationLevel,
			ManifestDigest: selected.ManifestDigest,
		})
		if bindErr != nil {
			return sandboxTemplateConstructionResult{}, bindErr
		}
		result.ExecutionID = binding.ExecutionID
		result.SandboxID = binding.SandboxID
		result.RuntimeID = binding.RuntimeID
		result.ExecutionTemplateLock = cloneRuntimeTemplateLock(binding.RuntimeMetadata)
		result.SandboxTemplateLock = cloneRuntimeTemplateLock(binding.RuntimeMetadata)
		result.RuntimeTemplateLock = cloneRuntimeTemplateLock(binding.RuntimeMetadata)
	}
	if deps.ResolveTarget != nil {
		deps.ResolveTarget()
	}
	if deps.ConstructProvider != nil {
		deps.ConstructProvider()
	}
	if deps.ConstructWorker != nil {
		deps.ConstructWorker()
	}
	if deps.ConstructRuntime != nil {
		deps.ConstructRuntime()
	}
	return result, nil
}

func cloneRuntimeTemplateLock(lock *sandboxruntime.RuntimeTemplateLockMetadata) *sandboxruntime.RuntimeTemplateLockMetadata {
	return sandboxruntime.SanitizeRuntimeTemplateLockMetadata(lock)
}

func bindSelectedTemplateToSandboxTarget(selected *selection.Result, executionID string, target *sandbox.SandboxState) (*sandbox.SandboxTemplateLockMetadata, error) {
	if selected == nil {
		return nil, nil
	}
	if target == nil || target.Runtime == nil {
		return nil, errors.New("selection_rejected")
	}
	expected := selectedTemplateConstructionLock(selected)
	actual := sandbox.SanitizeSandboxTemplateLockMetadata(target.Runtime.TemplateLock)
	if expected == nil || actual == nil || !reflect.DeepEqual(expected, actual) {
		return nil, errors.New("selection_rejected")
	}
	binding, err := selection.Bind(*selected, selection.BindingRequest{
		ExecutionID:    executionID,
		SandboxID:      target.ID,
		RuntimeID:      target.Runtime.RuntimeID,
		RuntimeDriver:  target.Runtime.Driver,
		IsolationLevel: target.Runtime.IsolationLevel,
		ManifestDigest: selected.ManifestDigest,
	})
	if err != nil {
		return nil, err
	}
	bound := sandboxTemplateLockFromRuntimeMetadata(&sandboxruntime.RuntimeMetadata{TemplateLock: binding.RuntimeMetadata})
	if bound == nil || !reflect.DeepEqual(bound, actual) {
		return nil, errors.New("selection_rejected")
	}
	return actual, nil
}

func selectedTemplateConstructionLock(selected *selection.Result) *sandbox.SandboxTemplateLockMetadata {
	if selected == nil {
		return nil
	}
	return sandboxTemplateLockFromRuntimeMetadata(&sandboxruntime.RuntimeMetadata{
		TemplateLock: selected.RuntimeMetadata,
	})
}

func templateSelectionRuntimeDriver(selected *selection.Result) string {
	if selected == nil {
		return ""
	}
	return strings.TrimSpace(selected.RuntimeDriver)
}

func templateSelectionIsolationLevel(selected *selection.Result) string {
	if selected == nil {
		return ""
	}
	return strings.TrimSpace(selected.IsolationLevel)
}

func bindSandboxTemplateSelectionToTarget(req *runSandboxRequest, target *sandbox.SandboxState) error {
	if req == nil {
		return errors.New("selection_rejected")
	}
	lock, err := bindSelectedTemplateToSandboxTarget(req.TemplateSelection, req.ExecutionID, target)
	if err != nil {
		return err
	}
	req.TemplateLock = lock
	return nil
}

func bindAutoSandboxTemplateSelectionToTarget(req *autoSandboxRequest, target *sandbox.SandboxState) error {
	if req == nil {
		return errors.New("selection_rejected")
	}
	lock, err := bindSelectedTemplateToSandboxTarget(req.TemplateSelection, req.ExecutionID, target)
	if err != nil {
		return err
	}
	req.TemplateLock = lock
	return nil
}

func newProductionSandboxTemplateSelectionWorkflow(reference string, deps sandboxTemplateSelectionDeps) (sandboxTemplateSelectionWorkflow, error) {
	validated, err := registry.ValidateReference(sandboxtemplate.ImmutableRef{
		Kind: sandboxtemplate.ReferenceKindOCIArtifact,
		Ref:  reference,
	})
	if err != nil {
		return nil, errors.New("invalid_reference")
	}
	authority := validated.Authority
	origin := "https://" + authority
	var client registryHTTPClient
	if deps.NewHTTPClient != nil {
		client, err = deps.NewHTTPClient()
	} else {
		client, err = registry.NewProductionClient(registry.ProductionClientOptions{})
	}
	if err != nil || client == nil {
		return nil, errors.New("registry_unavailable")
	}
	var cache registryCache
	if deps.NewCache != nil {
		cache, err = deps.NewCache()
	} else {
		var cacheRoot string
		cacheRoot, err = os.UserCacheDir()
		if err == nil {
			cache = registry.NewFileCache(filepath.Join(cacheRoot, "hal", "template-oci"))
		}
	}
	if err != nil || cache == nil {
		return nil, errors.New("cache_invalid")
	}
	credentialProvider, tokenPolicy, err := productionSandboxTemplateRegistryAuth(origin, authority, deps.ReadCredentialEnvironment)
	if err != nil {
		return nil, errors.New("selection_rejected")
	}
	resolver, err := registry.NewResolver(registry.Options{
		Client:                 client,
		AllowedRegistryOrigins: []string{origin},
		AllowedTokenOrigins:    tokenPolicy,
		CredentialProvider:     credentialProvider,
		Cache:                  cache,
		RequestTimeout:         registry.DefaultRequestTimeout,
	})
	if err != nil {
		return nil, errors.New("selection_rejected")
	}
	workflow := selection.NewWorkflow(acquisition.NewOCIResolver(resolver))
	return workflow, nil
}

type exactRegistryCredentialProvider struct {
	registryOrigin string
	tokenOrigin    string
	credential     registry.Credential
}

func (p exactRegistryCredentialProvider) LookupCredential(_ context.Context, request registry.CredentialRequest) (registry.Credential, error) {
	if request.RegistryOrigin != p.registryOrigin ||
		(request.TokenOrigin != "" && request.TokenOrigin != p.tokenOrigin) {
		return registry.Credential{}, errors.New("authentication_failed")
	}
	return p.credential, nil
}

func productionSandboxTemplateRegistryAuth(origin, authority string, lookup func(string) (string, bool)) (registry.CredentialProvider, map[string]registry.TokenOriginPolicy, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	tokenOrigin := origin
	credential := registry.Credential{}
	allowedOrigin, configured := lookup(sandboxTemplateRegistryAuthOriginEnv)
	if configured && strings.TrimSpace(allowedOrigin) != "" {
		normalized, err := normalizeCommandHTTPSOrigin(allowedOrigin)
		if err != nil {
			return nil, nil, err
		}
		if normalized == origin {
			credential.Username, _ = lookup(sandboxTemplateRegistryUsernameEnv)
			credential.Password, _ = lookup(sandboxTemplateRegistryPasswordEnv)
			if strings.ContainsAny(credential.Username+credential.Password, "\r\n") {
				return nil, nil, errors.New("authentication_failed")
			}
			if configuredTokenOrigin, ok := lookup(sandboxTemplateRegistryTokenOriginEnv); ok && strings.TrimSpace(configuredTokenOrigin) != "" {
				tokenOrigin, err = normalizeCommandHTTPSOrigin(configuredTokenOrigin)
				if err != nil {
					return nil, nil, err
				}
			}
		}
	}
	provider := exactRegistryCredentialProvider{
		registryOrigin: origin,
		tokenOrigin:    tokenOrigin,
		credential:     credential,
	}
	return provider, map[string]registry.TokenOriginPolicy{
		origin: {Origin: tokenOrigin, Service: authority},
	}, nil
}

func normalizeCommandHTTPSOrigin(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\\%") {
		return "", errors.New("authentication_failed")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.Host != strings.ToLower(parsed.Host) || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("authentication_failed")
	}
	return "https://" + parsed.Host, nil
}
