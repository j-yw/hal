package credentialdelivery

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestResolveBindingSecretMetadataFoundReferences(t *testing.T) {
	binding := safeBindingFixture()
	binding.SecretRef = " env:GITHUB_TOKEN "
	binding.DeliveryMode = Mode(" ENV ")
	resolver := newFakeSecretMetadataResolver(BrokerSecretMetadata{
		ID:       " env:GITHUB_TOKEN ",
		Source:   " env ",
		Required: true,
		Present:  true,
	})

	got := ResolveBindingSecretMetadata(SecretResolutionRequest{
		Bindings: []Binding{binding},
		Resolver: resolver,
	})

	assertSecretResolutionValid(t, got)
	if len(got.Bindings) != 1 {
		t.Fatalf("resolved bindings = %#v, want one", got.Bindings)
	}
	want := ResolvedBindingSecretMetadata{
		BindingID:    "binding-01",
		SecretRef:    "env:GITHUB_TOKEN",
		DeliveryMode: ModeEnv,
		BrokerSecret: BrokerSecretMetadata{
			ID:       "env:GITHUB_TOKEN",
			Source:   "env",
			Required: true,
			Present:  true,
		},
	}
	if !reflect.DeepEqual(got.Bindings[0], want) {
		t.Fatalf("resolved binding = %#v, want %#v", got.Bindings[0], want)
	}
	if len(resolver.calls) != 1 || resolver.calls[0] != (SecretReference{BindingID: "binding-01", SecretRef: "env:GITHUB_TOKEN"}) {
		t.Fatalf("resolver calls = %#v, want one safe reference", resolver.calls)
	}
	assertSecretResolutionNoLeak(t, got)
}

func TestResolveBindingSecretMetadataFailsClosedForMissingReferences(t *testing.T) {
	binding := safeBindingFixture()
	binding.SecretRef = "env:GITHUB_TOKEN"

	got := ResolveBindingSecretMetadata(SecretResolutionRequest{
		Bindings: []Binding{binding},
		Resolver: newFakeSecretMetadataResolver(),
	})

	assertSecretResolutionError(t, got, ErrorMissingSecretReference, "bindings.secretRef", "binding-01", intPtr(0))
	if got.Valid {
		t.Fatalf("resolution valid = true, want fail-closed result")
	}
	if len(got.Bindings) != 0 {
		t.Fatalf("resolved bindings = %#v, want none before activation", got.Bindings)
	}
	if len(got.Warnings) != 1 || got.Warnings[0].Code != WarningBindingOmitted || got.Warnings[0].ReasonCode != ReasonMissingSecretReference {
		t.Fatalf("warnings = %#v, want binding omitted missing-secret warning", got.Warnings)
	}
	assertSecretResolutionNoLeak(t, got)
}

func TestResolveBindingSecretMetadataRejectsUnsafeReferencesBeforeResolver(t *testing.T) {
	binding := safeBindingFixture()
	binding.SecretRef = "GITHUB_TOKEN=ghp_raw_secret_value"
	resolver := newFakeSecretMetadataResolver(BrokerSecretMetadata{
		ID:       "env:GITHUB_TOKEN",
		Source:   "env",
		Required: true,
		Present:  true,
	})

	got := ResolveBindingSecretMetadata(SecretResolutionRequest{
		Bindings: []Binding{binding},
		Resolver: resolver,
	})

	assertSecretResolutionError(t, got, ErrorUnsafeReference, "bindings.secretRef", "binding-01", intPtr(0))
	if len(resolver.calls) != 0 {
		t.Fatalf("resolver calls = %#v, want none for unsafe reference", resolver.calls)
	}
	assertSecretResolutionNoLeak(t, got, "GITHUB_TOKEN=ghp_raw_secret_value", "ghp_raw_secret_value")
}

func TestResolveBindingSecretMetadataCachesDuplicateReferences(t *testing.T) {
	first := safeBindingFixture()
	first.SecretRef = "env:GITHUB_TOKEN"
	first.DeliveryMode = ModeEnv
	second := safeBindingFixture()
	second.ID = "binding-02"
	second.SecretRef = first.SecretRef
	second.DeliveryMode = ModeHTTPProxy
	resolver := newFakeSecretMetadataResolver(BrokerSecretMetadata{
		ID:       "env:GITHUB_TOKEN",
		Source:   "env",
		Required: true,
		Present:  true,
	})

	got := ResolveBindingSecretMetadata(SecretResolutionRequest{
		Bindings: []Binding{first, second},
		Resolver: resolver,
	})

	assertSecretResolutionValid(t, got)
	if len(resolver.calls) != 1 {
		t.Fatalf("resolver calls = %#v, want duplicate secretRef resolved once", resolver.calls)
	}
	if len(got.Bindings) != 2 {
		t.Fatalf("resolved bindings = %#v, want both duplicate-reference bindings", got.Bindings)
	}
	if got.Bindings[0].BrokerSecret.ID != got.Bindings[1].BrokerSecret.ID {
		t.Fatalf("duplicate references resolved to different broker metadata: %#v", got.Bindings)
	}
	assertSecretResolutionNoLeak(t, got)
}

func TestResolveBindingSecretMetadataSanitizesResolverFailure(t *testing.T) {
	rawSecret := "ghp_raw_secret_value"
	providerDetail := "https://secrets.example.invalid/prod/token"
	binding := safeBindingFixture()
	binding.SecretRef = "env:GITHUB_TOKEN"
	resolver := newFakeSecretMetadataResolver()
	resolver.err = errors.New("provider returned " + rawSecret + " from " + providerDetail)

	got := ResolveBindingSecretMetadata(SecretResolutionRequest{
		Bindings: []Binding{binding},
		Resolver: resolver,
	})

	assertSecretResolutionError(t, got, ErrorResolverFailed, "bindings.secretRef", "binding-01", intPtr(0))
	assertSecretResolutionNoLeak(t, got, rawSecret, providerDetail, "secrets.example.invalid")
}

func TestResolveBindingSecretMetadataRejectsUnsafeResolverMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata BrokerSecretMetadata
		code     ErrorCode
		field    string
	}{
		{
			name: "unsafe id",
			metadata: BrokerSecretMetadata{
				ID:       "GITHUB_TOKEN=ghp_raw_secret_value",
				Source:   "env",
				Required: true,
				Present:  true,
			},
			code:  ErrorUnsafeReference,
			field: "brokerSecret.id",
		},
		{
			name: "mismatched id",
			metadata: BrokerSecretMetadata{
				ID:       "env:OTHER_TOKEN",
				Source:   "env",
				Required: true,
				Present:  true,
			},
			code:  ErrorUnsafeReference,
			field: "brokerSecret.id",
		},
		{
			name: "not present",
			metadata: BrokerSecretMetadata{
				ID:       "env:GITHUB_TOKEN",
				Source:   "env",
				Required: true,
				Present:  false,
			},
			code:  ErrorMissingSecretReference,
			field: "bindings.secretRef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := safeBindingFixture()
			binding.SecretRef = "env:GITHUB_TOKEN"
			resolver := newFakeSecretMetadataResolver(tt.metadata)
			if tt.field == "brokerSecret.id" {
				resolver.secrets[binding.SecretRef] = tt.metadata
			}

			got := ResolveBindingSecretMetadata(SecretResolutionRequest{
				Bindings: []Binding{binding},
				Resolver: resolver,
			})

			assertSecretResolutionError(t, got, tt.code, tt.field, "binding-01", intPtr(0))
			if len(got.Bindings) != 0 {
				t.Fatalf("resolved bindings = %#v, want none", got.Bindings)
			}
			assertSecretResolutionNoLeak(t, got, "GITHUB_TOKEN=ghp_raw_secret_value", "ghp_raw_secret_value")
		})
	}
}

func TestResolveBindingSecretMetadataDoesNotLeakRawValuesAcrossDurablePayloads(t *testing.T) {
	rawSecret := "ghp_raw_secret_value_123"
	providerDetail := "https://secrets.example.invalid/prod/token"
	binding := safeBindingFixture()
	binding.SecretRef = "env:GITHUB_TOKEN"
	resolver := newFakeSecretMetadataResolver()
	resolver.err = errors.New("provider failed with " + rawSecret + " at " + providerDetail)

	resolution := ResolveBindingSecretMetadata(SecretResolutionRequest{
		Bindings: []Binding{binding},
		Resolver: resolver,
	})
	assertSecretResolutionError(t, resolution, ErrorResolverFailed, "bindings.secretRef", "binding-01", intPtr(0))

	plan := SanitizePlanMetadata(Plan{
		ID:       "delivery-plan-01",
		Status:   StatusFailed,
		Warnings: resolution.Warnings,
		Errors:   resolution.Errors,
	})
	activation := SanitizeActivationResultMetadata(ActivationResult{
		ID:         "delivery-activation-01",
		PlanID:     plan.ID,
		Status:     StatusFailed,
		ReasonCode: ReasonMissingSecretReference,
		Warnings:   resolution.Warnings,
	})
	runtimeMetadata := sandboxruntime.RuntimeMetadata{
		CapabilityLabels: []string{"credential-delivery-resolution-failed"},
	}
	manifest := sandboxexecution.Manifest{
		ID:        "execution-01",
		Purpose:   sandboxexecution.PurposeRun,
		Status:    sandboxexecution.StatusFailed,
		StartedAt: time.Date(2026, 7, 3, 6, 0, 0, 0, time.UTC),
		Security: &sandbox.SandboxSecurity{
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{string(ModeEnv)},
			},
		},
	}
	timeline := factory.EventRecord{
		Sequence:  1,
		RunID:     "factory-run-01",
		EventType: factory.EventTypeStepEnded,
		Timestamp: time.Date(2026, 7, 3, 6, 0, 1, 0, time.UTC),
		Message:   "credential delivery resolution failed closed",
		Metadata: map[string]any{
			"credentialDelivery": resolution,
			"deliveryPlan":       plan,
		},
	}
	logs := []factory.LogChunk{{
		RunID:   "factory-run-01",
		Stream:  factory.LogStreamStderr,
		Source:  factory.LogSourceEngine,
		Text:    resolution.Errors[0].Error(),
		Summary: "credential delivery resolution failed closed",
	}}

	payload := struct {
		JSON            SecretResolutionResult         `json:"json"`
		Errors          []SanitizedError               `json:"errors"`
		Logs            []factory.LogChunk             `json:"logs"`
		RuntimeMetadata sandboxruntime.RuntimeMetadata `json:"runtimeMetadata"`
		Manifest        sandboxexecution.Manifest      `json:"manifest"`
		FactoryTimeline factory.EventRecord            `json:"factoryTimeline"`
		Plan            Plan                           `json:"plan"`
		Activation      ActivationResult               `json:"activation"`
	}{
		JSON:            resolution,
		Errors:          resolution.Errors,
		Logs:            logs,
		RuntimeMetadata: runtimeMetadata,
		Manifest:        manifest,
		FactoryTimeline: timeline,
		Plan:            plan,
		Activation:      activation,
	}

	assertSecretResolutionNoLeak(t, payload, rawSecret, providerDetail, "secrets.example.invalid", "provider failed")
	for _, err := range resolution.Errors {
		assertSecretResolutionNoLeak(t, err.Error(), rawSecret, providerDetail, "secrets.example.invalid", "provider failed")
	}
}

type fakeSecretMetadataResolver struct {
	secrets map[string]BrokerSecretMetadata
	calls   []SecretReference
	err     error
}

func newFakeSecretMetadataResolver(secrets ...BrokerSecretMetadata) *fakeSecretMetadataResolver {
	resolver := &fakeSecretMetadataResolver{
		secrets: make(map[string]BrokerSecretMetadata, len(secrets)),
	}
	for _, secret := range secrets {
		normalized := NormalizeBrokerSecretMetadata(secret)
		resolver.secrets[normalized.ID] = secret
	}
	return resolver
}

func (r *fakeSecretMetadataResolver) ResolveSecretReference(reference SecretReference) (BrokerSecretMetadata, bool, error) {
	r.calls = append(r.calls, reference)
	if r.err != nil {
		return BrokerSecretMetadata{}, false, r.err
	}
	secret, ok := r.secrets[reference.SecretRef]
	return secret, ok, nil
}

func assertSecretResolutionValid(t *testing.T, result SecretResolutionResult) {
	t.Helper()

	if !result.Valid {
		t.Fatalf("resolution valid = false, errors: %#v", result.Errors)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("resolution errors = %#v, want none", result.Errors)
	}
}

func assertSecretResolutionError(t *testing.T, result SecretResolutionResult, code ErrorCode, field string, bindingID string, index *int) {
	t.Helper()

	if result.Valid {
		t.Fatalf("resolution valid = true, want false")
	}
	for _, err := range result.Errors {
		if err.Code != code || err.Field != field || err.BindingID != bindingID {
			continue
		}
		switch {
		case index == nil && err.Index == nil:
			return
		case index != nil && err.Index != nil && *index == *err.Index:
			return
		}
	}
	t.Fatalf("resolution errors = %#v, want code %q field %q binding %q index %#v", result.Errors, code, field, bindingID, index)
}

func assertSecretResolutionNoLeak(t *testing.T, value any, rejectedValues ...string) {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error: %v", value, err)
	}
	payloads := []string{string(data)}
	if text, ok := value.(string); ok {
		payloads = append(payloads, text)
	}
	for _, payload := range payloads {
		for _, forbidden := range []string{
			"https://",
			"example.invalid",
			"/Users/",
			"/tmp/",
			"/var/run/",
			"Authorization",
			"Bearer",
			"X-Api-Key",
			"GITHUB_TOKEN=",
			"ghp_",
			"credentialValue",
			"secretValue",
			"provider_credential",
			"providerCredential",
			"raw_secret",
			"\n",
			"\u001f",
		} {
			if strings.Contains(payload, forbidden) {
				t.Fatalf("secret resolution payload leaked unsafe value %q in %s", forbidden, payload)
			}
		}
		for _, rejected := range rejectedValues {
			if rejected == "" {
				continue
			}
			if strings.Contains(payload, rejected) {
				t.Fatalf("secret resolution leaked rejected value %q in %s", rejected, payload)
			}
		}
	}
}
