package credentialdelivery

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestActivateDeliveryWithoutAdapterDoesNotActivatePlanActiveModes(t *testing.T) {
	binding := planBindingFixture(ModeHTTPProxy)
	request := planConstructionRequestFixture(binding)
	request.NetworkProxySession = planNetworkProxySessionFixture()
	plan := BuildDeliveryPlan(request)
	assertPlanModes(t, plan.ActiveModes, []Mode{ModeHTTPProxy})

	got := ActivateDelivery(ActivationRequest{
		ActivationID: " activation-01 ",
		Plan:         plan,
		Bindings:     []Binding{binding},
	}, nil)

	if got.ID != "activation-01" || got.PlanID != plan.ID {
		t.Fatalf("activation identity = %#v, want sanitized request and plan IDs", got)
	}
	assertPlanModes(t, got.RequestedModes, []Mode{ModeHTTPProxy})
	assertPlanModes(t, got.ActiveModes, nil)
	if got.Status != StatusSkipped {
		t.Fatalf("activation status = %q, want skipped without injected adapter", got.Status)
	}
	assertActivationWarning(t, got, WarningAdapterUnavailable, ReasonActivationUnavailable, ModeHTTPProxy)
	assertActivationBindingStatus(t, got, binding.ID, ModeHTTPProxy, StatusSkipped)
	assertActivationNoLeak(t, got)
}

func TestActivateDeliveryUsesInjectedFakeAdapterForEveryMode(t *testing.T) {
	for _, mode := range SupportedModes() {
		t.Run(string(mode), func(t *testing.T) {
			binding := planBindingFixture(mode)
			binding.ID = "binding-" + string(mode)
			plan := Plan{
				ID:             "delivery-plan-" + string(mode),
				RequestID:      "delivery-request-01",
				RequestedModes: []Mode{mode},
				Status:         StatusPlanned,
			}
			adapter := &fakeActivationAdapter{}

			got := ActivateDelivery(ActivationRequest{
				Plan:     plan,
				Bindings: []Binding{binding},
			}, adapter)

			if len(adapter.calls) != 1 {
				t.Fatalf("adapter calls = %d, want 1", len(adapter.calls))
			}
			if adapter.calls[0].ActivationID != plan.ID+"-activation" {
				t.Fatalf("adapter input activation ID = %q, want default from plan ID", adapter.calls[0].ActivationID)
			}
			if adapter.calls[0].Bindings[0].ID != binding.ID || adapter.calls[0].Bindings[0].DeliveryMode != mode {
				t.Fatalf("adapter input bindings = %#v, want sanitized binding metadata", adapter.calls[0].Bindings)
			}
			if got.Status != StatusActive {
				t.Fatalf("activation status = %q, want active", got.Status)
			}
			assertPlanModes(t, got.RequestedModes, []Mode{mode})
			assertPlanModes(t, got.ActiveModes, []Mode{mode})
			assertActivationBindingStatus(t, got, binding.ID, mode, StatusActive)
			assertActivationNoLeak(t, got)
		})
	}
}

func TestActivateDeliveryAdapterFailureRedactsRawValuesAcrossDurablePayloads(t *testing.T) {
	rawSecret := "ghp_raw_secret_value_123"
	providerDetail := "https://secrets.example.invalid/prod/token"
	rawSocketPath := "/tmp/credential-delivery.sock"
	binding := planBindingFixture(ModeEnv)
	plan := Plan{
		ID:             "delivery-plan-01",
		RequestID:      "delivery-request-01",
		RequestedModes: []Mode{ModeEnv},
		Status:         StatusPlanned,
	}
	adapter := &fakeActivationAdapter{
		err: errors.New("adapter failed with " + rawSecret + " at " + providerDetail + " Authorization Bearer " + rawSocketPath),
	}

	activation := ActivateDelivery(ActivationRequest{
		ActivationID: "activation-01",
		Plan:         plan,
		Bindings:     []Binding{binding},
	}, adapter)

	if activation.Status != StatusFailed {
		t.Fatalf("activation status = %q, want failed", activation.Status)
	}
	assertPlanModes(t, activation.ActiveModes, nil)
	assertActivationError(t, activation, ErrorActivationFailed, "adapter")
	assertActivationBindingStatus(t, activation, binding.ID, ModeEnv, StatusFailed)

	runtimeMetadata := sandboxruntime.RuntimeMetadata{
		CapabilityLabels: []string{"credential-delivery-activation-failed"},
	}
	manifest := sandboxexecution.Manifest{
		ID:        "execution-01",
		Purpose:   sandboxexecution.PurposeRun,
		Status:    sandboxexecution.StatusFailed,
		StartedAt: time.Date(2026, 7, 3, 6, 30, 0, 0, time.UTC),
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
		Timestamp: time.Date(2026, 7, 3, 6, 30, 1, 0, time.UTC),
		Message:   "credential delivery activation failed closed",
		Metadata: map[string]any{
			"credentialDeliveryActivation": activation,
		},
	}
	logs := []factory.LogChunk{{
		RunID:   "factory-run-01",
		Stream:  factory.LogStreamStderr,
		Source:  factory.LogSourceEngine,
		Text:    activation.Errors[0].Error(),
		Summary: "credential delivery activation failed closed",
	}}

	payload := struct {
		JSON            ActivationResult               `json:"json"`
		Errors          []SanitizedError               `json:"errors"`
		Logs            []factory.LogChunk             `json:"logs"`
		RuntimeMetadata sandboxruntime.RuntimeMetadata `json:"runtimeMetadata"`
		Manifest        sandboxexecution.Manifest      `json:"manifest"`
		FactoryTimeline factory.EventRecord            `json:"factoryTimeline"`
	}{
		JSON:            activation,
		Errors:          activation.Errors,
		Logs:            logs,
		RuntimeMetadata: runtimeMetadata,
		Manifest:        manifest,
		FactoryTimeline: timeline,
	}

	assertActivationNoLeak(t, payload, rawSecret, providerDetail, rawSocketPath, "secrets.example.invalid", "adapter failed")
	for _, err := range activation.Errors {
		assertActivationNoLeak(t, err.Error(), rawSecret, providerDetail, rawSocketPath, "secrets.example.invalid", "adapter failed")
	}
}

type fakeActivationAdapter struct {
	result ActivationResult
	err    error
	calls  []ActivationRequest
}

func (a *fakeActivationAdapter) ActivateCredentialDelivery(input SanitizedActivationRequest) (ActivationResult, error) {
	request := input.Request()
	a.calls = append(a.calls, request)
	if a.err != nil {
		return a.result, a.err
	}
	if a.result.ID != "" || a.result.PlanID != "" || len(a.result.ActiveModes) > 0 || len(a.result.Bindings) > 0 || a.result.Status != "" {
		return a.result, nil
	}
	return fakeActiveActivationResult(request), nil
}

func fakeActiveActivationResult(request ActivationRequest) ActivationResult {
	activeModes := newPlanModeSet()
	result := ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		Status:         StatusActive,
	}
	for _, binding := range request.Bindings {
		activeModes.add(binding.DeliveryMode)
		result.Bindings = append(result.Bindings, BindingActivationResult{
			BindingID:    binding.ID,
			DeliveryMode: binding.DeliveryMode,
			Status:       StatusActive,
			ReasonCode:   ReasonRequested,
		})
	}
	if len(result.Bindings) == 0 {
		for _, mode := range request.Plan.RequestedModes {
			activeModes.add(mode)
		}
	}
	result.ActiveModes = activeModes.ordered()
	return result
}

func assertActivationWarning(t *testing.T, activation ActivationResult, code WarningCode, reason ReasonCode, mode Mode) {
	t.Helper()

	for _, warning := range activation.Warnings {
		if warning.Code == code && warning.ReasonCode == reason && warning.Mode == mode {
			return
		}
	}
	t.Fatalf("activation warnings = %#v, want code %q reason %q mode %q", activation.Warnings, code, reason, mode)
}

func assertActivationError(t *testing.T, activation ActivationResult, code ErrorCode, field string) {
	t.Helper()

	for _, err := range activation.Errors {
		if err.Code == code && err.Field == field {
			return
		}
	}
	t.Fatalf("activation errors = %#v, want code %q field %q", activation.Errors, code, field)
}

func assertActivationBindingStatus(t *testing.T, activation ActivationResult, bindingID string, mode Mode, status Status) {
	t.Helper()

	for _, binding := range activation.Bindings {
		if binding.BindingID == bindingID && binding.DeliveryMode == mode && binding.Status == status {
			return
		}
	}
	t.Fatalf("activation bindings = %#v, want binding %q mode %q status %q", activation.Bindings, bindingID, mode, status)
}

func assertActivationNoLeak(t *testing.T, value any, rejectedValues ...string) {
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
				t.Fatalf("activation payload leaked unsafe value %q in %s", forbidden, payload)
			}
		}
		for _, rejected := range rejectedValues {
			if rejected == "" {
				continue
			}
			if strings.Contains(payload, rejected) {
				t.Fatalf("activation leaked rejected value %q in %s", rejected, payload)
			}
		}
	}
}
