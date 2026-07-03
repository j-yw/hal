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
	configureHTTPProxyProof(&request)
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
			if mode == ModeHTTPProxy {
				request := planConstructionRequestFixture(binding)
				configureHTTPProxyProof(&request)
				plan = BuildDeliveryPlan(request)
			}
			wantStatus := StatusActive
			wantBindingStatus := StatusActive
			wantActiveModes := []Mode{mode}
			if mode == ModeLegacyAuthSync {
				wantStatus = StatusSkipped
				wantBindingStatus = StatusSkipped
				wantActiveModes = nil
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
			if got.Status != wantStatus {
				t.Fatalf("activation status = %q, want %q", got.Status, wantStatus)
			}
			assertPlanModes(t, got.RequestedModes, []Mode{mode})
			assertPlanModes(t, got.ActiveModes, wantActiveModes)
			assertActivationBindingStatus(t, got, binding.ID, mode, wantBindingStatus)
			assertActivationBindingService(t, got, binding.ID, binding.ServiceID)
			if mode == ModeLegacyAuthSync {
				assertActivationWarning(t, got, WarningLegacyAuthCompatibility, ReasonCompatibilityMode, ModeLegacyAuthSync)
			}
			assertActivationNoLeak(t, got)
		})
	}
}

func TestActivateDeliverySanitizesAdapterBoundaryAndResultContractsForSupportedModes(t *testing.T) {
	rawEndpoint := "https://proxy.example.invalid:8443/credential?token=raw"
	rawPath := "/Users/v/.ssh/id_rsa"
	rawSocket := "/var/run/ssh-agent.sock"
	rawEnvValue := "GITHUB_TOKEN=ghp_raw_secret_value"
	rawHeader := "Authorization: Bearer ghp_raw_secret_value"
	rawCommand := "ssh-agent -a /tmp/agent.sock"
	rejectedValues := []string{rawEndpoint, rawPath, rawSocket, rawEnvValue, rawHeader, rawCommand, "proxy.example.invalid", "token=raw"}

	for _, mode := range SupportedModes() {
		t.Run(string(mode), func(t *testing.T) {
			binding := planBindingFixture(mode)
			binding.ID = "binding-" + string(mode)
			binding.RequestID = rawEndpoint
			binding.PolicySnapshotID = rawPath
			binding.ServiceLabels = []string{"source-control", rawHeader}
			binding.DomainLabels = []string{"github", rawCommand}
			binding.DestinationCategory = DestinationCategory(rawEndpoint)
			if mode == ModeHTTPProxy {
				binding.NetworkProxySessionID = "network-proxy-session-01"
				binding.PolicySnapshotID = "policy-snapshot-01"
			} else {
				binding.NetworkProxySessionID = rawSocket
			}

			plan := Plan{
				ID:             "delivery-plan-" + string(mode),
				RequestID:      rawEndpoint,
				RequestedModes: []Mode{mode},
				ActiveModes:    []Mode{Mode(rawEnvValue)},
				Status:         StatusPlanned,
				Warnings: []Warning{{
					Code:       WarningAdapterUnavailable,
					ReasonCode: ReasonActivationUnavailable,
					BindingID:  rawSocket,
					Mode:       mode,
				}},
			}
			if mode == ModeHTTPProxy {
				planBinding := binding
				planBinding.RequestID = "delivery-request-01"
				planBinding.ServiceLabels = []string{"source-control"}
				planBinding.DomainLabels = []string{"github"}
				planBinding.DestinationCategory = DestinationPublicInternet
				request := planConstructionRequestFixture(planBinding)
				configureHTTPProxyProof(&request)
				plan = BuildDeliveryPlan(request)
				plan.ActiveModes = append(plan.ActiveModes, Mode(rawEnvValue))
			}

			unsafeBinding := Binding{
				ID:           "binding-unsafe-" + string(mode),
				SecretRef:    rawEnvValue,
				ServiceID:    rawSocket,
				DeliveryMode: mode,
			}
			adapter := &fakeActivationAdapter{
				result: ActivationResult{
					ID:             rawEndpoint,
					PlanID:         rawPath,
					RequestedModes: []Mode{Mode(rawHeader)},
					ActiveModes:    []Mode{mode, Mode(rawEnvValue)},
					Bindings: []BindingActivationResult{
						{
							BindingID:    binding.ID,
							ServiceID:    rawSocket,
							DeliveryMode: mode,
							Outcome:      StatusActive,
							Status:       StatusActive,
							ReasonCode:   ReasonRequested,
						},
						{
							BindingID:    rawSocket,
							DeliveryMode: mode,
							Outcome:      StatusActive,
							Status:       StatusActive,
						},
					},
					Status: StatusActive,
					Warnings: []Warning{{
						Code:       WarningAdapterUnavailable,
						ReasonCode: ReasonActivationUnavailable,
						BindingID:  rawHeader,
						Mode:       mode,
					}},
				},
			}

			got := ActivateDelivery(ActivationRequest{
				ActivationID: " " + rawCommand + " ",
				Plan:         plan,
				Bindings:     []Binding{binding, unsafeBinding},
			}, adapter)

			if len(adapter.calls) != 1 {
				t.Fatalf("adapter calls = %d, want 1", len(adapter.calls))
			}
			call := adapter.calls[0]
			if call.ActivationID != plan.ID+"-activation" {
				t.Fatalf("adapter activation ID = %q, want sanitized default", call.ActivationID)
			}
			if len(call.Bindings) != 1 {
				t.Fatalf("adapter bindings = %#v, want only safe binding", call.Bindings)
			}
			if call.Bindings[0].ID != binding.ID || call.Bindings[0].DeliveryMode != mode {
				t.Fatalf("adapter binding = %#v, want safe %s binding", call.Bindings[0], mode)
			}
			assertPlanModes(t, call.Plan.RequestedModes, []Mode{mode})
			assertActivationNoLeak(t, call, rejectedValues...)

			assertPlanModes(t, got.RequestedModes, []Mode{mode})
			if mode == ModeLegacyAuthSync {
				if got.Status != StatusSkipped {
					t.Fatalf("legacy activation status = %q, want skipped compatibility metadata", got.Status)
				}
				assertPlanModes(t, got.ActiveModes, nil)
				assertActivationBindingStatus(t, got, binding.ID, mode, StatusSkipped)
				assertActivationWarning(t, got, WarningLegacyAuthCompatibility, ReasonCompatibilityMode, ModeLegacyAuthSync)
			} else {
				if got.Status != StatusActive {
					t.Fatalf("activation status = %q, want active", got.Status)
				}
				assertPlanModes(t, got.ActiveModes, []Mode{mode})
				assertActivationBindingStatus(t, got, binding.ID, mode, StatusActive)
			}
			assertActivationNoLeak(t, got, rejectedValues...)
		})
	}
}

func TestActivateDeliveryHTTPProxyRequiresSafeSessionBinding(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(*PlanConstructionRequest)
		wantActive bool
		rejected   []string
	}{
		{
			name: "safe activation",
			configure: func(request *PlanConstructionRequest) {
				configureHTTPProxyProof(request)
			},
			wantActive: true,
		},
		{
			name: "missing session",
			configure: func(request *PlanConstructionRequest) {
				request.Bindings[0].NetworkProxySessionID = ""
			},
		},
		{
			name: "unsafe session",
			configure: func(request *PlanConstructionRequest) {
				rawSession := "/tmp/credential-proxy.sock"
				request.Bindings[0].NetworkProxySessionID = ""
				request.NetworkProxySession = &sandbox.SandboxNetworkProxySessionMetadata{
					ID:     rawSession,
					Source: sandbox.SandboxNetworkPolicyDecisionSourceRun,
				}
				request.NetworkEnforcementProof = planNetworkEnforcementProofFixture()
			},
			rejected: []string{"/tmp/credential-proxy.sock"},
		},
		{
			name: "mismatched session",
			configure: func(request *PlanConstructionRequest) {
				configureHTTPProxyProof(request)
				request.Bindings[0].NetworkProxySessionID = "network-proxy-session-other"
			},
		},
		{
			name: "policy disallowed",
			configure: func(request *PlanConstructionRequest) {
				configureHTTPProxyProof(request)
				request.Bindings[0].PolicySnapshotID = "policy-snapshot-other"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := planBindingFixture(ModeHTTPProxy)
			request := planConstructionRequestFixture(binding)
			tt.configure(&request)
			plan := BuildDeliveryPlan(request)
			adapter := &fakeActivationAdapter{}

			got := ActivateDelivery(ActivationRequest{
				Plan:     plan,
				Bindings: request.Bindings,
			}, adapter)

			if len(adapter.calls) != 1 {
				t.Fatalf("adapter calls = %d, want 1 fake activation attempt", len(adapter.calls))
			}
			if tt.wantActive {
				if got.Status != StatusActive {
					t.Fatalf("activation status = %q, want active", got.Status)
				}
				assertPlanModes(t, got.ActiveModes, []Mode{ModeHTTPProxy})
				assertActivationBindingStatus(t, got, binding.ID, ModeHTTPProxy, StatusActive)
				assertActivationBindingService(t, got, binding.ID, binding.ServiceID)
				if got.Warnings != nil {
					t.Fatalf("activation warnings = %#v, want none for safe http_proxy activation", got.Warnings)
				}
			} else {
				if got.Status != StatusSkipped {
					t.Fatalf("activation status = %q, want skipped fail-closed result", got.Status)
				}
				assertPlanModes(t, got.ActiveModes, nil)
				assertActivationWarning(t, got, WarningActivationSkipped, ReasonMissingServiceBinding, ModeHTTPProxy)
				assertActivationBindingStatus(t, got, binding.ID, ModeHTTPProxy, StatusSkipped)
			}
			assertActivationNoLeak(t, got, tt.rejected...)
		})
	}
}

func TestActivateDeliveryHTTPProxyRequiresBrokerAndNetworkProofs(t *testing.T) {
	binding := planBindingFixture(ModeHTTPProxy)
	activePlanRequest := planConstructionRequestFixture(binding)
	configureHTTPProxyProof(&activePlanRequest)
	activePlan := BuildDeliveryPlan(activePlanRequest)
	tests := []struct {
		name string
		plan Plan
	}{
		{
			name: "broker only",
			plan: func() Plan {
				plan := cloneHTTPProxyProofPlan(activePlan)
				plan.HTTPProxyProof.NetworkEnforcement = nil
				return plan
			}(),
		},
		{
			name: "network only",
			plan: Plan{
				ID:                    "delivery-plan-network-only",
				NetworkProxySessionID: "network-proxy-session-01",
				HTTPProxyProof: &HTTPProxyProof{
					BindingID:          binding.ID,
					SecretID:           binding.SecretRef,
					NetworkEnforcement: planNetworkEnforcementProofFixture(),
				},
				RequestedModes: []Mode{ModeHTTPProxy},
				ActiveModes:    []Mode{ModeHTTPProxy},
				Status:         StatusPlanned,
			},
		},
		{
			name: "credential proxy plan only",
			plan: Plan{
				ID:                    "delivery-plan-proxy-plan-only",
				NetworkProxySessionID: "network-proxy-session-01",
				HTTPProxyProof: &HTTPProxyProof{
					BindingID:             binding.ID,
					SecretID:              binding.SecretRef,
					SecretBrokerSessionID: "secret-broker-session-01",
					CredentialProxyPlanID: "credential-proxy-plan-01",
					NetworkEnforcement:    planNetworkEnforcementProofFixture(),
				},
				RequestedModes: []Mode{ModeHTTPProxy},
				ActiveModes:    []Mode{ModeHTTPProxy},
				Status:         StatusPlanned,
			},
		},
		{
			name: "session id only",
			plan: Plan{
				ID:                    "delivery-plan-session-only",
				NetworkProxySessionID: "network-proxy-session-01",
				RequestedModes:        []Mode{ModeHTTPProxy},
				ActiveModes:           []Mode{ModeHTTPProxy},
				Status:                StatusPlanned,
			},
		},
		{
			name: "requested mode only",
			plan: Plan{
				ID:             "delivery-plan-requested-only",
				RequestedModes: []Mode{ModeHTTPProxy},
				Status:         StatusPlanned,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ActivateDelivery(ActivationRequest{
				Plan:     tt.plan,
				Bindings: []Binding{binding},
			}, &fakeActivationAdapter{})

			if got.Status != StatusSkipped {
				t.Fatalf("activation status = %q, want skipped fail-closed result", got.Status)
			}
			assertPlanModes(t, got.ActiveModes, nil)
			assertActivationWarning(t, got, WarningActivationSkipped, ReasonMissingServiceBinding, ModeHTTPProxy)
			assertActivationBindingStatus(t, got, binding.ID, ModeHTTPProxy, StatusSkipped)
			assertActivationNoLeak(t, got)
		})
	}
}

func cloneHTTPProxyProofPlan(plan Plan) Plan {
	clone := plan
	if plan.HTTPProxyProof != nil {
		proof := *plan.HTTPProxyProof
		if plan.HTTPProxyProof.NetworkEnforcement != nil {
			network := *plan.HTTPProxyProof.NetworkEnforcement
			proof.NetworkEnforcement = &network
		}
		clone.HTTPProxyProof = &proof
	}
	return clone
}

func TestActivateDeliveryHTTPProxyDowngradesMismatchedProofIdentifiers(t *testing.T) {
	binding := planBindingFixture(ModeHTTPProxy)
	request := planConstructionRequestFixture(binding)
	configureHTTPProxyProof(&request)
	activePlan := BuildDeliveryPlan(request)
	tests := []struct {
		name      string
		configure func(*Plan)
	}{
		{
			name: "binding mismatch",
			configure: func(plan *Plan) {
				plan.HTTPProxyProof.BindingID = "binding-other"
			},
		},
		{
			name: "policy mismatch",
			configure: func(plan *Plan) {
				plan.HTTPProxyProof.NetworkEnforcement.PolicySnapshotID = "policy-snapshot-other"
			},
		},
		{
			name: "broker mismatch",
			configure: func(plan *Plan) {
				plan.HTTPProxyProof.SecretBrokerSessionID = ""
			},
		},
		{
			name: "proxy mismatch",
			configure: func(plan *Plan) {
				plan.HTTPProxyProof.NetworkEnforcement.NetworkProxySessionID = "network-proxy-session-other"
			},
		},
		{
			name: "result unsupported",
			configure: func(plan *Plan) {
				plan.HTTPProxyProof.NetworkEnforcement.ResultSupported = false
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := cloneHTTPProxyProofPlan(activePlan)
			tt.configure(&plan)

			got := ActivateDelivery(ActivationRequest{
				Plan:     plan,
				Bindings: []Binding{binding},
			}, &fakeActivationAdapter{})

			if got.Status != StatusSkipped {
				t.Fatalf("activation status = %q, want skipped for mismatched proof", got.Status)
			}
			assertPlanModes(t, got.ActiveModes, nil)
			assertActivationBindingStatus(t, got, binding.ID, ModeHTTPProxy, StatusSkipped)
			assertActivationWarning(t, got, WarningActivationSkipped, ReasonMissingServiceBinding, ModeHTTPProxy)
			assertActivationNoLeak(t, got)
		})
	}
}

func TestActivateDeliveryHTTPProxyAdapterFailureFailsClosedWithSafeBindingMetadata(t *testing.T) {
	binding := planBindingFixture(ModeHTTPProxy)
	request := planConstructionRequestFixture(binding)
	configureHTTPProxyProof(&request)
	plan := BuildDeliveryPlan(request)
	adapter := &fakeActivationAdapter{
		err: errors.New("proxy adapter failed for https://proxy.example.invalid with Authorization Bearer ghp_raw_secret_value"),
	}

	got := ActivateDelivery(ActivationRequest{
		Plan:     plan,
		Bindings: request.Bindings,
	}, adapter)

	if got.Status != StatusFailed {
		t.Fatalf("activation status = %q, want failed", got.Status)
	}
	assertPlanModes(t, got.ActiveModes, nil)
	assertActivationError(t, got, ErrorActivationFailed, "adapter")
	assertActivationBindingStatus(t, got, binding.ID, ModeHTTPProxy, StatusFailed)
	assertActivationBindingService(t, got, binding.ID, binding.ServiceID)
	assertActivationNoLeak(t, got, "https://proxy.example.invalid", "proxy.example.invalid", "Authorization", "ghp_raw_secret_value")
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
			ServiceID:    binding.ServiceID,
			DeliveryMode: binding.DeliveryMode,
			Outcome:      StatusActive,
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
			if binding.Outcome != status {
				t.Fatalf("activation binding outcome = %q, want %q in %#v", binding.Outcome, status, binding)
			}
			return
		}
	}
	t.Fatalf("activation bindings = %#v, want binding %q mode %q status %q", activation.Bindings, bindingID, mode, status)
}

func assertActivationBindingService(t *testing.T, activation ActivationResult, bindingID string, serviceID string) {
	t.Helper()

	for _, binding := range activation.Bindings {
		if binding.BindingID == bindingID {
			if binding.ServiceID != serviceID {
				t.Fatalf("activation binding service = %q, want %q in %#v", binding.ServiceID, serviceID, binding)
			}
			return
		}
	}
	t.Fatalf("activation bindings = %#v, want binding %q service %q", activation.Bindings, bindingID, serviceID)
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
