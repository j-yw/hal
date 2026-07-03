package credentialdelivery

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestCredentialDeliverySanitizeReturnsCopies(t *testing.T) {
	request := Request{
		ID:             " delivery-request-01 ",
		Source:         Source(" RUN "),
		RequestedModes: []Mode{" HTTP_PROXY "},
		ActiveModes:    []Mode{" ENV "},
		Bindings: []Binding{{
			ID:                    " binding-01 ",
			RequestID:             " delivery-request-01 ",
			PlanID:                " delivery-plan-01 ",
			PolicySnapshotID:      " policy-snapshot-01 ",
			SecretRef:             " env:GITHUB_TOKEN ",
			NetworkProxySessionID: " network-proxy-session-01 ",
			ServiceID:             " service-01 ",
			ServiceLabels:         []string{" source-control "},
			DomainLabels:          []string{" github "},
			DestinationCategory:   DestinationCategory(" PUBLIC_INTERNET "),
			DeliveryMode:          Mode(" HTTP_PROXY "),
			Status:                Status(" PLANNED "),
			ReasonCode:            ReasonCode(" REQUESTED "),
		}},
		Status: Status(" REQUESTED "),
	}
	originalPayload := mustMarshalCredentialDeliverySanitizeString(t, request)

	sanitized := SanitizeRequestMetadata(request)
	if afterPayload := mustMarshalCredentialDeliverySanitizeString(t, request); afterPayload != originalPayload {
		t.Fatalf("request input mutated: got %s, want %s", afterPayload, originalPayload)
	}
	if len(sanitized.RequestedModes) == 0 || &sanitized.RequestedModes[0] == &request.RequestedModes[0] {
		t.Fatalf("requested modes were not copied")
	}
	if len(sanitized.Bindings) == 0 || &sanitized.Bindings[0] == &request.Bindings[0] {
		t.Fatalf("bindings were not copied")
	}
	if len(sanitized.Bindings[0].ServiceLabels) == 0 || &sanitized.Bindings[0].ServiceLabels[0] == &request.Bindings[0].ServiceLabels[0] {
		t.Fatalf("binding service labels were not copied")
	}
	if sanitized.ID != "delivery-request-01" || sanitized.Bindings[0].SecretRef != "env:GITHUB_TOKEN" {
		t.Fatalf("sanitized request = %#v, want normalized safe copy", sanitized)
	}

	index := 1
	plan := Plan{
		ID:       " delivery-plan-01 ",
		Status:   Status(" PLANNED "),
		Warnings: []Warning{{Code: WarningCode(" BINDING_OMITTED "), BindingID: " binding-01 "}},
		Errors: []SanitizedError{{
			Code:      ErrorCode(" UNSAFE_REFERENCE "),
			Field:     " bindings.secretRef ",
			BindingID: " binding-01 ",
			Index:     &index,
		}},
	}
	originalPlanPayload := mustMarshalCredentialDeliverySanitizeString(t, plan)
	sanitizedPlan := SanitizePlanMetadata(plan)
	if afterPayload := mustMarshalCredentialDeliverySanitizeString(t, plan); afterPayload != originalPlanPayload {
		t.Fatalf("plan input mutated: got %s, want %s", afterPayload, originalPlanPayload)
	}
	if len(sanitizedPlan.Errors) == 0 || sanitizedPlan.Errors[0].Index == plan.Errors[0].Index {
		t.Fatalf("sanitized error index was not copied")
	}
	if sanitizedPlan.Warnings[0].Code != WarningBindingOmitted || sanitizedPlan.Errors[0].Code != ErrorUnsafeReference {
		t.Fatalf("sanitized plan = %#v, want normalized warning/error copies", sanitizedPlan)
	}
}

func TestCredentialDeliverySanitizePreservesNilAndEmptySlices(t *testing.T) {
	request := SanitizeRequestMetadata(Request{
		ID:             "delivery-request-01",
		RequestedModes: nil,
		ActiveModes:    []Mode{},
		Bindings:       []Binding{},
	})
	if request.RequestedModes != nil {
		t.Fatalf("requested modes = %#v, want nil", request.RequestedModes)
	}
	if request.ActiveModes == nil || len(request.ActiveModes) != 0 {
		t.Fatalf("active modes = %#v, want explicit empty slice", request.ActiveModes)
	}
	if request.Bindings == nil || len(request.Bindings) != 0 {
		t.Fatalf("bindings = %#v, want explicit empty slice", request.Bindings)
	}

	plan := SanitizePlanMetadata(Plan{
		ID:             "delivery-plan-01",
		RequestedModes: []Mode{},
		Warnings:       nil,
		Errors:         []SanitizedError{},
	})
	if plan.RequestedModes == nil || len(plan.RequestedModes) != 0 {
		t.Fatalf("plan requested modes = %#v, want explicit empty slice", plan.RequestedModes)
	}
	if plan.Warnings != nil {
		t.Fatalf("plan warnings = %#v, want nil", plan.Warnings)
	}
	if plan.Errors == nil || len(plan.Errors) != 0 {
		t.Fatalf("plan errors = %#v, want explicit empty slice", plan.Errors)
	}

	activation := SanitizeActivationResultMetadata(ActivationResult{
		ID:       "activation-01",
		PlanID:   "delivery-plan-01",
		Bindings: []BindingActivationResult{},
		Warnings: []Warning{},
	})
	if activation.Bindings == nil || len(activation.Bindings) != 0 || activation.Warnings == nil || len(activation.Warnings) != 0 {
		t.Fatalf("activation slices = %#v %#v, want explicit empty slices", activation.Bindings, activation.Warnings)
	}
}

func TestCredentialDeliverySanitizeDropsUnsafeOptionalMetadata(t *testing.T) {
	binding := SanitizeBindingMetadata(Binding{
		ID:                    "binding-01",
		RequestID:             "https://example.invalid/request?token=value",
		PlanID:                "/Users/alice/plan.json",
		PolicySnapshotID:      "policy-snapshot-01",
		SecretRef:             "env:GITHUB_TOKEN",
		NetworkProxySessionID: "/tmp/credential-proxy.sock",
		ServiceID:             "api.example.invalid",
		ServiceLabels:         []string{"source-control", "Authorization"},
		DomainLabels:          []string{"github", "api.github.com"},
		DestinationCategory:   DestinationCategory("https://example.invalid/api"),
		DeliveryMode:          ModeEnv,
		Status:                Status("TOKEN=value"),
		ReasonCode:            ReasonCode("secretValue=raw-secret"),
	})
	if reflect.DeepEqual(binding, Binding{}) {
		t.Fatal("binding was zeroed, want required safe metadata preserved")
	}
	if binding.RequestID != "" || binding.PlanID != "" || binding.NetworkProxySessionID != "" || binding.ServiceID != "" {
		t.Fatalf("binding optional references = %#v, want unsafe references dropped", binding)
	}
	if binding.PolicySnapshotID != "policy-snapshot-01" {
		t.Fatalf("policy snapshot id = %q, want safe optional reference preserved", binding.PolicySnapshotID)
	}
	if !reflect.DeepEqual(binding.ServiceLabels, []string{"source-control"}) || !reflect.DeepEqual(binding.DomainLabels, []string{"github"}) {
		t.Fatalf("binding labels = %#v %#v, want unsafe labels removed", binding.ServiceLabels, binding.DomainLabels)
	}
	if binding.DestinationCategory != "" || binding.Status != "" || binding.ReasonCode != "" {
		t.Fatalf("binding optional enum metadata = %#v, want unsafe values dropped", binding)
	}

	plan := SanitizePlanMetadata(Plan{
		ID:                    "delivery-plan-01",
		RequestID:             "https://example.invalid/request",
		NetworkProxySessionID: "/tmp/credential-proxy.sock",
		RequestedModes:        []Mode{ModeEnv, Mode("https://example.invalid/mode"), Mode("TOKEN=value")},
		ActiveModes:           []Mode{ModeHTTPProxy},
		Warnings: []Warning{{
			Code:      WarningBindingOmitted,
			BindingID: "https://example.invalid/binding",
			Mode:      Mode("https://example.invalid/mode"),
		}},
		Errors: []SanitizedError{{
			Code:      ErrorUnsafeReference,
			Field:     "https://example.invalid/field",
			BindingID: "/tmp/binding",
			Mode:      Mode("TOKEN=value"),
		}},
	})
	if plan.RequestID != "" || plan.NetworkProxySessionID != "" || !reflect.DeepEqual(plan.RequestedModes, []Mode{ModeEnv}) {
		t.Fatalf("plan optional metadata = %#v, want unsafe request id and modes dropped", plan)
	}
	if plan.Warnings[0].BindingID != "" || plan.Warnings[0].Mode != "" {
		t.Fatalf("warning metadata = %#v, want unsafe optional metadata dropped", plan.Warnings[0])
	}
	if plan.Errors[0].Field != "" || plan.Errors[0].BindingID != "" || plan.Errors[0].Mode != "" {
		t.Fatalf("error metadata = %#v, want unsafe optional metadata dropped", plan.Errors[0])
	}

	assertCredentialDeliverySanitizeNoUnsafeLeak(t, binding,
		"https://example.invalid/request?token=value",
		"/Users/alice/plan.json",
		"/tmp/credential-proxy.sock",
		"api.example.invalid",
		"Authorization",
		"api.github.com",
		"TOKEN=value",
		"secretValue=raw-secret",
	)
	assertCredentialDeliverySanitizeNoUnsafeLeak(t, plan,
		"https://example.invalid/request",
		"/tmp/credential-proxy.sock",
		"https://example.invalid/mode",
		"https://example.invalid/binding",
		"https://example.invalid/field",
		"/tmp/binding",
		"TOKEN=value",
	)
}

func TestCredentialDeliverySanitizeRemovesUnsafeRequiredRecords(t *testing.T) {
	tests := []struct {
		name string
		got  any
		want any
	}{
		{
			name: "request id unsafe",
			got: SanitizeRequestMetadata(Request{
				ID: "https://example.invalid/request?token=value",
			}),
			want: Request{},
		},
		{
			name: "binding secret unsafe",
			got: SanitizeBindingMetadata(Binding{
				ID:           "binding-01",
				SecretRef:    "secretValue=raw-secret",
				DeliveryMode: ModeEnv,
			}),
			want: Binding{},
		},
		{
			name: "activation plan id unsafe",
			got: SanitizeActivationResultMetadata(ActivationResult{
				ID:     "activation-01",
				PlanID: "/Users/alice/plan.json",
			}),
			want: ActivationResult{},
		},
		{
			name: "activation binding optional metadata unsafe",
			got: SanitizeBindingActivationResultMetadata(BindingActivationResult{
				BindingID:    "binding-01",
				ServiceID:    "api.example.invalid",
				DeliveryMode: ModeHTTPProxy,
				Outcome:      Status("TOKEN=value"),
				Status:       StatusActive,
			}),
			want: BindingActivationResult{
				BindingID:    "binding-01",
				DeliveryMode: ModeHTTPProxy,
				Status:       StatusActive,
			},
		},
		{
			name: "warning code unsafe",
			got: SanitizeWarningMetadata(Warning{
				Code: WarningCode("Authorization"),
			}),
			want: Warning{},
		},
		{
			name: "error code unsafe",
			got: SanitizeSanitizedError(SanitizedError{
				Code: ErrorCode("TOKEN=value"),
			}),
			want: SanitizedError{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !reflect.DeepEqual(tt.got, tt.want) {
				t.Fatalf("sanitized record = %#v, want %#v", tt.got, tt.want)
			}
		})
	}

	bindings := SanitizeBindingMetadataRecords([]Binding{
		safeBindingFixture(),
		{ID: "https://example.invalid/binding", SecretRef: "secret-ref-02", DeliveryMode: ModeEnv},
		{ID: "binding-03", SecretRef: "secret-ref-03", DeliveryMode: Mode("tmp_file")},
	})
	if len(bindings) != 1 || bindings[0].ID != "binding-01" {
		t.Fatalf("sanitized binding records = %#v, want only the safe binding", bindings)
	}

	request := SanitizeRequestMetadata(Request{
		ID: "delivery-request-01",
		Bindings: []Binding{
			safeBindingFixture(),
			{ID: "binding-unsafe", SecretRef: "Authorization: Bearer raw-token", DeliveryMode: ModeEnv},
		},
	})
	if len(request.Bindings) != 1 || request.Bindings[0].ID != "binding-01" {
		t.Fatalf("sanitized request bindings = %#v, want unsafe required binding omitted", request.Bindings)
	}

	warnings := SanitizeWarningMetadataRecords([]Warning{
		{Code: WarningBindingOmitted},
		{Code: WarningCode("https://example.invalid/warning")},
	})
	if len(warnings) != 1 || warnings[0].Code != WarningBindingOmitted {
		t.Fatalf("sanitized warning records = %#v, want unsafe required warning omitted", warnings)
	}

	errors := SanitizeSanitizedErrorRecords([]SanitizedError{
		{Code: ErrorUnsafeReference, Field: "bindings.secretRef"},
		{Code: ErrorCode("https://example.invalid/error"), Field: "bindings.secretRef"},
	})
	if len(errors) != 1 || errors[0].Code != ErrorUnsafeReference {
		t.Fatalf("sanitized error records = %#v, want unsafe required error omitted", errors)
	}
}

func assertCredentialDeliverySanitizeNoUnsafeLeak(t *testing.T, value any, unsafeValues ...string) {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error: %v", value, err)
	}
	for _, payload := range []string{fmt.Sprintf("%#v", value), string(data)} {
		for _, unsafeValue := range unsafeValues {
			if unsafeValue == "" {
				continue
			}
			for _, forbidden := range []string{unsafeValue, credentialDeliverySanitizeJSONEscapedStringFragment(t, unsafeValue)} {
				if forbidden == "" {
					continue
				}
				if strings.Contains(payload, forbidden) {
					t.Fatalf("sanitized payload leaked rejected value %q in %s", forbidden, payload)
				}
			}
		}
	}
}

func mustMarshalCredentialDeliverySanitizeString(t *testing.T, value any) string {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error: %v", value, err)
	}
	return string(data)
}

func credentialDeliverySanitizeJSONEscapedStringFragment(t *testing.T, value string) string {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%q) error: %v", value, err)
	}
	escaped := string(data)
	if len(escaped) < 2 {
		return escaped
	}
	return escaped[1 : len(escaped)-1]
}
