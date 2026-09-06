package credentialdelivery

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBindingValidationAcceptsSafeRoutingMetadata(t *testing.T) {
	got := ValidateBindingMetadata(Binding{
		ID:                    "binding-01",
		RequestID:             "delivery-request-01",
		PlanID:                "delivery-plan-01",
		PolicySnapshotID:      "policy-snapshot-01",
		SecretRef:             "env:GITHUB_TOKEN",
		NetworkProxySessionID: "network-proxy-session-01",
		ServiceID:             "service-01",
		ServiceLabels:         []string{"source-control", "package-registry"},
		DomainLabels:          []string{"github", "registry"},
		DestinationCategory:   DestinationPublicInternet,
		DeliveryMode:          ModeHTTPProxy,
		Status:                StatusPlanned,
		ReasonCode:            ReasonRequested,
	})
	assertBindingValidationValid(t, got)
}

func TestBindingValidationRejectsUnsafeRoutingMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Binding)
		code   ErrorCode
		field  string
		index  *int
		leaks  []string
	}{
		{
			name: "binding id url",
			mutate: func(binding *Binding) {
				binding.ID = "https://user:pass@example.invalid/binding?token=value"
			},
			code:  ErrorUnsafeReference,
			field: "id",
			leaks: []string{"https://user:pass@example.invalid/binding?token=value"},
		},
		{
			name: "service id raw domain",
			mutate: func(binding *Binding) {
				binding.ServiceID = "api.example.invalid"
			},
			code:  ErrorUnsafeReference,
			field: "serviceId",
			leaks: []string{"api.example.invalid"},
		},
		{
			name: "policy snapshot path",
			mutate: func(binding *Binding) {
				binding.PolicySnapshotID = "/Users/alice/policies/rules.json"
			},
			code:  ErrorUnsafeReference,
			field: "policySnapshotId",
			leaks: []string{"/Users/alice/policies/rules.json"},
		},
		{
			name: "network proxy session url",
			mutate: func(binding *Binding) {
				binding.NetworkProxySessionID = "https://proxy.example.invalid/session?token=value"
			},
			code:  ErrorUnsafeReference,
			field: "networkProxySessionId",
			leaks: []string{"https://proxy.example.invalid/session?token=value"},
		},
		{
			name: "plan id socket path",
			mutate: func(binding *Binding) {
				binding.PlanID = "/tmp/credential-proxy.sock"
			},
			code:  ErrorUnsafeReference,
			field: "planId",
			leaks: []string{"/tmp/credential-proxy.sock"},
		},
		{
			name: "secret ref token",
			mutate: func(binding *Binding) {
				binding.SecretRef = "ghp_raw_token_123"
			},
			code:  ErrorUnsafeReference,
			field: "secretRef",
			leaks: []string{"ghp_raw_token_123"},
		},
		{
			name: "secret ref raw secret marker",
			mutate: func(binding *Binding) {
				binding.SecretRef = "secretValue=raw-secret"
			},
			code:  ErrorUnsafeReference,
			field: "secretRef",
			leaks: []string{"secretValue=raw-secret"},
		},
		{
			name: "service label authorization header",
			mutate: func(binding *Binding) {
				binding.ServiceLabels = []string{"Authorization"}
			},
			code:  ErrorUnsafeMetadata,
			field: "serviceLabels",
			index: intPtr(0),
			leaks: []string{"Authorization"},
		},
		{
			name: "service label api key header",
			mutate: func(binding *Binding) {
				binding.ServiceLabels = []string{"X-Api-Key"}
			},
			code:  ErrorUnsafeMetadata,
			field: "serviceLabels",
			index: intPtr(0),
			leaks: []string{"X-Api-Key"},
		},
		{
			name: "domain label raw domain",
			mutate: func(binding *Binding) {
				binding.DomainLabels = []string{"api.github.com"}
			},
			code:  ErrorUnsafeMetadata,
			field: "domainLabels",
			index: intPtr(0),
			leaks: []string{"api.github.com"},
		},
		{
			name: "domain label path",
			mutate: func(binding *Binding) {
				binding.DomainLabels = []string{"/var/run/proxy.sock"}
			},
			code:  ErrorUnsafeMetadata,
			field: "domainLabels",
			index: intPtr(0),
			leaks: []string{"/var/run/proxy.sock"},
		},
		{
			name: "domain label secret-looking string",
			mutate: func(binding *Binding) {
				binding.DomainLabels = []string{"credentialValue"}
			},
			code:  ErrorUnsafeMetadata,
			field: "domainLabels",
			index: intPtr(0),
			leaks: []string{"credentialValue"},
		},
		{
			name: "destination category raw url",
			mutate: func(binding *Binding) {
				binding.DestinationCategory = DestinationCategory("https://api.example.invalid")
			},
			code:  ErrorUnsafeMetadata,
			field: "destinationCategory",
			leaks: []string{"https://api.example.invalid"},
		},
		{
			name: "destination category unsupported",
			mutate: func(binding *Binding) {
				binding.DestinationCategory = DestinationCategory("external_host")
			},
			code:  ErrorUnsupportedCategory,
			field: "destinationCategory",
			leaks: []string{"external_host"},
		},
		{
			name: "delivery mode url",
			mutate: func(binding *Binding) {
				binding.DeliveryMode = Mode("https://example.invalid/mode")
			},
			code:  ErrorUnsafeMetadata,
			field: "deliveryMode",
			leaks: []string{"https://example.invalid/mode"},
		},
		{
			name: "delivery mode unsupported",
			mutate: func(binding *Binding) {
				binding.DeliveryMode = Mode("tmp_file")
			},
			code:  ErrorUnsupportedMode,
			field: "deliveryMode",
			leaks: []string{"tmp_file"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := safeBindingFixture()
			tt.mutate(&binding)

			got := ValidateBindingMetadata(binding)
			assertBindingValidationError(t, got, tt.code, tt.field, tt.index)
			assertBindingValidationNoUnsafeLeak(t, got, tt.leaks...)
		})
	}
}

func TestBindingPersistedJSONFixtureContainsOnlySafeRoutingMetadata(t *testing.T) {
	binding := Binding{
		ID:                    "binding-01",
		RequestID:             "delivery-request-01",
		PlanID:                "delivery-plan-01",
		PolicySnapshotID:      "policy-snapshot-01",
		SecretRef:             "broker-secret-01",
		NetworkProxySessionID: "network-proxy-session-01",
		ServiceID:             "service-01",
		ServiceLabels:         []string{"source-control"},
		DomainLabels:          []string{"github"},
		DestinationCategory:   DestinationPrivateNetwork,
		DeliveryMode:          ModeHTTPProxy,
		Status:                StatusPlanned,
		ReasonCode:            ReasonRequested,
	}
	assertBindingValidationValid(t, ValidateBindingMetadata(binding))

	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatalf("json.Marshal(binding) error: %v", err)
	}
	payload := string(data)
	for _, forbidden := range []string{
		"https://",
		"example.invalid",
		"Authorization",
		"Bearer",
		"ghp_",
		"credentialValue",
		"secretValue",
		"/Users/",
		"/tmp/",
		".sock",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("persisted binding fixture leaked %q in %s", forbidden, payload)
		}
	}

	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(binding) error: %v", err)
	}
	assertJSONKeysExcludeUnsafeRawFields(t, decoded, "$")
}

func safeBindingFixture() Binding {
	return Binding{
		ID:                    "binding-01",
		RequestID:             "delivery-request-01",
		PlanID:                "delivery-plan-01",
		PolicySnapshotID:      "policy-snapshot-01",
		SecretRef:             "secret-ref-01",
		NetworkProxySessionID: "network-proxy-session-01",
		ServiceID:             "service-01",
		ServiceLabels:         []string{"source-control"},
		DomainLabels:          []string{"github"},
		DestinationCategory:   DestinationPublicInternet,
		DeliveryMode:          ModeHTTPProxy,
		Status:                StatusPlanned,
		ReasonCode:            ReasonRequested,
	}
}

func assertBindingValidationValid(t *testing.T, result ValidationResult) {
	t.Helper()

	if !result.Valid {
		t.Fatalf("binding validation valid = false, errors: %#v", result.Errors)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("binding validation errors = %#v, want none", result.Errors)
	}
}

func assertBindingValidationError(t *testing.T, result ValidationResult, code ErrorCode, field string, index *int) {
	t.Helper()

	if result.Valid {
		t.Fatalf("binding validation valid = true, want false")
	}
	for _, err := range result.Errors {
		if err.Code != code || err.Field != field {
			continue
		}
		switch {
		case index == nil && err.Index == nil:
			return
		case index != nil && err.Index != nil && *index == *err.Index:
			return
		}
	}
	t.Fatalf("binding validation errors = %#v, want code %q field %q index %#v", result.Errors, code, field, index)
}

func assertBindingValidationNoUnsafeLeak(t *testing.T, result ValidationResult, rejectedValues ...string) {
	t.Helper()

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	payload := string(data)
	for _, forbidden := range []string{
		"https://",
		"example.invalid",
		"/Users/",
		"/tmp/",
		"/var/run/",
		"Authorization",
		"Bearer",
		"X-Api-Key",
		"ghp_",
		"credentialValue",
		"secretValue",
		"raw-secret",
		"\n",
		"\u001f",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("binding validation result leaked unsafe value %q in %s", forbidden, payload)
		}
	}
	for _, err := range result.Errors {
		if strings.Contains(err.Error(), "https://") || strings.Contains(err.Error(), "example.invalid") {
			t.Fatalf("binding validation error string leaked unsafe input: %q", err.Error())
		}
		for _, rejected := range rejectedValues {
			if rejected == "" {
				continue
			}
			if strings.Contains(payload, rejected) || strings.Contains(err.Error(), rejected) {
				t.Fatalf("binding validation leaked rejected value %q in %s / %q", rejected, payload, err.Error())
			}
		}
	}
}

func intPtr(value int) *int {
	return &value
}
