package credentialdelivery

import "testing"

func TestCredentialDeliveryNormalizationTrimsReferencesAndLowercasesEnums(t *testing.T) {
	request := NormalizeRequestMetadata(Request{
		ID:             " DeliveryRequest-01 ",
		Source:         Source(" RUN "),
		RequestedModes: []Mode{" HTTP_PROXY ", " ENV "},
		ActiveModes:    []Mode{" SSH_AGENT "},
		Bindings: []Binding{{
			ID:                    " Binding-01 ",
			RequestID:             " DeliveryRequest-01 ",
			PlanID:                " DeliveryPlan-01 ",
			PolicySnapshotID:      " PolicySnapshot-01 ",
			SecretRef:             " env:GITHUB_TOKEN ",
			NetworkProxySessionID: " NetworkProxySession-01 ",
			ServiceID:             " Service-01 ",
			ServiceLabels:         []string{" source-control "},
			DomainLabels:          []string{" github "},
			DestinationCategory:   DestinationCategory(" PUBLIC_INTERNET "),
			DeliveryMode:          Mode(" HTTP_PROXY "),
			Status:                Status(" PLANNED "),
			ReasonCode:            ReasonCode(" REQUESTED "),
		}},
		Status: Status(" REQUESTED "),
	})
	if request.ID != "DeliveryRequest-01" || request.Source != SourceRun || request.Status != StatusRequested {
		t.Fatalf("request metadata = %#v, want trimmed IDs and lowercased enums", request)
	}
	if request.RequestedModes[0] != ModeHTTPProxy || request.RequestedModes[1] != ModeEnv || request.ActiveModes[0] != ModeSSHAgent {
		t.Fatalf("request modes = %#v %#v, want normalized modes", request.RequestedModes, request.ActiveModes)
	}
	binding := request.Bindings[0]
	if binding.ID != "Binding-01" || binding.RequestID != "DeliveryRequest-01" || binding.SecretRef != "env:GITHUB_TOKEN" {
		t.Fatalf("binding references = %#v, want trimmed references", binding)
	}
	if binding.DestinationCategory != DestinationPublicInternet || binding.DeliveryMode != ModeHTTPProxy || binding.Status != StatusPlanned || binding.ReasonCode != ReasonRequested {
		t.Fatalf("binding enum metadata = %#v, want lowercased enum-like metadata", binding)
	}
	assertRequestValidationValid(t, ValidateRequestMetadata(request))

	plan := NormalizePlanMetadata(Plan{
		ID:                    " DeliveryPlan-01 ",
		RequestID:             " DeliveryRequest-01 ",
		NetworkProxySessionID: " NetworkProxySession-01 ",
		RequestedModes:        []Mode{" LEGACY_AUTH_SYNC "},
		ActiveModes:           []Mode{" HTTP_PROXY "},
		Status:                Status(" PLANNED "),
		Warnings: []Warning{{
			Code:       WarningCode(" LEGACY_AUTH_COMPATIBILITY "),
			ReasonCode: ReasonCode(" COMPATIBILITY_MODE "),
			BindingID:  " Binding-01 ",
			Mode:       Mode(" LEGACY_AUTH_SYNC "),
		}},
		Errors: []SanitizedError{{
			Code:       ErrorCode(" UNSUPPORTED_MODE "),
			Field:      " requestedModes ",
			BindingID:  " Binding-01 ",
			Mode:       Mode(" LEGACY_AUTH_SYNC "),
			ReasonCode: ReasonCode(" UNSUPPORTED_MODE "),
		}},
	})
	if plan.ID != "DeliveryPlan-01" || plan.RequestID != "DeliveryRequest-01" || plan.NetworkProxySessionID != "NetworkProxySession-01" || plan.Status != StatusPlanned {
		t.Fatalf("plan metadata = %#v, want normalized plan", plan)
	}
	if plan.Warnings[0].Code != WarningLegacyAuthCompatibility || plan.Errors[0].Code != ErrorUnsupportedMode {
		t.Fatalf("plan warning/error metadata = %#v %#v, want normalized codes", plan.Warnings, plan.Errors)
	}

	activation := NormalizeActivationResultMetadata(ActivationResult{
		ID:             " Activation-01 ",
		PlanID:         " DeliveryPlan-01 ",
		RequestedModes: []Mode{" FILE_TMPFS "},
		Bindings: []BindingActivationResult{{
			BindingID:    " Binding-01 ",
			ServiceID:    " Service-01 ",
			DeliveryMode: Mode(" FILE_TMPFS "),
			Outcome:      Status(" ACTIVE "),
			Status:       Status(" ACTIVE "),
			ReasonCode:   ReasonCode(" REQUESTED "),
		}},
		Status: Status(" ACTIVE "),
	})
	if activation.ID != "Activation-01" || activation.PlanID != "DeliveryPlan-01" || activation.Bindings[0].ServiceID != "Service-01" || activation.Bindings[0].DeliveryMode != ModeFileTmpfs || activation.Bindings[0].Outcome != StatusActive {
		t.Fatalf("activation metadata = %#v, want normalized activation result", activation)
	}
}

func TestCredentialDeliveryNormalizationPreservesNilAndEmptySlices(t *testing.T) {
	nilRequest := NormalizeRequestMetadata(Request{ID: "delivery-request-01"})
	if nilRequest.RequestedModes != nil || nilRequest.ActiveModes != nil || nilRequest.Bindings != nil {
		t.Fatalf("nil request slices normalized to %#v, want nil slices", nilRequest)
	}

	emptyRequest := NormalizeRequestMetadata(Request{
		ID:             "delivery-request-01",
		RequestedModes: []Mode{},
		ActiveModes:    []Mode{},
		Bindings:       []Binding{},
	})
	if emptyRequest.RequestedModes == nil || emptyRequest.ActiveModes == nil || emptyRequest.Bindings == nil {
		t.Fatalf("empty request slices normalized to %#v, want explicit empty slices", emptyRequest)
	}

	if got := NormalizeBindingMetadataRecords(nil); got != nil {
		t.Fatalf("nil binding records normalized to %#v, want nil", got)
	}
	if got := NormalizeBindingMetadataRecords([]Binding{}); got == nil || len(got) != 0 {
		t.Fatalf("empty binding records normalized to %#v, want explicit empty slice", got)
	}
	if got := NormalizeWarningMetadataRecords([]Warning{}); got == nil || len(got) != 0 {
		t.Fatalf("empty warning records normalized to %#v, want explicit empty slice", got)
	}
	if got := NormalizeSanitizedErrorRecords([]SanitizedError{}); got == nil || len(got) != 0 {
		t.Fatalf("empty error records normalized to %#v, want explicit empty slice", got)
	}
}

func TestCredentialDeliveryNormalizationDoesNotConvertUnsafeRawValuesIntoAcceptedValues(t *testing.T) {
	request := NormalizeRequestMetadata(Request{
		ID:             " https://user:pass@example.invalid/request?token=value ",
		Source:         Source(" RUN "),
		RequestedModes: []Mode{" HTTPS://EXAMPLE.INVALID/MODE "},
		Bindings: []Binding{{
			ID:           "binding-01",
			SecretRef:    " secretValue=raw-secret ",
			DeliveryMode: Mode(" HTTP_PROXY "),
		}},
	})

	got := ValidateRequestMetadata(request)
	assertRequestValidationError(t, got, ErrorUnsafeReference, "id", nil)
	assertRequestValidationError(t, got, ErrorUnsafeMetadata, "requestedModes", intPtr(0))
	assertRequestValidationError(t, got, ErrorUnsafeReference, "bindings.secretRef", intPtr(0))
	assertRequestValidationNoUnsafeLeak(t, got, "https://user:pass@example.invalid/request?token=value", "secretValue=raw-secret")
}
