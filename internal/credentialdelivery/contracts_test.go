package credentialdelivery

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSupportedModes(t *testing.T) {
	want := []Mode{
		ModeHTTPProxy,
		ModeSSHAgent,
		ModeFileTmpfs,
		ModeEnv,
		ModeLegacyAuthSync,
	}
	if got := SupportedModes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedModes() = %#v, want %#v", got, want)
	}

	tests := []struct {
		name string
		got  Mode
		want string
	}{
		{name: "http proxy", got: ModeHTTPProxy, want: "http_proxy"},
		{name: "ssh agent", got: ModeSSHAgent, want: "ssh_agent"},
		{name: "file tmpfs", got: ModeFileTmpfs, want: "file_tmpfs"},
		{name: "env", got: ModeEnv, want: "env"},
		{name: "legacy auth sync", got: ModeLegacyAuthSync, want: "legacy_auth_sync"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Fatalf("mode = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestSupportedDestinationCategories(t *testing.T) {
	want := []DestinationCategory{
		DestinationPublicInternet,
		DestinationPrivateNetwork,
		DestinationMetadataService,
		DestinationLoopback,
		DestinationUnixSocket,
		DestinationUnknown,
	}
	if got := SupportedDestinationCategories(); !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedDestinationCategories() = %#v, want %#v", got, want)
	}

	tests := []struct {
		name string
		got  DestinationCategory
		want string
	}{
		{name: "public internet", got: DestinationPublicInternet, want: "public_internet"},
		{name: "private network", got: DestinationPrivateNetwork, want: "private_network"},
		{name: "metadata service", got: DestinationMetadataService, want: "metadata_service"},
		{name: "loopback", got: DestinationLoopback, want: "loopback"},
		{name: "unix socket", got: DestinationUnixSocket, want: "unix_socket"},
		{name: "unknown", got: DestinationUnknown, want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Fatalf("destination category = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestContractConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "source run", got: string(SourceRun), want: "run"},
		{name: "source auto", got: string(SourceAuto), want: "auto"},
		{name: "source factory", got: string(SourceFactory), want: "factory"},
		{name: "source worker", got: string(SourceWorker), want: "worker"},
		{name: "source runtime", got: string(SourceRuntime), want: "runtime"},
		{name: "status requested", got: string(StatusRequested), want: "requested"},
		{name: "status planned", got: string(StatusPlanned), want: "planned"},
		{name: "status ready", got: string(StatusReady), want: "ready"},
		{name: "status active", got: string(StatusActive), want: "active"},
		{name: "status completed", got: string(StatusCompleted), want: "completed"},
		{name: "status skipped", got: string(StatusSkipped), want: "skipped"},
		{name: "status failed", got: string(StatusFailed), want: "failed"},
		{name: "status disabled", got: string(StatusDisabled), want: "disabled"},
		{name: "reason requested", got: string(ReasonRequested), want: "requested"},
		{name: "reason unsupported mode", got: string(ReasonUnsupportedMode), want: "unsupported_mode"},
		{name: "reason missing secret reference", got: string(ReasonMissingSecretReference), want: "missing_secret_reference"},
		{name: "reason missing service binding", got: string(ReasonMissingServiceBinding), want: "missing_service_binding"},
		{name: "reason activation unavailable", got: string(ReasonActivationUnavailable), want: "activation_unavailable"},
		{name: "reason compatibility mode", got: string(ReasonCompatibilityMode), want: "compatibility_mode"},
		{name: "reason disabled", got: string(ReasonDisabled), want: "disabled"},
		{name: "reason unknown", got: string(ReasonUnknown), want: "unknown"},
		{name: "warning unsupported mode", got: string(WarningUnsupportedMode), want: "unsupported_mode"},
		{name: "warning binding omitted", got: string(WarningBindingOmitted), want: "binding_omitted"},
		{name: "warning activation skipped", got: string(WarningActivationSkipped), want: "activation_skipped"},
		{name: "warning adapter unavailable", got: string(WarningAdapterUnavailable), want: "adapter_unavailable"},
		{name: "warning legacy auth compatibility", got: string(WarningLegacyAuthCompatibility), want: "legacy_auth_compatibility"},
		{name: "error missing required field", got: string(ErrorMissingRequiredField), want: "missing_required_field"},
		{name: "error missing secret reference", got: string(ErrorMissingSecretReference), want: "missing_secret_reference"},
		{name: "error unsupported mode", got: string(ErrorUnsupportedMode), want: "unsupported_mode"},
		{name: "error unsupported category", got: string(ErrorUnsupportedCategory), want: "unsupported_category"},
		{name: "error unsafe reference", got: string(ErrorUnsafeReference), want: "unsafe_reference"},
		{name: "error unsafe metadata", got: string(ErrorUnsafeMetadata), want: "unsafe_metadata"},
		{name: "error duplicate binding", got: string(ErrorDuplicateBinding), want: "duplicate_binding"},
		{name: "error resolver failed", got: string(ErrorResolverFailed), want: "resolver_failed"},
		{name: "error activation failed", got: string(ErrorActivationFailed), want: "activation_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestRequestJSONContract(t *testing.T) {
	request := Request{
		ID:             "delivery-request-01",
		Source:         SourceRun,
		RequestedModes: []Mode{ModeHTTPProxy, ModeSSHAgent},
		ActiveModes:    []Mode{ModeHTTPProxy},
		Bindings: []Binding{{
			ID:                    "binding-01",
			PolicySnapshotID:      "policy-snapshot-01",
			SecretRef:             "secret-ref-01",
			NetworkProxySessionID: "network-proxy-session-01",
			ServiceID:             "service-01",
			ServiceLabels:         []string{"source-control"},
			DomainLabels:          []string{"github"},
			DestinationCategory:   DestinationPublicInternet,
			DeliveryMode:          ModeHTTPProxy,
			Status:                StatusRequested,
			ReasonCode:            ReasonRequested,
		}},
		Status: StatusRequested,
	}
	got := mustMarshalObject(t, request)
	assertObjectKeys(t, got, []string{
		"id",
		"source",
		"requestedModes",
		"activeModes",
		"bindings",
		"status",
	}, forbiddenRawFieldNames())

	minimal := mustMarshalObject(t, Request{ID: "delivery-request-02"})
	assertObjectKeys(t, minimal, []string{"id"}, []string{
		"source",
		"requestedModes",
		"activeModes",
		"bindings",
		"status",
	})
}

func TestBindingJSONContract(t *testing.T) {
	binding := Binding{
		ID:                    "binding-01",
		RequestID:             "delivery-request-01",
		PlanID:                "delivery-plan-01",
		PolicySnapshotID:      "policy-snapshot-01",
		SecretRef:             "secret-ref-01",
		NetworkProxySessionID: "network-proxy-session-01",
		ServiceID:             "service-01",
		ServiceLabels:         []string{"source-control", "package-registry"},
		DomainLabels:          []string{"github", "registry"},
		DestinationCategory:   DestinationPrivateNetwork,
		DeliveryMode:          ModeFileTmpfs,
		Status:                StatusPlanned,
		ReasonCode:            ReasonRequested,
	}
	got := mustMarshalObject(t, binding)
	assertObjectKeys(t, got, []string{
		"id",
		"requestId",
		"planId",
		"policySnapshotId",
		"secretRef",
		"networkProxySessionId",
		"serviceId",
		"serviceLabels",
		"domainLabels",
		"destinationCategory",
		"deliveryMode",
		"status",
		"reasonCode",
	}, forbiddenRawFieldNames())

	minimal := mustMarshalObject(t, Binding{
		ID:           "binding-02",
		SecretRef:    "secret-ref-02",
		DeliveryMode: ModeEnv,
	})
	assertObjectKeys(t, minimal, []string{"id", "secretRef", "deliveryMode"}, []string{
		"requestId",
		"planId",
		"policySnapshotId",
		"networkProxySessionId",
		"serviceId",
		"serviceLabels",
		"domainLabels",
		"destinationCategory",
		"status",
		"reasonCode",
	})
}

func TestPlanJSONContract(t *testing.T) {
	index := 0
	plan := Plan{
		ID:                    "delivery-plan-01",
		RequestID:             "delivery-request-01",
		NetworkProxySessionID: "network-proxy-session-01",
		RequestedModes:        []Mode{ModeHTTPProxy, ModeLegacyAuthSync},
		ActiveModes:           []Mode{ModeHTTPProxy},
		BindingCount:          2,
		Status:                StatusPlanned,
		Warnings: []Warning{{
			Code:       WarningLegacyAuthCompatibility,
			ReasonCode: ReasonCompatibilityMode,
			Mode:       ModeLegacyAuthSync,
		}},
		Errors: []SanitizedError{{
			Code:       ErrorUnsupportedMode,
			Field:      "requestedModes",
			Index:      &index,
			ReasonCode: ReasonUnsupportedMode,
		}},
	}
	got := mustMarshalObject(t, plan)
	assertObjectKeys(t, got, []string{
		"id",
		"requestId",
		"networkProxySessionId",
		"requestedModes",
		"activeModes",
		"bindingCount",
		"status",
		"warnings",
		"errors",
	}, forbiddenRawFieldNames())

	minimal := mustMarshalObject(t, Plan{ID: "delivery-plan-02"})
	assertObjectKeys(t, minimal, []string{"id"}, []string{
		"requestId",
		"networkProxySessionId",
		"requestedModes",
		"activeModes",
		"bindingCount",
		"status",
		"warnings",
		"errors",
	})
}

func TestSecretResolutionJSONContracts(t *testing.T) {
	reference := mustMarshalObject(t, SecretReference{
		BindingID: "binding-01",
		SecretRef: "env:GITHUB_TOKEN",
	})
	assertObjectKeys(t, reference, []string{"bindingId", "secretRef"}, forbiddenRawFieldNames())

	brokerSecret := mustMarshalObject(t, BrokerSecretMetadata{
		ID:       "env:GITHUB_TOKEN",
		Source:   "env",
		Required: true,
		Present:  true,
	})
	assertObjectKeys(t, brokerSecret, []string{"id", "source", "required", "present"}, forbiddenRawFieldNames())

	resolved := mustMarshalObject(t, ResolvedBindingSecretMetadata{
		BindingID:    "binding-01",
		SecretRef:    "env:GITHUB_TOKEN",
		DeliveryMode: ModeEnv,
		BrokerSecret: BrokerSecretMetadata{
			ID:       "env:GITHUB_TOKEN",
			Source:   "env",
			Required: true,
			Present:  true,
		},
	})
	assertObjectKeys(t, resolved, []string{"bindingId", "secretRef", "deliveryMode", "brokerSecret"}, forbiddenRawFieldNames())

	index := 0
	result := mustMarshalObject(t, SecretResolutionResult{
		Valid:    false,
		Bindings: []ResolvedBindingSecretMetadata{},
		Warnings: []Warning{{
			Code:       WarningBindingOmitted,
			ReasonCode: ReasonMissingSecretReference,
			BindingID:  "binding-01",
			Mode:       ModeEnv,
		}},
		Errors: []SanitizedError{{
			Code:       ErrorMissingSecretReference,
			Field:      "bindings.secretRef",
			BindingID:  "binding-01",
			Mode:       ModeEnv,
			Index:      &index,
			ReasonCode: ReasonMissingSecretReference,
		}},
	})
	assertObjectKeys(t, result, []string{"valid", "warnings", "errors"}, forbiddenRawFieldNames())

	minimal := mustMarshalObject(t, SecretResolutionResult{Valid: true})
	assertObjectKeys(t, minimal, []string{"valid"}, []string{"bindings", "warnings", "errors"})
}

func TestActivationRequestJSONContract(t *testing.T) {
	request := ActivationRequest{
		ActivationID: "activation-01",
		Plan: Plan{
			ID:             "delivery-plan-01",
			RequestedModes: []Mode{ModeHTTPProxy},
			Status:         StatusPlanned,
		},
		Bindings: []Binding{{
			ID:           "binding-01",
			SecretRef:    "env:GITHUB_TOKEN",
			DeliveryMode: ModeHTTPProxy,
			Status:       StatusPlanned,
		}},
	}
	got := mustMarshalObject(t, request)
	assertObjectKeys(t, got, []string{
		"activationId",
		"plan",
		"bindings",
	}, forbiddenRawFieldNames())

	minimal := mustMarshalObject(t, ActivationRequest{
		Plan: Plan{ID: "delivery-plan-02"},
	})
	assertObjectKeys(t, minimal, []string{"plan"}, []string{"activationId", "bindings"})
}

func TestActivationResultJSONContract(t *testing.T) {
	activation := ActivationResult{
		ID:             "activation-01",
		PlanID:         "delivery-plan-01",
		RequestedModes: []Mode{ModeHTTPProxy, ModeSSHAgent},
		ActiveModes:    []Mode{ModeHTTPProxy},
		Bindings: []BindingActivationResult{{
			BindingID:    "binding-01",
			ServiceID:    "service-01",
			DeliveryMode: ModeHTTPProxy,
			Outcome:      StatusActive,
			Status:       StatusActive,
			ReasonCode:   ReasonRequested,
		}},
		Status: StatusActive,
		Warnings: []Warning{{
			Code:       WarningActivationSkipped,
			BindingID:  "binding-02",
			ReasonCode: ReasonActivationUnavailable,
			Mode:       ModeSSHAgent,
		}},
		Errors: []SanitizedError{{
			Code:      ErrorActivationFailed,
			BindingID: "binding-03",
			Mode:      ModeFileTmpfs,
		}},
	}
	got := mustMarshalObject(t, activation)
	assertObjectKeys(t, got, []string{
		"id",
		"planId",
		"requestedModes",
		"activeModes",
		"bindings",
		"status",
		"warnings",
		"errors",
	}, forbiddenRawFieldNames())

	minimal := mustMarshalObject(t, ActivationResult{
		ID:     "activation-02",
		PlanID: "delivery-plan-02",
	})
	assertObjectKeys(t, minimal, []string{"id", "planId"}, []string{
		"requestedModes",
		"activeModes",
		"bindings",
		"status",
		"warnings",
		"errors",
	})
}

func TestStatusMetadataJSONContract(t *testing.T) {
	status := StatusMetadata{
		ID:             "delivery-status-01",
		RequestID:      "delivery-request-01",
		PlanID:         "delivery-plan-01",
		ActivationID:   "activation-01",
		RequestedModes: []Mode{ModeHTTPProxy, ModeEnv},
		ActiveModes:    []Mode{ModeHTTPProxy},
		Status:         StatusActive,
		ReasonCode:     ReasonRequested,
		WarningCount:   1,
		ErrorCount:     2,
	}
	got := mustMarshalObject(t, status)
	assertObjectKeys(t, got, []string{
		"id",
		"requestId",
		"planId",
		"activationId",
		"requestedModes",
		"activeModes",
		"status",
		"reasonCode",
		"warningCount",
		"errorCount",
	}, forbiddenRawFieldNames())

	minimal := mustMarshalObject(t, StatusMetadata{ID: "delivery-status-02"})
	assertObjectKeys(t, minimal, []string{"id"}, []string{
		"requestId",
		"planId",
		"activationId",
		"requestedModes",
		"activeModes",
		"status",
		"reasonCode",
		"warningCount",
		"errorCount",
	})
}

func TestWarningAndSanitizedErrorJSONContracts(t *testing.T) {
	index := 0
	warning := mustMarshalObject(t, Warning{
		Code:       WarningBindingOmitted,
		ReasonCode: ReasonMissingServiceBinding,
		BindingID:  "binding-01",
		Mode:       ModeSSHAgent,
	})
	assertObjectKeys(t, warning, []string{"code", "reasonCode", "bindingId", "mode"}, forbiddenRawFieldNames())

	minimalWarning := mustMarshalObject(t, Warning{Code: WarningAdapterUnavailable})
	assertObjectKeys(t, minimalWarning, []string{"code"}, []string{"reasonCode", "bindingId", "mode"})

	err := mustMarshalObject(t, SanitizedError{
		Code:       ErrorUnsafeReference,
		Field:      "secretRef",
		BindingID:  "binding-01",
		Mode:       ModeEnv,
		Index:      &index,
		ReasonCode: ReasonMissingSecretReference,
	})
	assertObjectKeys(t, err, []string{"code", "field", "bindingId", "mode", "index", "reasonCode"}, forbiddenRawFieldNames())

	minimalErr := mustMarshalObject(t, SanitizedError{Code: ErrorMissingRequiredField})
	assertObjectKeys(t, minimalErr, []string{"code"}, []string{"field", "bindingId", "mode", "index", "reasonCode"})
}

func TestJSONTagsAreStable(t *testing.T) {
	assertJSONTags(t, reflect.TypeOf(Request{}), []jsonTagExpectation{
		{field: "ID", name: "id"},
		{field: "Source", name: "source", omitempty: true},
		{field: "RequestedModes", name: "requestedModes", omitempty: true},
		{field: "ActiveModes", name: "activeModes", omitempty: true},
		{field: "Bindings", name: "bindings", omitempty: true},
		{field: "Status", name: "status", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(Binding{}), []jsonTagExpectation{
		{field: "ID", name: "id"},
		{field: "RequestID", name: "requestId", omitempty: true},
		{field: "PlanID", name: "planId", omitempty: true},
		{field: "PolicySnapshotID", name: "policySnapshotId", omitempty: true},
		{field: "SecretRef", name: "secretRef"},
		{field: "NetworkProxySessionID", name: "networkProxySessionId", omitempty: true},
		{field: "ServiceID", name: "serviceId", omitempty: true},
		{field: "ServiceLabels", name: "serviceLabels", omitempty: true},
		{field: "DomainLabels", name: "domainLabels", omitempty: true},
		{field: "DestinationCategory", name: "destinationCategory", omitempty: true},
		{field: "DeliveryMode", name: "deliveryMode"},
		{field: "Status", name: "status", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(SecretReference{}), []jsonTagExpectation{
		{field: "BindingID", name: "bindingId", omitempty: true},
		{field: "SecretRef", name: "secretRef"},
	})
	assertJSONTags(t, reflect.TypeOf(BrokerSecretMetadata{}), []jsonTagExpectation{
		{field: "ID", name: "id"},
		{field: "Source", name: "source", omitempty: true},
		{field: "Required", name: "required"},
		{field: "Present", name: "present"},
	})
	assertJSONTags(t, reflect.TypeOf(ResolvedBindingSecretMetadata{}), []jsonTagExpectation{
		{field: "BindingID", name: "bindingId"},
		{field: "SecretRef", name: "secretRef"},
		{field: "DeliveryMode", name: "deliveryMode", omitempty: true},
		{field: "BrokerSecret", name: "brokerSecret"},
	})
	assertJSONTags(t, reflect.TypeOf(SecretResolutionResult{}), []jsonTagExpectation{
		{field: "Valid", name: "valid"},
		{field: "Bindings", name: "bindings", omitempty: true},
		{field: "Warnings", name: "warnings", omitempty: true},
		{field: "Errors", name: "errors", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(Plan{}), []jsonTagExpectation{
		{field: "ID", name: "id"},
		{field: "RequestID", name: "requestId", omitempty: true},
		{field: "NetworkProxySessionID", name: "networkProxySessionId", omitempty: true},
		{field: "RequestedModes", name: "requestedModes", omitempty: true},
		{field: "ActiveModes", name: "activeModes", omitempty: true},
		{field: "BindingCount", name: "bindingCount", omitempty: true},
		{field: "Status", name: "status", omitempty: true},
		{field: "Warnings", name: "warnings", omitempty: true},
		{field: "Errors", name: "errors", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(ActivationRequest{}), []jsonTagExpectation{
		{field: "ActivationID", name: "activationId", omitempty: true},
		{field: "Plan", name: "plan"},
		{field: "Bindings", name: "bindings", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(ActivationResult{}), []jsonTagExpectation{
		{field: "ID", name: "id"},
		{field: "PlanID", name: "planId"},
		{field: "RequestedModes", name: "requestedModes", omitempty: true},
		{field: "ActiveModes", name: "activeModes", omitempty: true},
		{field: "Bindings", name: "bindings", omitempty: true},
		{field: "Status", name: "status", omitempty: true},
		{field: "Warnings", name: "warnings", omitempty: true},
		{field: "Errors", name: "errors", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(BindingActivationResult{}), []jsonTagExpectation{
		{field: "BindingID", name: "bindingId"},
		{field: "ServiceID", name: "serviceId", omitempty: true},
		{field: "DeliveryMode", name: "deliveryMode"},
		{field: "Outcome", name: "outcome", omitempty: true},
		{field: "Status", name: "status", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(StatusMetadata{}), []jsonTagExpectation{
		{field: "ID", name: "id"},
		{field: "RequestID", name: "requestId", omitempty: true},
		{field: "PlanID", name: "planId", omitempty: true},
		{field: "ActivationID", name: "activationId", omitempty: true},
		{field: "RequestedModes", name: "requestedModes", omitempty: true},
		{field: "ActiveModes", name: "activeModes", omitempty: true},
		{field: "Status", name: "status", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
		{field: "WarningCount", name: "warningCount", omitempty: true},
		{field: "ErrorCount", name: "errorCount", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(Warning{}), []jsonTagExpectation{
		{field: "Code", name: "code"},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
		{field: "BindingID", name: "bindingId", omitempty: true},
		{field: "Mode", name: "mode", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(SanitizedError{}), []jsonTagExpectation{
		{field: "Code", name: "code"},
		{field: "Field", name: "field", omitempty: true},
		{field: "BindingID", name: "bindingId", omitempty: true},
		{field: "Mode", name: "mode", omitempty: true},
		{field: "Index", name: "index", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(ValidationResult{}), []jsonTagExpectation{
		{field: "Valid", name: "valid"},
		{field: "Errors", name: "errors", omitempty: true},
	})
}

func TestContractsExposeNoRawValueFields(t *testing.T) {
	contractTypes := []reflect.Type{
		reflect.TypeOf(Request{}),
		reflect.TypeOf(Binding{}),
		reflect.TypeOf(SecretReference{}),
		reflect.TypeOf(BrokerSecretMetadata{}),
		reflect.TypeOf(ResolvedBindingSecretMetadata{}),
		reflect.TypeOf(SecretResolutionResult{}),
		reflect.TypeOf(Plan{}),
		reflect.TypeOf(ActivationRequest{}),
		reflect.TypeOf(ActivationResult{}),
		reflect.TypeOf(BindingActivationResult{}),
		reflect.TypeOf(StatusMetadata{}),
		reflect.TypeOf(Warning{}),
		reflect.TypeOf(SanitizedError{}),
		reflect.TypeOf(ValidationResult{}),
	}
	for _, typ := range contractTypes {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				fieldName := strings.ToLower(field.Name)
				jsonName := strings.ToLower(strings.Split(field.Tag.Get("json"), ",")[0])
				for _, forbidden := range forbiddenRawFieldNameFragments() {
					if strings.Contains(fieldName, forbidden) || strings.Contains(jsonName, forbidden) {
						t.Fatalf("%s.%s json %q exposes forbidden raw field fragment %q", typ.Name(), field.Name, jsonName, forbidden)
					}
				}
			}
		})
	}
}

func TestSerializedMetadataContainsNoUnsafeRawFieldNames(t *testing.T) {
	value := ActivationResult{
		ID:             "activation-01",
		PlanID:         "delivery-plan-01",
		RequestedModes: []Mode{ModeHTTPProxy},
		ActiveModes:    []Mode{ModeHTTPProxy},
		Bindings: []BindingActivationResult{{
			BindingID:    "binding-01",
			ServiceID:    "service-01",
			DeliveryMode: ModeHTTPProxy,
			Outcome:      StatusActive,
			Status:       StatusActive,
		}},
		Status: StatusActive,
		Warnings: []Warning{{
			Code:       WarningAdapterUnavailable,
			ReasonCode: ReasonActivationUnavailable,
		}},
		Errors: []SanitizedError{{
			Code:       ErrorActivationFailed,
			Field:      "binding",
			BindingID:  "binding-01",
			ReasonCode: ReasonActivationUnavailable,
		}},
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	assertJSONKeysExcludeUnsafeRawFields(t, decoded, "$")
}

func TestSanitizedErrorStringIsCodeAndLocationOnly(t *testing.T) {
	index := 1
	err := SanitizedError{
		Code:  ErrorUnsafeReference,
		Field: "requestedModes",
		Index: &index,
	}
	got := err.Error()
	for _, want := range []string{"credential delivery", "unsafe_reference", "requestedModes[1]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Error() = %q, want substring %q", got, want)
		}
	}
	for _, forbidden := range []string{
		"ghp_secret",
		"https://",
		"example.invalid",
		"Authorization",
		"/tmp/credential",
	} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("Error() leaked %q: %q", forbidden, got)
		}
	}
}

func mustMarshalObject(t *testing.T, value any) map[string]any {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error: %v", value, err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("json.Unmarshal(%T) error: %v", value, err)
	}
	return object
}

func assertObjectKeys(t *testing.T, object map[string]any, wantKeys []string, forbiddenKeys []string) {
	t.Helper()

	if len(object) != len(wantKeys) {
		t.Fatalf("object keys = %#v, want exactly %#v", sortedKeys(object), wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := object[key]; !ok {
			t.Fatalf("object keys = %#v, missing %q", sortedKeys(object), key)
		}
	}
	for _, key := range forbiddenKeys {
		if _, ok := object[key]; ok {
			t.Fatalf("object unexpectedly contains forbidden key %q in %#v", key, sortedKeys(object))
		}
	}
}

type jsonTagExpectation struct {
	field     string
	name      string
	omitempty bool
}

func assertJSONTags(t *testing.T, typ reflect.Type, expectations []jsonTagExpectation) {
	t.Helper()

	if typ.NumField() != len(expectations) {
		t.Fatalf("%s field count = %d, want %d", typ.Name(), typ.NumField(), len(expectations))
	}

	expectedFields := make(map[string]struct{}, len(expectations))
	for _, expectation := range expectations {
		expectedFields[expectation.field] = struct{}{}

		field, ok := typ.FieldByName(expectation.field)
		if !ok {
			t.Fatalf("%s missing expected field %s", typ.Name(), expectation.field)
		}
		tag := field.Tag.Get("json")
		parts := strings.Split(tag, ",")
		if parts[0] != expectation.name {
			t.Fatalf("%s.%s json name = %q, want %q", typ.Name(), expectation.field, parts[0], expectation.name)
		}
		gotOmitEmpty := false
		for _, option := range parts[1:] {
			if option == "omitempty" {
				gotOmitEmpty = true
			}
		}
		if gotOmitEmpty != expectation.omitempty {
			t.Fatalf("%s.%s omitempty = %t, want %t", typ.Name(), expectation.field, gotOmitEmpty, expectation.omitempty)
		}
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if _, ok := expectedFields[field.Name]; !ok {
			t.Fatalf("%s has unlocked JSON field %s with tag %q", typ.Name(), field.Name, field.Tag.Get("json"))
		}
	}
}

func sortedKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

func forbiddenRawFieldNames() []string {
	return []string{
		"host",
		"hostname",
		"port",
		"url",
		"uri",
		"header",
		"headers",
		"body",
		"requestBody",
		"credentialValue",
		"environmentValue",
		"localPath",
		"socketPath",
		"providerCredential",
		"rawValue",
	}
}

func forbiddenRawFieldNameFragments() []string {
	return []string{
		"host",
		"hostname",
		"port",
		"url",
		"uri",
		"header",
		"body",
		"value",
		"environment",
		"localpath",
		"socketpath",
		"providercredential",
		"raw",
	}
}

func assertJSONKeysExcludeUnsafeRawFields(t *testing.T, value any, path string) {
	t.Helper()

	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			for _, forbidden := range forbiddenRawFieldNames() {
				if strings.EqualFold(key, forbidden) {
					t.Fatalf("%s contains unsafe raw field name %q", path, key)
				}
			}
			assertJSONKeysExcludeUnsafeRawFields(t, child, path+"."+key)
		}
	case []any:
		for _, child := range typed {
			assertJSONKeysExcludeUnsafeRawFields(t, child, path+"[]")
		}
	}
}
