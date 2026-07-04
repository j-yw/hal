package credentialdelivery

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestActivationSchemaJSONFieldNamesOmitemptyAndEnums(t *testing.T) {
	activation := ActivationResult{
		ID:             "activation-01",
		PlanID:         "delivery-plan-01",
		RequestedModes: []Mode{ModeEnv, ModeHTTPProxy},
		ActiveModes:    []Mode{ModeEnv},
		Bindings: []BindingActivationResult{{
			BindingID:    "binding-01",
			DeliveryMode: ModeEnv,
			Status:       StatusActive,
			ReasonCode:   ReasonRequested,
			ProofRef:     "proof-ref-01",
		}},
		ProofRefs: []ActivationProofReference{{
			ProofID:      "proof-ref-01",
			BindingID:    "binding-01",
			DeliveryMode: ModeEnv,
		}},
		Status:     StatusActive,
		ReasonCode: ReasonRequested,
		Warnings: []Warning{{
			Code:       WarningActivationSkipped,
			BindingID:  "binding-02",
			ReasonCode: ReasonActivationUnavailable,
			Mode:       ModeHTTPProxy,
		}},
	}

	got := mustMarshalObject(t, activation)
	assertObjectKeys(t, got, []string{
		"id",
		"planId",
		"requestedModes",
		"activeModes",
		"bindings",
		"proofRefs",
		"status",
		"reasonCode",
		"warnings",
	}, activationSchemaForbiddenFieldNames())
	assertActivationSchemaKeysExcludeRawFields(t, got, "$")

	binding := got["bindings"].([]any)[0].(map[string]any)
	assertObjectKeys(t, binding, []string{
		"bindingId",
		"deliveryMode",
		"status",
		"reasonCode",
		"proofRef",
	}, activationSchemaForbiddenFieldNames())
	if binding["status"] != string(StatusActive) || binding["reasonCode"] != string(ReasonRequested) || binding["deliveryMode"] != string(ModeEnv) {
		t.Fatalf("binding activation enums = %#v, want stable mode/status/reason strings", binding)
	}

	proof := got["proofRefs"].([]any)[0].(map[string]any)
	assertObjectKeys(t, proof, []string{"proofId", "bindingId", "deliveryMode"}, activationSchemaForbiddenFieldNames())

	minimal := mustMarshalObject(t, ActivationResult{
		ID:     "activation-02",
		PlanID: "delivery-plan-02",
	})
	assertObjectKeys(t, minimal, []string{"id", "planId"}, []string{
		"requestedModes",
		"activeModes",
		"bindings",
		"proofRefs",
		"status",
		"reasonCode",
		"warnings",
	})

	assertJSONTags(t, reflect.TypeOf(ActivationResult{}), []jsonTagExpectation{
		{field: "ID", name: "id"},
		{field: "PlanID", name: "planId"},
		{field: "RequestedModes", name: "requestedModes", omitempty: true},
		{field: "ActiveModes", name: "activeModes", omitempty: true},
		{field: "Bindings", name: "bindings", omitempty: true},
		{field: "ProofRefs", name: "proofRefs", omitempty: true},
		{field: "Status", name: "status", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
		{field: "Warnings", name: "warnings", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(BindingActivationResult{}), []jsonTagExpectation{
		{field: "BindingID", name: "bindingId"},
		{field: "DeliveryMode", name: "deliveryMode"},
		{field: "Status", name: "status", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
		{field: "ProofRef", name: "proofRef", omitempty: true},
	})
	assertJSONTags(t, reflect.TypeOf(ActivationProofReference{}), []jsonTagExpectation{
		{field: "ProofID", name: "proofId"},
		{field: "BindingID", name: "bindingId", omitempty: true},
		{field: "DeliveryMode", name: "deliveryMode"},
	})
}

func TestActivationSanitizeDropsUnsafeRecordsAndReturnsCopies(t *testing.T) {
	input := ActivationResult{
		ID:             " activation-01 ",
		PlanID:         " delivery-plan-01 ",
		RequestedModes: []Mode{ModeEnv, Mode("sk-phase51-secret")},
		ActiveModes:    []Mode{ModeEnv, Mode("PHASE51_SECRET_VALUE")},
		Bindings: []BindingActivationResult{
			{
				BindingID:    " binding-01 ",
				DeliveryMode: Mode(" ENV "),
				Status:       Status(" ACTIVE "),
				ReasonCode:   ReasonCode(" REQUESTED "),
				ProofRef:     " proof-ref-01 ",
			},
			{
				BindingID:    "ghp_phase51_secret",
				DeliveryMode: ModeEnv,
				Status:       StatusActive,
				ProofRef:     "proof-ref-unsafe-binding",
			},
			{
				BindingID:    "binding-unsafe-mode",
				DeliveryMode: Mode("https://provider.example.invalid/credential?token=ghp_phase51_secret"),
				Status:       StatusActive,
				ProofRef:     "proof-ref-unsafe-mode",
			},
			{
				BindingID:    "binding-unsafe-proof",
				DeliveryMode: ModeEnv,
				Status:       Status("PHASE51_SECRET_VALUE"),
				ReasonCode:   ReasonCode("sk-phase51-secret"),
				ProofRef:     "/tmp/credential-delivery.sock",
			},
		},
		ProofRefs: []ActivationProofReference{
			{
				ProofID:      " proof-ref-01 ",
				BindingID:    " binding-01 ",
				DeliveryMode: Mode(" ENV "),
			},
			{
				ProofID:      "sk-phase51-secret",
				BindingID:    "binding-01",
				DeliveryMode: ModeEnv,
			},
			{
				ProofID:      "proof-ref-unsafe-binding",
				BindingID:    "PHASE51_SECRET_VALUE",
				DeliveryMode: ModeEnv,
			},
			{
				ProofID:      "proof-ref-unsafe-mode",
				BindingID:    "binding-01",
				DeliveryMode: Mode("https://provider.example.invalid/credential"),
			},
		},
		Status:     Status(" ACTIVE "),
		ReasonCode: ReasonCode(" REQUESTED "),
		Warnings: []Warning{
			{
				Code:       WarningAdapterUnavailable,
				BindingID:  "ghp_phase51_secret",
				ReasonCode: ReasonActivationUnavailable,
				Mode:       Mode("sk-phase51-secret"),
			},
			{Code: WarningCode("PHASE51_SECRET_VALUE")},
		},
	}
	originalPayload := mustMarshalCredentialDeliverySanitizeString(t, input)

	sanitized := SanitizeActivationResultMetadata(input)

	if afterPayload := mustMarshalCredentialDeliverySanitizeString(t, input); afterPayload != originalPayload {
		t.Fatalf("activation input mutated: got %s, want %s", afterPayload, originalPayload)
	}
	if sanitized.ID != "activation-01" || sanitized.PlanID != "delivery-plan-01" {
		t.Fatalf("activation ids = %#v, want trimmed safe identifiers", sanitized)
	}
	if len(sanitized.Bindings) != 2 {
		t.Fatalf("activation bindings = %#v, want safe binding and binding with unsafe optional proof cleared", sanitized.Bindings)
	}
	if sanitized.Bindings[0].BindingID != "binding-01" || sanitized.Bindings[0].ProofRef != "proof-ref-01" {
		t.Fatalf("safe activation binding = %#v, want normalized safe proof ref", sanitized.Bindings[0])
	}
	if sanitized.Bindings[1].BindingID != "binding-unsafe-proof" || sanitized.Bindings[1].ProofRef != "" || sanitized.Bindings[1].Status != "" || sanitized.Bindings[1].ReasonCode != "" {
		t.Fatalf("unsafe optional activation fields = %#v, want cleared", sanitized.Bindings[1])
	}
	if len(sanitized.ProofRefs) != 1 || sanitized.ProofRefs[0].ProofID != "proof-ref-01" || sanitized.ProofRefs[0].BindingID != "binding-01" {
		t.Fatalf("activation proof refs = %#v, want only safe proof reference", sanitized.ProofRefs)
	}
	if len(sanitized.Warnings) != 1 || sanitized.Warnings[0].BindingID != "" || sanitized.Warnings[0].Mode != "" {
		t.Fatalf("activation warnings = %#v, want safe warning with unsafe optional metadata cleared", sanitized.Warnings)
	}
	if len(sanitized.RequestedModes) != 1 || sanitized.RequestedModes[0] != ModeEnv || len(sanitized.ActiveModes) != 1 || sanitized.ActiveModes[0] != ModeEnv {
		t.Fatalf("activation modes = %#v/%#v, want unsafe modes omitted", sanitized.RequestedModes, sanitized.ActiveModes)
	}
	assertActivationSchemaNoSecretLeak(t, sanitized,
		"ghp_phase51_secret",
		"sk-phase51-secret",
		"PHASE51_SECRET_VALUE",
		"provider.example.invalid",
		"/tmp/credential-delivery.sock",
	)
}

func TestActivationRedactionSeededPhase51SecretsAreAbsentFromMarshaledMetadata(t *testing.T) {
	result := SanitizeActivationResultMetadata(ActivationResult{
		ID:             "activation-01",
		PlanID:         "delivery-plan-01",
		RequestedModes: []Mode{ModeEnv, Mode("ghp_phase51_secret")},
		ActiveModes:    []Mode{ModeEnv, Mode("sk-phase51-secret")},
		Bindings: []BindingActivationResult{{
			BindingID:    "binding-01",
			DeliveryMode: ModeEnv,
			Status:       StatusActive,
			ReasonCode:   ReasonRequested,
			ProofRef:     "PHASE51_SECRET_VALUE",
		}},
		ProofRefs: []ActivationProofReference{{
			ProofID:      "ghp_phase51_secret",
			BindingID:    "binding-01",
			DeliveryMode: ModeEnv,
		}},
		Status:     StatusActive,
		ReasonCode: ReasonRequested,
		Warnings: []Warning{{
			Code:       WarningAdapterUnavailable,
			ReasonCode: ReasonActivationUnavailable,
			BindingID:  "sk-phase51-secret",
			Mode:       Mode("PHASE51_SECRET_VALUE"),
		}},
	})

	assertActivationSchemaNoSecretLeak(t, result, "ghp_phase51_secret", "sk-phase51-secret", "PHASE51_SECRET_VALUE")
	assertActivationSchemaKeysExcludeRawFields(t, mustMarshalObject(t, result), "$")
}

func activationSchemaForbiddenFieldNames() []string {
	return []string{
		"secret",
		"secretValue",
		"handle",
		"path",
		"socket",
		"url",
		"uri",
		"host",
		"hostname",
		"header",
		"headers",
		"body",
		"token",
		"credential",
		"provider",
		"serviceId",
		"outcome",
		"errors",
	}
}

func assertActivationSchemaKeysExcludeRawFields(t *testing.T, value any, path string) {
	t.Helper()

	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			lowerKey := strings.ToLower(key)
			for _, forbidden := range activationSchemaForbiddenFieldNames() {
				if strings.Contains(lowerKey, strings.ToLower(forbidden)) {
					t.Fatalf("%s contains unsafe activation field name %q", path, key)
				}
			}
			assertActivationSchemaKeysExcludeRawFields(t, child, path+"."+key)
		}
	case []any:
		for _, child := range typed {
			assertActivationSchemaKeysExcludeRawFields(t, child, path+"[]")
		}
	}
}

func assertActivationSchemaNoSecretLeak(t *testing.T, value any, rejected ...string) {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%T) error = %v", value, err)
	}
	payload := string(data)
	for _, forbidden := range rejected {
		if forbidden == "" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("activation metadata leaked %q in %s", forbidden, payload)
		}
	}
}
