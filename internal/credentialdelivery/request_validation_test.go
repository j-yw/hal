package credentialdelivery

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRequestValidationAcceptsSafeMetadata(t *testing.T) {
	got := ValidateRequestMetadata(safeRequestFixture())
	assertRequestValidationValid(t, got)
}

func TestRequestValidationRejectsMissingBindingIDsAndSecretReferences(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
		code   ErrorCode
		field  string
		index  *int
	}{
		{
			name: "binding id",
			mutate: func(request *Request) {
				request.Bindings[0].ID = ""
			},
			code:  ErrorMissingRequiredField,
			field: "bindings.id",
			index: intPtr(0),
		},
		{
			name: "secret reference",
			mutate: func(request *Request) {
				request.Bindings[0].SecretRef = " \t "
			},
			code:  ErrorMissingRequiredField,
			field: "bindings.secretRef",
			index: intPtr(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := safeRequestFixture()
			tt.mutate(&request)

			got := ValidateRequestMetadata(request)
			assertRequestValidationError(t, got, tt.code, tt.field, tt.index)
			assertRequestValidationNoUnsafeLeak(t, got)
		})
	}
}

func TestRequestValidationRejectsUnsafeReferencesAndServiceMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
		code   ErrorCode
		field  string
		index  *int
		leaks  []string
	}{
		{
			name: "request id path",
			mutate: func(request *Request) {
				request.ID = "/Users/alice/.config/credential-request.json"
			},
			code:  ErrorUnsafeReference,
			field: "id",
			leaks: []string{"/Users/alice/.config/credential-request.json"},
		},
		{
			name: "secret ref raw token",
			mutate: func(request *Request) {
				request.Bindings[0].SecretRef = "GITHUB_TOKEN=ghp_raw_secret_value"
			},
			code:  ErrorUnsafeReference,
			field: "bindings.secretRef",
			index: intPtr(0),
			leaks: []string{"GITHUB_TOKEN=ghp_raw_secret_value", "ghp_raw_secret_value"},
		},
		{
			name: "service id hostname",
			mutate: func(request *Request) {
				request.Bindings[0].ServiceID = "api.github.example.invalid"
			},
			code:  ErrorUnsafeReference,
			field: "bindings.serviceId",
			index: intPtr(0),
			leaks: []string{"api.github.example.invalid"},
		},
		{
			name: "service label header",
			mutate: func(request *Request) {
				request.Bindings[0].ServiceLabels = []string{"Authorization"}
			},
			code:  ErrorUnsafeMetadata,
			field: "bindings.serviceLabels",
			index: intPtr(0),
			leaks: []string{"Authorization"},
		},
		{
			name: "domain label url",
			mutate: func(request *Request) {
				request.Bindings[0].DomainLabels = []string{"https://tokens.example.invalid/path"}
			},
			code:  ErrorUnsafeMetadata,
			field: "bindings.domainLabels",
			index: intPtr(0),
			leaks: []string{"https://tokens.example.invalid/path", "tokens.example.invalid"},
		},
		{
			name: "requested mode raw provider credential",
			mutate: func(request *Request) {
				request.RequestedModes = []Mode{"provider_credential:aws-prod"}
			},
			code:  ErrorUnsafeMetadata,
			field: "requestedModes",
			index: intPtr(0),
			leaks: []string{"provider_credential:aws-prod", "aws-prod"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := safeRequestFixture()
			tt.mutate(&request)

			got := ValidateRequestMetadata(request)
			assertRequestValidationError(t, got, tt.code, tt.field, tt.index)
			assertRequestValidationNoUnsafeLeak(t, got, tt.leaks...)
		})
	}
}

func TestRequestValidationRejectsRequestedModesOutsideAllowlist(t *testing.T) {
	request := safeRequestFixture()
	request.RequestedModes = []Mode{ModeHTTPProxy, Mode("credential_proxy")}

	got := ValidateRequestMetadata(request)
	assertRequestValidationError(t, got, ErrorUnsupportedMode, "requestedModes", intPtr(1))
	assertRequestValidationNoUnsafeLeak(t, got, "credential_proxy")
}

func TestRequestValidationRejectsUnsupportedBindingDeliveryMode(t *testing.T) {
	request := safeRequestFixture()
	request.Bindings[0].DeliveryMode = Mode("tmp_file")

	got := ValidateRequestMetadata(request)
	assertRequestValidationError(t, got, ErrorUnsupportedMode, "bindings.deliveryMode", intPtr(0))
	assertRequestValidationNoUnsafeLeak(t, got, "tmp_file")
}

func TestRequestValidationRejectsDuplicateBindingIDs(t *testing.T) {
	request := safeRequestFixture()
	second := safeBindingFixture()
	second.SecretRef = "secret-ref-02"
	request.Bindings = append(request.Bindings, second)

	got := ValidateRequestMetadata(request)
	assertRequestValidationError(t, got, ErrorDuplicateBinding, "bindings.id", intPtr(1))
	assertRequestValidationNoUnsafeLeak(t, got)
}

func TestRequestValidationErrorsAreStructuredAndSanitized(t *testing.T) {
	request := safeRequestFixture()
	second := safeBindingFixture()
	second.ID = "binding-02"
	second.SecretRef = ""
	request.Bindings = append(request.Bindings, second)

	got := ValidateRequestMetadata(request)
	assertRequestValidationError(t, got, ErrorMissingRequiredField, "bindings.secretRef", intPtr(1))

	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(validation result) error: %v", err)
	}
	errorsValue, ok := raw["errors"].([]any)
	if !ok || len(errorsValue) != 1 {
		t.Fatalf("errors = %#v, want one structured error", raw["errors"])
	}
	errorObject, ok := errorsValue[0].(map[string]any)
	if !ok {
		t.Fatalf("error entry = %#v, want object", errorsValue[0])
	}
	assertObjectKeys(t, errorObject, []string{"code", "field", "index"}, []string{"bindingId", "mode", "reasonCode"})
	assertRequestValidationNoUnsafeLeak(t, got)
}

func safeRequestFixture() Request {
	return Request{
		ID:             "delivery-request-01",
		Source:         SourceRun,
		RequestedModes: []Mode{ModeHTTPProxy, ModeEnv},
		ActiveModes:    []Mode{ModeHTTPProxy},
		Bindings:       []Binding{safeBindingFixture()},
		Status:         StatusRequested,
	}
}

func assertRequestValidationValid(t *testing.T, result ValidationResult) {
	t.Helper()

	if !result.Valid {
		t.Fatalf("request validation valid = false, errors: %#v", result.Errors)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("request validation errors = %#v, want none", result.Errors)
	}
}

func assertRequestValidationError(t *testing.T, result ValidationResult, code ErrorCode, field string, index *int) {
	t.Helper()

	if result.Valid {
		t.Fatalf("request validation valid = true, want false")
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
	t.Fatalf("request validation errors = %#v, want code %q field %q index %#v", result.Errors, code, field, index)
}

func assertRequestValidationNoUnsafeLeak(t *testing.T, result ValidationResult, rejectedValues ...string) {
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
		"GITHUB_TOKEN=",
		"AWS_ACCESS_KEY_ID",
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
			t.Fatalf("request validation result leaked unsafe value %q in %s", forbidden, payload)
		}
	}
	for _, err := range result.Errors {
		errText := err.Error()
		for _, forbidden := range []string{"https://", "example.invalid", "/Users/", "Authorization", "Bearer", "ghp_"} {
			if strings.Contains(errText, forbidden) {
				t.Fatalf("request validation error string leaked unsafe value %q in %q", forbidden, errText)
			}
		}
		for _, rejected := range rejectedValues {
			if rejected == "" {
				continue
			}
			if strings.Contains(payload, rejected) || strings.Contains(errText, rejected) {
				t.Fatalf("request validation leaked rejected value %q in %s / %q", rejected, payload, errText)
			}
		}
	}
}
