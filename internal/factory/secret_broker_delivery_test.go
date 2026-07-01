package factory

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestSecretBrokerDeliveryModes(t *testing.T) {
	wantModes := []string{
		SecretBrokerDeliveryModeEnv,
		SecretBrokerDeliveryModeFileTmpfs,
		SecretBrokerDeliveryModeSSHAgent,
		SecretBrokerDeliveryModeHTTPProxy,
		SecretBrokerDeliveryModeLegacyAuthSync,
	}
	if got := SupportedSecretBrokerDeliveryModes(); !reflect.DeepEqual(got, wantModes) {
		t.Fatalf("SupportedSecretBrokerDeliveryModes() = %#v, want %#v", got, wantModes)
	}

	metadata, err := ValidateSecretBrokerDeliveryModes(SecretBrokerDeliveryModeValidationRequest{
		RequestedModes: []string{
			" " + SecretBrokerDeliveryModeEnv + " ",
			SecretBrokerDeliveryModeFileTmpfs,
			SecretBrokerDeliveryModeEnv,
		},
		ActiveModes: []string{
			SecretBrokerDeliveryModeLegacyAuthSync,
			SecretBrokerDeliveryModeFileTmpfs,
			SecretBrokerDeliveryModeLegacyAuthSync,
		},
	})
	if err != nil {
		t.Fatalf("ValidateSecretBrokerDeliveryModes() unexpected error: %v", err)
	}
	wantMetadata := SecretBrokerDeliveryModeMetadata{
		RequestedModes: []string{
			SecretBrokerDeliveryModeEnv,
			SecretBrokerDeliveryModeFileTmpfs,
		},
		ActiveModes: []string{
			SecretBrokerDeliveryModeLegacyAuthSync,
			SecretBrokerDeliveryModeFileTmpfs,
		},
	}
	if !reflect.DeepEqual(metadata, wantMetadata) {
		t.Fatalf("delivery metadata = %#v, want %#v", metadata, wantMetadata)
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("json.Marshal(metadata) error: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(metadata) error: %v", err)
	}
	requireExactJSONKeys(t, raw, []string{"requestedModes", "activeModes"})
	if strings.Contains(string(data), "value") || strings.Contains(string(data), "secret") {
		t.Fatalf("delivery metadata JSON should contain mode names only: %s", string(data))
	}

	secretValue := "ghp_delivery_mode_secret_value_123"
	broker := NewInMemorySecretBroker()
	session, err := broker.CreateSession(SecretBrokerSessionRequest{
		ID:                     "delivery-session",
		RequestedDeliveryModes: []string{SecretBrokerDeliveryModeEnv, SecretBrokerDeliveryModeHTTPProxy},
		ActiveDeliveryModes:    []string{SecretBrokerDeliveryModeEnv},
		ResolvedSecrets: []ResolvedRunSecret{{
			Name:     "GITHUB_TOKEN",
			Source:   RunSecretSourceEnv,
			Required: true,
			Value:    secretValue,
		}},
	})
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}
	if session.DeliveryModes == nil {
		t.Fatal("session delivery modes = nil, want metadata")
	}
	wantSessionDelivery := &SecretBrokerDeliveryModeMetadata{
		RequestedModes: []string{SecretBrokerDeliveryModeEnv, SecretBrokerDeliveryModeHTTPProxy},
		ActiveModes:    []string{SecretBrokerDeliveryModeEnv},
	}
	if !reflect.DeepEqual(session.DeliveryModes, wantSessionDelivery) {
		t.Fatalf("session delivery modes = %#v, want %#v", session.DeliveryModes, wantSessionDelivery)
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("json.Marshal(session) error: %v", err)
	}
	payload := string(sessionData)
	if strings.Contains(payload, secretValue) {
		t.Fatalf("session metadata JSON leaked secret value: %s", payload)
	}
	if strings.Contains(payload, `"value"`) {
		t.Fatalf("session metadata JSON contains a value field: %s", payload)
	}
}

func TestSecretBrokerDeliveryModeValidation(t *testing.T) {
	for _, mode := range SupportedSecretBrokerDeliveryModes() {
		if _, err := ValidateSecretBrokerDeliveryModes(SecretBrokerDeliveryModeValidationRequest{
			RequestedModes: []string{mode},
			ActiveModes:    []string{mode},
		}); err != nil {
			t.Fatalf("ValidateSecretBrokerDeliveryModes(%q) unexpected error: %v", mode, err)
		}
	}

	secretLikeMode := "https://user:ghp_delivery_secret@example.invalid/proxy?token=ghp_delivery_secret"
	_, err := ValidateSecretBrokerDeliveryModes(SecretBrokerDeliveryModeValidationRequest{
		RequestedModes: []string{secretLikeMode},
	})
	if err == nil {
		t.Fatal("ValidateSecretBrokerDeliveryModes() error = nil, want unsupported mode")
	}
	if !errors.Is(err, ErrUnsupportedSecretBrokerDeliveryMode) {
		t.Fatalf("ValidateSecretBrokerDeliveryModes() error = %v, want ErrUnsupportedSecretBrokerDeliveryMode", err)
	}
	errText := err.Error()
	for _, forbidden := range []string{
		secretLikeMode,
		"ghp_delivery_secret",
		"user:",
		"token=",
		"example.invalid",
	} {
		if strings.Contains(errText, forbidden) {
			t.Fatalf("unsupported mode error leaked %q: %q", forbidden, errText)
		}
	}
	if !strings.Contains(errText, "requestedModes[0]") {
		t.Fatalf("unsupported mode error = %q, want safe field/index", errText)
	}

	_, err = ValidateSecretBrokerDeliveryModes(SecretBrokerDeliveryModeValidationRequest{
		ActiveModes: []string{"credential_proxy"},
	})
	if err == nil {
		t.Fatal("ValidateSecretBrokerDeliveryModes() active mode error = nil, want unsupported mode")
	}
	if !errors.Is(err, ErrUnsupportedSecretBrokerDeliveryMode) {
		t.Fatalf("active mode error = %v, want ErrUnsupportedSecretBrokerDeliveryMode", err)
	}
	if strings.Contains(err.Error(), "credential_proxy") {
		t.Fatalf("active mode error leaked unsupported value: %q", err.Error())
	}

	_, err = ValidateSecretBrokerDeliveryModes(SecretBrokerDeliveryModeValidationRequest{
		RequestedModes: []string{" \t "},
	})
	if err == nil {
		t.Fatal("ValidateSecretBrokerDeliveryModes() empty mode error = nil, want invalid mode")
	}
	if !errors.Is(err, ErrInvalidSecretBrokerDeliveryMode) {
		t.Fatalf("empty mode error = %v, want ErrInvalidSecretBrokerDeliveryMode", err)
	}
}
