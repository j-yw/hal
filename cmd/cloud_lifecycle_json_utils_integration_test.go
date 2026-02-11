//go:build integration
// +build integration

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

const (
	cloudLifecycleNormalizedCreatedAt = "<created-at>"
	cloudLifecycleNormalizedUpdatedAt = "<updated-at>"
)

type cloudLifecycleJSONNormalization struct {
	Fields map[string]interface{}
}

func mustDecodeLifecycleJSONOutput(t *testing.T, output string) map[string]interface{} {
	t.Helper()

	payload, err := decodeLifecycleJSONOutput(output)
	if err != nil {
		t.Fatalf("failed to decode lifecycle JSON output: %v\noutput: %s", err, output)
	}
	return payload
}

func decodeLifecycleJSONOutput(output string) (map[string]interface{}, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return nil, fmt.Errorf("json output is empty")
	}

	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.UseNumber()

	var payload map[string]interface{}
	if err := decoder.Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode json output: %w", err)
	}

	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("json output contains multiple JSON documents")
		}
		return nil, fmt.Errorf("decode trailing json output: %w", err)
	}

	return payload, nil
}

func normalizeLifecycleJSONPayload(payload map[string]interface{}, normalization cloudLifecycleJSONNormalization) map[string]interface{} {
	if payload == nil {
		return nil
	}

	cloned, _ := cloneLifecycleJSONValue(payload).(map[string]interface{})
	if len(normalization.Fields) == 0 {
		return cloned
	}

	for key, replacement := range normalization.Fields {
		if _, exists := cloned[key]; exists {
			cloned[key] = replacement
		}
	}

	return cloned
}

func lifecycleJSONFirstKey(payload map[string]interface{}, keys ...string) (string, bool) {
	for _, key := range keys {
		if _, ok := payload[key]; ok {
			return key, true
		}
	}
	return "", false
}

func lifecycleJSONStringField(payload map[string]interface{}, keys ...string) (string, bool) {
	for _, key := range keys {
		value, ok := payload[key]
		if !ok {
			continue
		}
		str, ok := value.(string)
		if !ok || str == "" {
			return "", false
		}
		return str, true
	}
	return "", false
}

func cloneLifecycleJSONValue(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		cloned := make(map[string]interface{}, len(typed))
		for key, nested := range typed {
			cloned[key] = cloneLifecycleJSONValue(nested)
		}
		return cloned
	case []interface{}:
		cloned := make([]interface{}, len(typed))
		for i, nested := range typed {
			cloned[i] = cloneLifecycleJSONValue(nested)
		}
		return cloned
	default:
		return typed
	}
}

func TestDecodeLifecycleJSONOutput(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantErr    string
		checkValue func(t *testing.T, payload map[string]interface{})
	}{
		{
			name:   "valid object with useNumber",
			output: "\n{\"runId\":\"run-001\",\"attemptCount\":2}\n",
			checkValue: func(t *testing.T, payload map[string]interface{}) {
				t.Helper()
				runID, ok := lifecycleJSONStringField(payload, cloudLifecycleJSONKeyRunID)
				if !ok || runID != "run-001" {
					t.Fatalf("run ID = %q, want %q", runID, "run-001")
				}
				attempt, ok := payload[cloudLifecycleJSONKeyAttemptCount].(json.Number)
				if !ok || attempt.String() != "2" {
					t.Fatalf("attemptCount = %#v, want json.Number(2)", payload[cloudLifecycleJSONKeyAttemptCount])
				}
			},
		},
		{
			name:    "empty output",
			output:  "   \n\t",
			wantErr: "json output is empty",
		},
		{
			name:    "invalid json",
			output:  "{runId}",
			wantErr: "decode json output",
		},
		{
			name:    "multiple json documents",
			output:  "{\"runId\":\"run-001\"}\n{\"runId\":\"run-002\"}",
			wantErr: "multiple JSON documents",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := decodeLifecycleJSONOutput(tt.output)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkValue != nil {
				tt.checkValue(t, payload)
			}
		})
	}
}

func TestNormalizeLifecycleJSONPayload(t *testing.T) {
	original := map[string]interface{}{
		cloudLifecycleJSONKeyRunID:     "run-123",
		cloudLifecycleJSONKeyStatus:    "queued",
		cloudLifecycleJSONKeyCreatedAt: "2026-02-12T01:00:00Z",
		"details": map[string]interface{}{
			"events": []interface{}{"queued", "running"},
		},
	}

	normalized := normalizeLifecycleJSONPayload(original, cloudLifecycleJSONNormalization{
		Fields: map[string]interface{}{
			cloudLifecycleJSONKeyRunID:     cloudLifecycleRunIDPlaceholder,
			cloudLifecycleJSONKeyCreatedAt: cloudLifecycleNormalizedCreatedAt,
			"missingKey":                   "ignored",
		},
	})

	if got, _ := lifecycleJSONStringField(normalized, cloudLifecycleJSONKeyRunID); got != cloudLifecycleRunIDPlaceholder {
		t.Fatalf("normalized runId = %q, want %q", got, cloudLifecycleRunIDPlaceholder)
	}
	if got, _ := lifecycleJSONStringField(normalized, cloudLifecycleJSONKeyCreatedAt); got != cloudLifecycleNormalizedCreatedAt {
		t.Fatalf("normalized createdAt = %q, want %q", got, cloudLifecycleNormalizedCreatedAt)
	}
	if got, _ := lifecycleJSONStringField(normalized, cloudLifecycleJSONKeyStatus); got != "queued" {
		t.Fatalf("status should remain unchanged, got %q", got)
	}
	if _, exists := normalized["missingKey"]; exists {
		t.Fatal("normalization should not add missing keys")
	}

	if got, _ := lifecycleJSONStringField(original, cloudLifecycleJSONKeyRunID); got != "run-123" {
		t.Fatalf("original runId was mutated: %q", got)
	}
	if got, _ := lifecycleJSONStringField(original, cloudLifecycleJSONKeyCreatedAt); got != "2026-02-12T01:00:00Z" {
		t.Fatalf("original createdAt was mutated: %q", got)
	}

	normalizedDetails, ok := normalized["details"].(map[string]interface{})
	if !ok {
		t.Fatalf("normalized details type = %T, want map[string]interface{}", normalized["details"])
	}
	normalizedDetails["events"] = []interface{}{"done"}

	originalDetails, ok := original["details"].(map[string]interface{})
	if !ok {
		t.Fatalf("original details type = %T, want map[string]interface{}", original["details"])
	}
	originalEvents, ok := originalDetails["events"].([]interface{})
	if !ok {
		t.Fatalf("original details.events type = %T, want []interface{}", originalDetails["events"])
	}
	if len(originalEvents) != 2 {
		t.Fatalf("original nested data was mutated: %#v", originalEvents)
	}
}
