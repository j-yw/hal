package sandboxworker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestWorkerJSONSlashEscapesRoundTrip(t *testing.T) {
	values := []struct {
		name  string
		value string
	}{
		{name: "plain slash", value: "a/b"},
		{name: "literal backslash slash", value: "a\\/b"},
		{name: "unicode and quotes", value: "李 Éva \"/\\/\n\t"},
		// Exact json_escape line from the factory recovery artifact script.
		{name: "recovery sed", value: `json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }`},
	}
	for count := 0; count <= 8; count++ {
		values = append(values, struct {
			name  string
			value string
		}{name: fmt.Sprintf("backslash run %d", count), value: "a" + strings.Repeat("\\", count) + "/b"})
	}

	for _, value := range values {
		for _, escapeSlashes := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/escaped_slash_%t", value.name, escapeSlashes), func(t *testing.T) {
				t.Run("preflight string", func(t *testing.T) {
					parser := workerJSONPreflightV2{raw: string(workerJSONSlashMarshal(t, value.value, escapeSlashes))}
					decoded, err := parser.parseString()
					if err != nil || decoded != value.value || parser.offset != len(parser.raw) {
						t.Fatalf("preflight string changed meaning or failed: %v", err)
					}
				})
				request := workerJSONSlashRequest(value.value)
				if err := request.Validate(); err != nil {
					t.Fatalf("request fixture is invalid: %v", err)
				}
				t.Run("request", func(t *testing.T) {
					payload := workerJSONSlashMarshal(t, request, escapeSlashes)
					server := &Server{maxRequestBytes: defaultMaxRequestBytes}
					decoded, rejected := server.readRequest(bytes.NewReader(payload))
					if rejected != nil {
						t.Fatalf("valid request rejected: %v", rejected.Error)
					}
					if !reflect.DeepEqual(decoded, request) {
						t.Fatal("request bytes changed during strict decode")
					}
				})

				response := Response{
					ProtocolVersion: ProtocolVersion,
					RequestID:       request.RequestID,
					Operation:       OperationExec,
					OK:              true,
					Exec: &ExecResponse{
						Stdout: ExecOutputPayload{Data: value.value, SizeBytes: int64(len(value.value)), LimitBytes: MaxExecStdoutCaptureBytes},
						Stderr: ExecOutputPayload{LimitBytes: MaxExecStderrCaptureBytes},
					},
				}
				if err := response.Validate(); err != nil {
					t.Fatalf("response fixture is invalid: %v", err)
				}
				t.Run("response", func(t *testing.T) {
					decodedResponse, err := decodeWorkerResponse(bytes.NewReader(workerJSONSlashMarshal(t, response, escapeSlashes)))
					if err != nil {
						t.Fatalf("valid response rejected: %v", err)
					}
					if !reflect.DeepEqual(decodedResponse, response) {
						t.Fatal("response bytes changed during strict decode")
					}
				})
			})
		}
	}
}

func TestWorkerJSONSlashEscapesStoredStateDecodePreservesValidationBoundary(t *testing.T) {
	valid := storedJobStateV2{
		JobV2:            l8WorkerV2QueuedJob(),
		RequestKey:       "request-v2-" + strings.Repeat("0", 64),
		PrincipalID:      "principal-owner",
		DaemonGeneration: l8WorkerV2DaemonGeneration,
	}
	valid.JobV2.CredentialIntent = JobCredentialIntentV2{}
	if err := valid.Validate(); err != nil {
		t.Fatalf("baseline stored-state fixture is invalid: %v", err)
	}
	var baseline storedJobStateV2
	if err := decodeStoredJobStateV2Into(bytes.NewReader(workerJSONSlashMarshal(t, valid, false)), maxStoredJobStateV2Bytes, &baseline); err != nil {
		t.Fatalf("valid baseline state rejected: %v", err)
	}
	if !reflect.DeepEqual(baseline, valid) || baseline.Validate() != nil {
		t.Fatal("valid baseline stored-state round trip failed")
	}
	for count := 0; count <= 8; count++ {
		for _, escapeSlashes := range []bool{false, true} {
			t.Run(fmt.Sprintf("backslash_run_%d/escaped_slash_%t", count, escapeSlashes), func(t *testing.T) {
				// This is a decoder-only probe, not a valid persisted authority:
				// slash-bearing request keys must still fail state validation.
				state := valid
				state.RequestKey = "request-v2-" + strings.Repeat("\\", count) + "/"
				var decoded storedJobStateV2
				if err := decodeStoredJobStateV2Into(bytes.NewReader(workerJSONSlashMarshal(t, state, escapeSlashes)), maxStoredJobStateV2Bytes, &decoded); err != nil {
					t.Fatalf("valid stored-state JSON rejected: %v", err)
				}
				if !reflect.DeepEqual(decoded, state) {
					t.Fatal("stored-state bytes changed during strict decode")
				}
				if err := decoded.Validate(); err == nil || err.Error() != "stored worker job request identity is invalid" {
					t.Fatal("slash-bearing metadata acquired stored-state authority")
				}
			})
		}
	}
}

func TestWorkerJSONSlashEscapesKeepStrictRejections(t *testing.T) {
	request := workerJSONSlashRequest("payload-marker")
	canonical := string(workerJSONSlashMarshal(t, request, false))
	for _, value := range []string{
		`"\q"`, `"\x2f"`, `"\U0000002f"`, `"\a"`, `"\u12"`,
		`"\ud800"`, `"\udc00"`, `"\ud83d\ude80"`, `"a\\/\q"`,
		"\"unescaped\ncontrol\"", "\"invalid\xffutf8\"", `"unfinished\`,
	} {
		t.Run(fmt.Sprintf("invalid_string_%q", value), func(t *testing.T) {
			raw := strings.ReplaceAll(canonical, `"payload-marker"`, value)
			server := &Server{maxRequestBytes: defaultMaxRequestBytes}
			if _, rejected := server.readRequest(strings.NewReader(raw)); rejected == nil || rejected.Error == nil || rejected.Error.Code != ErrorCodeMalformedRequest {
				t.Fatal("invalid or previously unsupported string was accepted")
			}
		})
	}
	for name, mutate := range map[string]func(string) string{
		"escaped typed key":     func(raw string) string { return strings.Replace(raw, `"exec":`, `"\u0065xec":`, 1) },
		"case folded typed key": func(raw string) string { return strings.Replace(raw, `"exec":`, `"Exec":`, 1) },
		"duplicate typed key": func(raw string) string {
			return strings.Replace(raw, `"operation":"exec"`, `"operation":"exec","Operation":"exec"`, 1)
		},
		"unknown typed key": func(raw string) string {
			return strings.Replace(raw, `"operation":"exec"`, `"unknown":true,"operation":"exec"`, 1)
		},
		"duplicate slash map key": func(raw string) string {
			return strings.Replace(raw, `"env":{"payload-marker":"payload-marker"}`, `"env":{"a\\/b":"one","a\\\/b":"two"}`, 1)
		},
		"trailing JSON": func(raw string) string { return raw + "{}" },
	} {
		t.Run(name, func(t *testing.T) {
			raw := mutate(canonical)
			if raw == canonical {
				t.Fatal("negative fixture was not mutated")
			}
			server := &Server{maxRequestBytes: defaultMaxRequestBytes}
			if _, rejected := server.readRequest(strings.NewReader(raw)); rejected == nil || rejected.Error == nil || rejected.Error.Code != ErrorCodeMalformedRequest {
				t.Fatal("strict rejection changed")
			}
		})
	}
}

func workerJSONSlashRequest(value string) Request {
	return Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "request-slash",
		Operation:       OperationExec,
		DriverID:        RuntimeDriverRootlessPodman,
		Exec: &ExecRequest{
			OperationID: "exec-slash",
			Target: Target{
				ID:      "runtime-slash",
				Name:    "sandbox-slash",
				Runtime: RuntimeTarget{Driver: RuntimeDriverRootlessPodman, RuntimeID: "runtime-slash"},
			},
			Args:             []string{"sh", "-c", value},
			Env:              map[string]string{value: value},
			StdoutLimitBytes: MaxExecStdoutCaptureBytes,
			StderrLimitBytes: MaxExecStderrCaptureBytes,
		},
	}
}

func workerJSONSlashMarshal(t *testing.T, value any, escapeSlashes bool) []byte {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if escapeSlashes {
		payload = bytes.ReplaceAll(payload, []byte("/"), []byte(`\/`))
	}
	if !json.Valid(payload) {
		t.Fatal("test encoder produced invalid JSON")
	}
	return payload
}
