package verify

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestSchemaVersionConstant(t *testing.T) {
	if SchemaVersion != "verify-v1" {
		t.Fatalf("SchemaVersion = %q, want verify-v1", SchemaVersion)
	}
}

func TestStatusConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "pass", got: StatusPass, want: "pass"},
		{name: "fail", got: StatusFail, want: "fail"},
		{name: "warn", got: StatusWarn, want: "warn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("status = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestCheckStatusConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "pass", got: CheckStatusPass, want: "pass"},
		{name: "fail", got: CheckStatusFail, want: "fail"},
		{name: "timeout", got: CheckStatusTimeout, want: "timeout"},
		{name: "missing", got: CheckStatusMissing, want: "missing"},
		{name: "skipped", got: CheckStatusSkipped, want: "skipped"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("check status = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestAdapterConstants(t *testing.T) {
	if AdapterShell != "shell" {
		t.Fatalf("AdapterShell = %q, want shell", AdapterShell)
	}
}

func TestResultTypesHaveJSONTags(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(Result{}),
		reflect.TypeOf(Summary{}),
		reflect.TypeOf(CheckResult{}),
		reflect.TypeOf(Warning{}),
		reflect.TypeOf(ArtifactReference{}),
	}

	for _, typ := range types {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if !field.IsExported() {
					continue
				}

				tag, ok := field.Tag.Lookup("json")
				if !ok || tag == "" || tag == "-" {
					t.Errorf("%s.%s missing explicit json tag", typ.Name(), field.Name)
				}
			}
		})
	}
}

func TestResultJSONFieldsAndRoundTrip(t *testing.T) {
	startedAt := time.Date(2026, time.June, 20, 12, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)
	generatedAt := finishedAt.Add(100 * time.Millisecond)

	original := Result{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   generatedAt,
		Status:        StatusWarn,
		Summary: Summary{
			Total:    2,
			Passed:   1,
			Failed:   0,
			TimedOut: 0,
			Missing:  1,
			Skipped:  0,
			Warnings: 1,
		},
		Checks: []CheckResult{
			{
				ID:             "test",
				Name:           "Unit tests",
				Adapter:        AdapterShell,
				Status:         CheckStatusPass,
				Required:       true,
				Command:        "go test ./...",
				WorkDir:        "/work/hal",
				TimeoutSeconds: 60,
				StartedAt:      startedAt,
				FinishedAt:     finishedAt,
				DurationMs:     2000,
				ExitCode:       0,
				StdoutArtifact: ".hal/reports/verify/test-stdout.txt",
				StderrArtifact: ".hal/reports/verify/test-stderr.txt",
				Message:        "check passed",
			},
		},
		Warnings: []Warning{
			{
				CheckID: "optional-lint",
				Status:  CheckStatusMissing,
				Message: "optional check command is unavailable",
			},
		},
		Artifacts: []ArtifactReference{
			{
				CheckID: "test",
				Kind:    "stdout",
				Path:    ".hal/reports/verify/test-stdout.txt",
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	for _, key := range []string{"schemaVersion", "generatedAt", "status", "summary", "checks", "warnings", "artifacts"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing result JSON field %q", key)
		}
	}

	summary, ok := raw["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary should be an object, got %T", raw["summary"])
	}
	for _, key := range []string{"total", "passed", "failed", "timedOut", "missing", "skipped", "warnings"} {
		if _, ok := summary[key]; !ok {
			t.Errorf("missing summary JSON field %q", key)
		}
	}

	checks, ok := raw["checks"].([]any)
	if !ok {
		t.Fatalf("checks should be an array, got %T", raw["checks"])
	}
	if len(checks) != 1 {
		t.Fatalf("checks length = %d, want 1", len(checks))
	}

	check, ok := checks[0].(map[string]any)
	if !ok {
		t.Fatalf("checks[0] should be an object, got %T", checks[0])
	}
	for _, key := range []string{
		"id",
		"name",
		"adapter",
		"status",
		"required",
		"command",
		"workDir",
		"timeoutSeconds",
		"startedAt",
		"finishedAt",
		"durationMs",
		"exitCode",
		"stdoutArtifact",
		"stderrArtifact",
		"message",
	} {
		if _, ok := check[key]; !ok {
			t.Errorf("missing check JSON field %q", key)
		}
	}

	warnings, ok := raw["warnings"].([]any)
	if !ok {
		t.Fatalf("warnings should be an array, got %T", raw["warnings"])
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings length = %d, want 1", len(warnings))
	}
	warning, ok := warnings[0].(map[string]any)
	if !ok {
		t.Fatalf("warnings[0] should be an object, got %T", warnings[0])
	}
	for _, key := range []string{"checkId", "status", "message"} {
		if _, ok := warning[key]; !ok {
			t.Errorf("missing warning JSON field %q", key)
		}
	}

	artifacts, ok := raw["artifacts"].([]any)
	if !ok {
		t.Fatalf("artifacts should be an array, got %T", raw["artifacts"])
	}
	if len(artifacts) != 1 {
		t.Fatalf("artifacts length = %d, want 1", len(artifacts))
	}
	artifact, ok := artifacts[0].(map[string]any)
	if !ok {
		t.Fatalf("artifacts[0] should be an object, got %T", artifacts[0])
	}
	for _, key := range []string{"checkId", "kind", "path"} {
		if _, ok := artifact[key]; !ok {
			t.Errorf("missing artifact JSON field %q", key)
		}
	}

	var decoded Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}
