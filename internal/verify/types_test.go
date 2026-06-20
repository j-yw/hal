package verify

import (
	"encoding/json"
	"reflect"
	"sort"
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

func TestResultJSONEmitsExactFieldContracts(t *testing.T) {
	original := verifyResultFixture()

	raw := marshalRawObject(t, original)

	requireExactJSONKeys(t, "result", raw, resultJSONKeys)
	summary, ok := raw["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary should be an object, got %T", raw["summary"])
	}
	requireExactJSONKeys(t, "summary", summary, summaryJSONKeys)

	check := firstObjectInArray(t, raw, "checks")
	requireExactJSONKeys(t, "checks[0]", check, checkResultJSONKeys)

	warning := firstObjectInArray(t, raw, "warnings")
	requireExactJSONKeys(t, "warnings[0]", warning, warningJSONKeys)

	artifact := firstObjectInArray(t, raw, "artifacts")
	requireExactJSONKeys(t, "artifacts[0]", artifact, artifactReferenceJSONKeys)
}

func TestResultJSONEmitsRequiredFieldsWhenZeroValued(t *testing.T) {
	raw := marshalRawObject(t, Result{
		Summary:   Summary{},
		Checks:    []CheckResult{{}},
		Warnings:  []Warning{{}},
		Artifacts: []ArtifactReference{{}},
	})

	requireExactJSONKeys(t, "result", raw, resultJSONKeys)
	summary, ok := raw["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary should be an object, got %T", raw["summary"])
	}
	requireExactJSONKeys(t, "summary", summary, summaryJSONKeys)

	check := firstObjectInArray(t, raw, "checks")
	requireExactJSONKeys(t, "checks[0]", check, checkResultJSONKeys)

	warning := firstObjectInArray(t, raw, "warnings")
	requireExactJSONKeys(t, "warnings[0]", warning, warningJSONKeys)

	artifact := firstObjectInArray(t, raw, "artifacts")
	requireExactJSONKeys(t, "artifacts[0]", artifact, artifactReferenceJSONKeys)
}

func TestResultJSONRoundTrip(t *testing.T) {
	original := verifyResultFixture()

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var decoded Result
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

var resultJSONKeys = []string{"schemaVersion", "generatedAt", "status", "summary", "checks", "warnings", "artifacts"}

var summaryJSONKeys = []string{"total", "passed", "failed", "timedOut", "missing", "skipped", "warnings"}

var checkResultJSONKeys = []string{
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
}

var warningJSONKeys = []string{"checkId", "status", "message"}

var artifactReferenceJSONKeys = []string{"checkId", "kind", "path"}

func verifyResultFixture() Result {
	startedAt := time.Date(2026, time.June, 20, 12, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)
	generatedAt := finishedAt.Add(100 * time.Millisecond)

	return Result{
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
}

func marshalRawObject(t *testing.T, value any) map[string]any {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}
	return raw
}

func firstObjectInArray(t *testing.T, raw map[string]any, field string) map[string]any {
	t.Helper()

	items, ok := raw[field].([]any)
	if !ok {
		t.Fatalf("%s should be an array, got %T", field, raw[field])
	}
	if len(items) == 0 {
		t.Fatalf("%s should include at least one item", field)
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("%s[0] should be an object, got %T", field, items[0])
	}
	return item
}

func requireExactJSONKeys(t *testing.T, label string, got map[string]any, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("%s JSON keys = %v, want exactly %v", label, sortedJSONKeys(got), sortedStrings(want))
	}

	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Fatalf("%s missing JSON field %q; keys = %v", label, key, sortedJSONKeys(got))
		}
	}
}

func sortedJSONKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func sortedStrings(values []string) []string {
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return sorted
}
