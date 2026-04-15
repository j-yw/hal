package ci

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestContractVersionConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "push", got: PushContractVersion, want: "ci-push-v1"},
		{name: "status", got: StatusContractVersion, want: "ci-status-v1"},
		{name: "fix", got: FixContractVersion, want: "ci-fix-v1"},
		{name: "merge", got: MergeContractVersion, want: "ci-merge-v1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("contract version = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestWaitTerminalReasonConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "completed", got: WaitTerminalReasonCompleted, want: "completed"},
		{name: "timeout", got: WaitTerminalReasonTimeout, want: "timeout"},
		{name: "no_checks_detected", got: WaitTerminalReasonNoChecksDetected, want: "no_checks_detected"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("terminal reason = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestResultTypesHaveJSONTags(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(PushResult{}),
		reflect.TypeOf(PullRequest{}),
		reflect.TypeOf(StatusResult{}),
		reflect.TypeOf(StatusCheck{}),
		reflect.TypeOf(StatusTotals{}),
		reflect.TypeOf(FixResult{}),
		reflect.TypeOf(MergeResult{}),
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

func TestPushResultJSONFields(t *testing.T) {
	original := PushResult{
		ContractVersion: PushContractVersion,
		Branch:          "hal/ci-gap-free",
		Pushed:          true,
		DryRun:          false,
		PullRequest: PullRequest{
			Number:   42,
			URL:      "https://github.com/acme/repo/pull/42",
			Title:    "feat: add ci safety",
			HeadRef:  "hal/ci-gap-free",
			HeadSHA:  "abc123",
			BaseRef:  "develop",
			Draft:    true,
			Existing: false,
		},
		Summary: "pushed branch and created pull request",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	requiredTopLevel := []string{"contractVersion", "branch", "pushed", "dryRun", "pullRequest", "summary"}
	for _, key := range requiredTopLevel {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing push JSON field %q", key)
		}
	}

	pr, ok := raw["pullRequest"].(map[string]any)
	if !ok {
		t.Fatalf("pullRequest should be an object, got %T", raw["pullRequest"])
	}
	for _, key := range []string{"number", "url", "title", "headRef", "headSha", "baseRef", "draft", "existing"} {
		if _, ok := pr[key]; !ok {
			t.Errorf("missing pullRequest JSON field %q", key)
		}
	}

	var decoded PushResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

func TestStatusResultJSONFields(t *testing.T) {
	original := StatusResult{
		ContractVersion:    StatusContractVersion,
		Branch:             "hal/ci-gap-free",
		SHA:                "def456",
		Status:             StatusPending,
		ChecksDiscovered:   false,
		Wait:               true,
		WaitTerminalReason: WaitTerminalReasonNoChecksDetected,
		Checks: []StatusCheck{
			{
				Key:    "check:build",
				Source: CheckSourceCheckRun,
				Name:   "build",
				Status: StatusPending,
				URL:    "https://github.com/acme/repo/actions/runs/1",
			},
			{
				Key:    "status:lint",
				Source: CheckSourceStatus,
				Name:   "lint",
				Status: StatusFailing,
			},
		},
		Totals: StatusTotals{
			Pending: 1,
			Failing: 1,
			Passing: 0,
		},
		Summary: "checks are pending with no-checks grace terminal reason",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	requiredTopLevel := []string{
		"contractVersion",
		"branch",
		"sha",
		"status",
		"checksDiscovered",
		"wait",
		"waitTerminalReason",
		"checks",
		"totals",
		"summary",
	}
	for _, key := range requiredTopLevel {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing status JSON field %q", key)
		}
	}

	checks, ok := raw["checks"].([]any)
	if !ok {
		t.Fatalf("checks should be an array, got %T", raw["checks"])
	}
	if len(checks) != 2 {
		t.Fatalf("checks length = %d, want 2", len(checks))
	}

	first, ok := checks[0].(map[string]any)
	if !ok {
		t.Fatalf("checks[0] should be an object, got %T", checks[0])
	}
	for _, key := range []string{"key", "source", "name", "status", "url"} {
		if _, ok := first[key]; !ok {
			t.Errorf("missing check JSON field %q", key)
		}
	}

	totals, ok := raw["totals"].(map[string]any)
	if !ok {
		t.Fatalf("totals should be an object, got %T", raw["totals"])
	}
	for _, key := range []string{"pending", "failing", "passing"} {
		if _, ok := totals[key]; !ok {
			t.Errorf("missing totals JSON field %q", key)
		}
	}

	var decoded StatusResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

func TestFixResultJSONFields(t *testing.T) {
	original := FixResult{
		ContractVersion: FixContractVersion,
		Attempt:         1,
		MaxAttempts:     3,
		Applied:         true,
		Branch:          "hal/ci-gap-free",
		CommitSHA:       "feedbeef",
		Pushed:          true,
		FilesChanged:    []string{"cmd/ci_fix.go", "internal/ci/fix.go"},
		Summary:         "applied one fix attempt and pushed branch",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	for _, key := range []string{"contractVersion", "attempt", "maxAttempts", "applied", "branch", "commitSha", "pushed", "filesChanged", "summary"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing fix JSON field %q", key)
		}
	}

	var decoded FixResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}

func TestMergeResultJSONFields(t *testing.T) {
	original := MergeResult{
		ContractVersion: MergeContractVersion,
		PRNumber:        42,
		Strategy:        "squash",
		DryRun:          false,
		Merged:          true,
		MergeCommitSHA:  "1234abcd",
		BranchDeleted:   false,
		DeleteWarning:   "remote branch delete failed with 500",
		Summary:         "merged pull request with warning",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	for _, key := range []string{"contractVersion", "prNumber", "strategy", "dryRun", "merged", "mergeCommitSha", "branchDeleted", "deleteWarning", "summary"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing merge JSON field %q", key)
		}
	}

	var decoded MergeResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", decoded, original)
	}
}
