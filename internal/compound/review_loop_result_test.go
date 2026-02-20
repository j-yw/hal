package compound

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestReviewLoopResultJSONRoundTrip(t *testing.T) {
	startedAt := time.Date(2026, time.February, 15, 9, 30, 0, 0, time.UTC)
	endedAt := startedAt.Add(5 * time.Minute)

	want := ReviewLoopResult{
		Command:             "hal review --base develop --iterations 5",
		BaseBranch:          "develop",
		CurrentBranch:       "hal/report-review-split",
		RequestedIterations: 5,
		CompletedIterations: 2,
		StopReason:          "no_valid_issues",
		StartedAt:           startedAt,
		EndedAt:             endedAt,
		Totals: ReviewLoopTotals{
			IssuesFound:   6,
			ValidIssues:   4,
			InvalidIssues: 2,
			FixesApplied:  4,
		},
		Iterations: []ReviewLoopIteration{
			{
				Iteration:     1,
				IssuesFound:   5,
				ValidIssues:   3,
				InvalidIssues: 2,
				FixesApplied:  3,
				Summary:       "Resolved most high-severity findings",
				Status:        "completed",
			},
			{
				Iteration:     2,
				IssuesFound:   1,
				ValidIssues:   1,
				InvalidIssues: 0,
				FixesApplied:  1,
				Summary:       "Resolved final valid issue",
				Status:        "completed",
			},
		},
	}

	data, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("json.Unmarshal(payload) error = %v", err)
	}

	requiredTopLevel := []string{
		"command",
		"baseBranch",
		"currentBranch",
		"requestedIterations",
		"completedIterations",
		"stopReason",
		"startedAt",
		"endedAt",
		"totals",
		"iterations",
	}
	for _, key := range requiredTopLevel {
		if _, ok := payload[key]; !ok {
			t.Errorf("missing top-level JSON field %q", key)
		}
	}

	totals, ok := payload["totals"].(map[string]any)
	if !ok {
		t.Fatalf("totals should be an object, got %T", payload["totals"])
	}

	requiredTotalsFields := []string{"issuesFound", "validIssues", "invalidIssues", "fixesApplied"}
	for _, key := range requiredTotalsFields {
		if _, ok := totals[key]; !ok {
			t.Errorf("missing totals JSON field %q", key)
		}
	}

	iterations, ok := payload["iterations"].([]any)
	if !ok {
		t.Fatalf("iterations should be an array, got %T", payload["iterations"])
	}
	if len(iterations) == 0 {
		t.Fatal("iterations should contain at least one item")
	}

	iterationItem, ok := iterations[0].(map[string]any)
	if !ok {
		t.Fatalf("iteration item should be an object, got %T", iterations[0])
	}

	requiredIterationFields := []string{"iteration", "issuesFound", "validIssues", "invalidIssues", "fixesApplied", "summary", "status"}
	for _, key := range requiredIterationFields {
		if _, ok := iterationItem[key]; !ok {
			t.Errorf("missing iteration JSON field %q", key)
		}
	}

	var got ReviewLoopResult
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal(round-trip) error = %v", err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("round-trip mismatch\n got: %#v\nwant: %#v", got, want)
	}
}
