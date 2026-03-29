package ci

import (
	"context"
	"fmt"
	"reflect"
	"testing"
)

func TestGetStatusWithDeps_MixedContexts_UsesPRHeadSHA(t *testing.T) {
	t.Parallel()

	headCalled := false
	checkSHA := ""
	statusSHA := ""

	result, err := getStatusWithDeps(context.Background(), statusDeps{
		resolveRepo: func(context.Context) (GitHubRepository, error) {
			return GitHubRepository{Owner: "acme", Name: "repo"}, nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "hal/ci-gap-free", nil
		},
		currentHeadSHA: func(context.Context) (string, error) {
			headCalled = true
			return "local-head-sha", nil
		},
		findPRHeadSHA: func(context.Context, GitHubRepository, string) (string, error) {
			return "pr-head-sha", nil
		},
		listCheckRunsPage: func(_ context.Context, _ GitHubRepository, sha string, page int, perPage int) ([]checkRunData, error) {
			checkSHA = sha
			if page != 1 {
				t.Fatalf("check-runs page = %d, want 1", page)
			}
			if perPage != statusPageSize {
				t.Fatalf("check-runs perPage = %d, want %d", perPage, statusPageSize)
			}
			return []checkRunData{
				{Name: "build", Status: "completed", Conclusion: "success", URL: "https://example/check/build"},
				{Name: "integration", Status: "queued", URL: "https://example/check/integration"},
			}, nil
		},
		listCommitStatusesPage: func(_ context.Context, _ GitHubRepository, sha string, page int, perPage int) ([]commitStatusData, error) {
			statusSHA = sha
			if page != 1 {
				t.Fatalf("statuses page = %d, want 1", page)
			}
			if perPage != statusPageSize {
				t.Fatalf("statuses perPage = %d, want %d", perPage, statusPageSize)
			}
			return []commitStatusData{
				{Context: "lint", State: "success", URL: "https://example/status/lint"},
				{Context: "security", State: "failure", URL: "https://example/status/security"},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("getStatusWithDeps() error = %v", err)
	}

	if headCalled {
		t.Fatal("currentHeadSHA should not be called when PR head sha is available")
	}
	if result.SHA != "pr-head-sha" {
		t.Fatalf("result.SHA = %q, want %q", result.SHA, "pr-head-sha")
	}
	if checkSHA != "pr-head-sha" {
		t.Fatalf("check-runs sha = %q, want %q", checkSHA, "pr-head-sha")
	}
	if statusSHA != "pr-head-sha" {
		t.Fatalf("statuses sha = %q, want %q", statusSHA, "pr-head-sha")
	}

	if result.Status != StatusPending {
		t.Fatalf("result.Status = %q, want %q", result.Status, StatusPending)
	}
	if !result.ChecksDiscovered {
		t.Fatal("result.ChecksDiscovered = false, want true")
	}
	if result.Totals.Pending != 1 || result.Totals.Failing != 1 || result.Totals.Passing != 2 {
		t.Fatalf("totals = %#v, want pending=1 failing=1 passing=2", result.Totals)
	}

	checks := checksByKey(result.Checks)
	assertCheck(t, checks, "check:build", CheckSourceCheckRun, "build", StatusPassing)
	assertCheck(t, checks, "check:integration", CheckSourceCheckRun, "integration", StatusPending)
	assertCheck(t, checks, "status:lint", CheckSourceStatus, "lint", StatusPassing)
	assertCheck(t, checks, "status:security", CheckSourceStatus, "security", StatusFailing)
}

func TestGetStatusWithDeps_UsesLocalHeadSHAWhenNoPR(t *testing.T) {
	t.Parallel()

	headCalls := 0
	checkSHA := ""
	statusSHA := ""

	result, err := getStatusWithDeps(context.Background(), statusDeps{
		resolveRepo: func(context.Context) (GitHubRepository, error) {
			return GitHubRepository{Owner: "acme", Name: "repo"}, nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "hal/no-pr", nil
		},
		currentHeadSHA: func(context.Context) (string, error) {
			headCalls++
			return "local-head-sha", nil
		},
		findPRHeadSHA: func(context.Context, GitHubRepository, string) (string, error) {
			return "", nil
		},
		listCheckRunsPage: func(_ context.Context, _ GitHubRepository, sha string, page int, _ int) ([]checkRunData, error) {
			checkSHA = sha
			if page != 1 {
				t.Fatalf("check-runs page = %d, want 1", page)
			}
			return nil, nil
		},
		listCommitStatusesPage: func(_ context.Context, _ GitHubRepository, sha string, page int, _ int) ([]commitStatusData, error) {
			statusSHA = sha
			if page != 1 {
				t.Fatalf("statuses page = %d, want 1", page)
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("getStatusWithDeps() error = %v", err)
	}

	if headCalls != 1 {
		t.Fatalf("currentHeadSHA calls = %d, want 1", headCalls)
	}
	if result.SHA != "local-head-sha" {
		t.Fatalf("result.SHA = %q, want %q", result.SHA, "local-head-sha")
	}
	if checkSHA != "local-head-sha" {
		t.Fatalf("check-runs sha = %q, want %q", checkSHA, "local-head-sha")
	}
	if statusSHA != "local-head-sha" {
		t.Fatalf("statuses sha = %q, want %q", statusSHA, "local-head-sha")
	}

	if result.Status != StatusPending {
		t.Fatalf("result.Status = %q, want %q", result.Status, StatusPending)
	}
	if result.ChecksDiscovered {
		t.Fatal("result.ChecksDiscovered = true, want false")
	}
	if len(result.Checks) != 0 {
		t.Fatalf("len(result.Checks) = %d, want 0", len(result.Checks))
	}
	if result.Totals != (StatusTotals{}) {
		t.Fatalf("totals = %#v, want empty", result.Totals)
	}
}

func TestGetStatusWithDeps_DedupesByLockedKeys(t *testing.T) {
	t.Parallel()

	result, err := getStatusWithDeps(context.Background(), statusDeps{
		resolveRepo: func(context.Context) (GitHubRepository, error) {
			return GitHubRepository{Owner: "acme", Name: "repo"}, nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "hal/dedupe", nil
		},
		currentHeadSHA: func(context.Context) (string, error) {
			return "head-sha", nil
		},
		findPRHeadSHA: func(context.Context, GitHubRepository, string) (string, error) {
			return "", nil
		},
		listCheckRunsPage: func(_ context.Context, _ GitHubRepository, _ string, page int, _ int) ([]checkRunData, error) {
			if page != 1 {
				t.Fatalf("check-runs page = %d, want 1", page)
			}
			return []checkRunData{
				{Name: "build", Status: "completed", Conclusion: "success"},
				{Name: "build", Status: "completed", Conclusion: "failure"},
			}, nil
		},
		listCommitStatusesPage: func(_ context.Context, _ GitHubRepository, _ string, page int, _ int) ([]commitStatusData, error) {
			if page != 1 {
				t.Fatalf("statuses page = %d, want 1", page)
			}
			return []commitStatusData{
				{Context: "lint", State: "failure"},
				{Context: "lint", State: "success"},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("getStatusWithDeps() error = %v", err)
	}

	if len(result.Checks) != 2 {
		t.Fatalf("len(result.Checks) = %d, want 2", len(result.Checks))
	}

	checks := checksByKey(result.Checks)
	assertCheck(t, checks, "check:build", CheckSourceCheckRun, "build", StatusPassing)
	assertCheck(t, checks, "status:lint", CheckSourceStatus, "lint", StatusFailing)

	if result.Status != StatusFailing {
		t.Fatalf("result.Status = %q, want %q", result.Status, StatusFailing)
	}
	if result.Totals.Passing != 1 || result.Totals.Failing != 1 || result.Totals.Pending != 0 {
		t.Fatalf("totals = %#v, want passing=1 failing=1 pending=0", result.Totals)
	}
}

func TestGetStatusWithDeps_PaginatesCheckRunsAndStatuses(t *testing.T) {
	t.Parallel()

	checkPages := []int{}
	statusPages := []int{}

	result, err := getStatusWithDeps(context.Background(), statusDeps{
		resolveRepo: func(context.Context) (GitHubRepository, error) {
			return GitHubRepository{Owner: "acme", Name: "repo"}, nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "hal/pagination", nil
		},
		currentHeadSHA: func(context.Context) (string, error) {
			return "head-sha", nil
		},
		findPRHeadSHA: func(context.Context, GitHubRepository, string) (string, error) {
			return "", nil
		},
		listCheckRunsPage: func(_ context.Context, _ GitHubRepository, _ string, page int, perPage int) ([]checkRunData, error) {
			if perPage != statusPageSize {
				t.Fatalf("check-runs perPage = %d, want %d", perPage, statusPageSize)
			}
			checkPages = append(checkPages, page)
			switch page {
			case 1:
				return makeCheckRuns(statusPageSize, "check-a"), nil
			case 2:
				return makeCheckRuns(1, "check-b"), nil
			default:
				return nil, fmt.Errorf("unexpected check-runs page %d", page)
			}
		},
		listCommitStatusesPage: func(_ context.Context, _ GitHubRepository, _ string, page int, perPage int) ([]commitStatusData, error) {
			if perPage != statusPageSize {
				t.Fatalf("statuses perPage = %d, want %d", perPage, statusPageSize)
			}
			statusPages = append(statusPages, page)
			switch page {
			case 1:
				return makeCommitStatuses(statusPageSize, "status-a"), nil
			case 2:
				return makeCommitStatuses(1, "status-b"), nil
			default:
				return nil, fmt.Errorf("unexpected statuses page %d", page)
			}
		},
	})
	if err != nil {
		t.Fatalf("getStatusWithDeps() error = %v", err)
	}

	if !reflect.DeepEqual(checkPages, []int{1, 2}) {
		t.Fatalf("check-runs pages = %v, want [1 2]", checkPages)
	}
	if !reflect.DeepEqual(statusPages, []int{1, 2}) {
		t.Fatalf("statuses pages = %v, want [1 2]", statusPages)
	}

	wantChecks := (statusPageSize + 1) + (statusPageSize + 1)
	if len(result.Checks) != wantChecks {
		t.Fatalf("len(result.Checks) = %d, want %d", len(result.Checks), wantChecks)
	}
	if !result.ChecksDiscovered {
		t.Fatal("result.ChecksDiscovered = false, want true")
	}
	if result.Status != StatusPassing {
		t.Fatalf("result.Status = %q, want %q", result.Status, StatusPassing)
	}
	if result.Totals.Passing != wantChecks || result.Totals.Failing != 0 || result.Totals.Pending != 0 {
		t.Fatalf("totals = %#v, want passing=%d failing=0 pending=0", result.Totals, wantChecks)
	}
}

func TestMapCheckRunStatus_LockedMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		runStatus  string
		conclusion string
		want       string
	}{
		{name: "queued", runStatus: "queued", want: StatusPending},
		{name: "in progress", runStatus: "in_progress", want: StatusPending},
		{name: "completed success", runStatus: "completed", conclusion: "success", want: StatusPassing},
		{name: "completed neutral", runStatus: "completed", conclusion: "neutral", want: StatusPassing},
		{name: "completed skipped", runStatus: "completed", conclusion: "skipped", want: StatusPassing},
		{name: "completed failure", runStatus: "completed", conclusion: "failure", want: StatusFailing},
		{name: "completed timed out", runStatus: "completed", conclusion: "timed_out", want: StatusFailing},
		{name: "completed cancelled", runStatus: "completed", conclusion: "cancelled", want: StatusFailing},
		{name: "completed action required", runStatus: "completed", conclusion: "action_required", want: StatusFailing},
		{name: "completed startup failure", runStatus: "completed", conclusion: "startup_failure", want: StatusFailing},
		{name: "completed stale", runStatus: "completed", conclusion: "stale", want: StatusFailing},
		{name: "completed unknown", runStatus: "completed", conclusion: "unknown", want: StatusPending},
		{name: "unknown run status", runStatus: "requested", conclusion: "success", want: StatusPending},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := mapCheckRunStatus(tt.runStatus, tt.conclusion)
			if got != tt.want {
				t.Fatalf("mapCheckRunStatus(%q, %q) = %q, want %q", tt.runStatus, tt.conclusion, got, tt.want)
			}
		})
	}
}

func TestMapCommitStatusState_LockedMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state string
		want  string
	}{
		{state: "success", want: StatusPassing},
		{state: "failure", want: StatusFailing},
		{state: "error", want: StatusFailing},
		{state: "pending", want: StatusPending},
		{state: "", want: StatusPending},
		{state: "unknown", want: StatusPending},
	}

	for _, tt := range tests {
		t.Run(tt.state, func(t *testing.T) {
			t.Parallel()

			got := mapCommitStatusState(tt.state)
			if got != tt.want {
				t.Fatalf("mapCommitStatusState(%q) = %q, want %q", tt.state, got, tt.want)
			}
		})
	}
}

func makeCheckRuns(count int, prefix string) []checkRunData {
	runs := make([]checkRunData, 0, count)
	for i := 0; i < count; i++ {
		runs = append(runs, checkRunData{
			Name:       fmt.Sprintf("%s-%03d", prefix, i),
			Status:     "completed",
			Conclusion: "success",
		})
	}
	return runs
}

func makeCommitStatuses(count int, prefix string) []commitStatusData {
	statuses := make([]commitStatusData, 0, count)
	for i := 0; i < count; i++ {
		statuses = append(statuses, commitStatusData{
			Context: fmt.Sprintf("%s-%03d", prefix, i),
			State:   "success",
		})
	}
	return statuses
}

func checksByKey(checks []StatusCheck) map[string]StatusCheck {
	m := make(map[string]StatusCheck, len(checks))
	for _, check := range checks {
		m[check.Key] = check
	}
	return m
}

func assertCheck(t *testing.T, checks map[string]StatusCheck, key, source, name, status string) {
	t.Helper()

	check, ok := checks[key]
	if !ok {
		t.Fatalf("missing check %q", key)
	}
	if check.Source != source {
		t.Fatalf("check %q source = %q, want %q", key, check.Source, source)
	}
	if check.Name != name {
		t.Fatalf("check %q name = %q, want %q", key, check.Name, name)
	}
	if check.Status != status {
		t.Fatalf("check %q status = %q, want %q", key, check.Status, status)
	}
}
