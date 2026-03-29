package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	ci "github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/spf13/cobra"
)

type ciFakeEngine struct{}

func (ciFakeEngine) Name() string { return "fake" }

func (ciFakeEngine) Execute(context.Context, string, *engine.Display) engine.Result {
	return engine.Result{}
}

func (ciFakeEngine) Prompt(context.Context, string) (string, error) {
	return "", nil
}

func (ciFakeEngine) StreamPrompt(context.Context, string, *engine.Display) (string, error) {
	return "", nil
}

func preserveCIPushGlobals(t *testing.T) {
	t.Helper()
	origDryRun := ciPushDryRunFlag
	origJSON := ciPushJSONFlag
	origPushDeps := defaultCIPushDeps

	origStatusWait := ciStatusWaitFlag
	origStatusTimeout := ciStatusTimeoutFlag
	origStatusPollInterval := ciStatusPollIntervalFlag
	origStatusNoChecksGrace := ciStatusNoChecksGraceFlag
	origStatusJSON := ciStatusJSONFlag
	origStatusDeps := defaultCIStatusDeps

	origFixMaxAttempts := ciFixMaxAttemptsFlag
	origFixEngine := ciFixEngineFlag
	origFixJSON := ciFixJSONFlag
	origFixDeps := defaultCIFixDeps

	t.Cleanup(func() {
		ciPushDryRunFlag = origDryRun
		ciPushJSONFlag = origJSON
		defaultCIPushDeps = origPushDeps

		ciStatusWaitFlag = origStatusWait
		ciStatusTimeoutFlag = origStatusTimeout
		ciStatusPollIntervalFlag = origStatusPollInterval
		ciStatusNoChecksGraceFlag = origStatusNoChecksGrace
		ciStatusJSONFlag = origStatusJSON
		defaultCIStatusDeps = origStatusDeps

		ciFixMaxAttemptsFlag = origFixMaxAttempts
		ciFixEngineFlag = origFixEngine
		ciFixJSONFlag = origFixJSON
		defaultCIFixDeps = origFixDeps
	})
}

func TestCICommandMetadataAndFlags(t *testing.T) {
	if ciCmd.Use != "ci" {
		t.Fatalf("ciCmd.Use = %q, want %q", ciCmd.Use, "ci")
	}
	if strings.TrimSpace(ciCmd.Long) == "" {
		t.Fatal("ciCmd.Long should not be empty")
	}

	if ciPushCmd.Use != "push" {
		t.Fatalf("ciPushCmd.Use = %q, want %q", ciPushCmd.Use, "push")
	}
	if !strings.Contains(ciPushCmd.Example, "hal ci push") {
		t.Fatalf("ciPushCmd.Example should include command path, got %q", ciPushCmd.Example)
	}

	dryRun := ciPushCmd.Flags().Lookup("dry-run")
	if dryRun == nil {
		t.Fatal("ci push command missing --dry-run flag")
	}
	if dryRun.DefValue != "false" {
		t.Fatalf("ci push --dry-run default = %q, want %q", dryRun.DefValue, "false")
	}

	pushJSON := ciPushCmd.Flags().Lookup("json")
	if pushJSON == nil {
		t.Fatal("ci push command missing --json flag")
	}
	if pushJSON.DefValue != "false" {
		t.Fatalf("ci push --json default = %q, want %q", pushJSON.DefValue, "false")
	}

	if ciPushCmd.Args == nil {
		t.Fatal("ci push command should reject positional arguments")
	}
	if err := ciPushCmd.Args(ciPushCmd, []string{"unexpected"}); err == nil {
		t.Fatal("ci push command should fail on positional arguments")
	}

	if ciStatusCmd.Use != "status" {
		t.Fatalf("ciStatusCmd.Use = %q, want %q", ciStatusCmd.Use, "status")
	}
	if !strings.Contains(ciStatusCmd.Example, "hal ci status") {
		t.Fatalf("ciStatusCmd.Example should include command path, got %q", ciStatusCmd.Example)
	}

	waitFlag := ciStatusCmd.Flags().Lookup("wait")
	if waitFlag == nil {
		t.Fatal("ci status command missing --wait flag")
	}
	if waitFlag.DefValue != "false" {
		t.Fatalf("ci status --wait default = %q, want %q", waitFlag.DefValue, "false")
	}

	timeoutFlag := ciStatusCmd.Flags().Lookup("timeout")
	if timeoutFlag == nil {
		t.Fatal("ci status command missing --timeout flag")
	}
	if timeoutFlag.DefValue != "0s" {
		t.Fatalf("ci status --timeout default = %q, want %q", timeoutFlag.DefValue, "0s")
	}

	pollFlag := ciStatusCmd.Flags().Lookup("poll-interval")
	if pollFlag == nil {
		t.Fatal("ci status command missing --poll-interval flag")
	}
	if pollFlag.DefValue != "0s" {
		t.Fatalf("ci status --poll-interval default = %q, want %q", pollFlag.DefValue, "0s")
	}

	noChecksFlag := ciStatusCmd.Flags().Lookup("no-checks-grace")
	if noChecksFlag == nil {
		t.Fatal("ci status command missing --no-checks-grace flag")
	}
	if noChecksFlag.DefValue != "0s" {
		t.Fatalf("ci status --no-checks-grace default = %q, want %q", noChecksFlag.DefValue, "0s")
	}

	statusJSON := ciStatusCmd.Flags().Lookup("json")
	if statusJSON == nil {
		t.Fatal("ci status command missing --json flag")
	}
	if statusJSON.DefValue != "false" {
		t.Fatalf("ci status --json default = %q, want %q", statusJSON.DefValue, "false")
	}

	if ciStatusCmd.Args == nil {
		t.Fatal("ci status command should reject positional arguments")
	}
	if err := ciStatusCmd.Args(ciStatusCmd, []string{"unexpected"}); err == nil {
		t.Fatal("ci status command should fail on positional arguments")
	}

	if ciFixCmd.Use != "fix" {
		t.Fatalf("ciFixCmd.Use = %q, want %q", ciFixCmd.Use, "fix")
	}
	if !strings.Contains(ciFixCmd.Example, "hal ci fix") {
		t.Fatalf("ciFixCmd.Example should include command path, got %q", ciFixCmd.Example)
	}

	maxAttemptsFlag := ciFixCmd.Flags().Lookup("max-attempts")
	if maxAttemptsFlag == nil {
		t.Fatal("ci fix command missing --max-attempts flag")
	}
	if maxAttemptsFlag.DefValue != "3" {
		t.Fatalf("ci fix --max-attempts default = %q, want %q", maxAttemptsFlag.DefValue, "3")
	}

	fixEngineFlag := ciFixCmd.Flags().Lookup("engine")
	if fixEngineFlag == nil {
		t.Fatal("ci fix command missing --engine flag")
	}
	if fixEngineFlag.DefValue != "codex" {
		t.Fatalf("ci fix --engine default = %q, want %q", fixEngineFlag.DefValue, "codex")
	}

	fixJSONFlag := ciFixCmd.Flags().Lookup("json")
	if fixJSONFlag == nil {
		t.Fatal("ci fix command missing --json flag")
	}
	if fixJSONFlag.DefValue != "false" {
		t.Fatalf("ci fix --json default = %q, want %q", fixJSONFlag.DefValue, "false")
	}

	if ciFixCmd.Args == nil {
		t.Fatal("ci fix command should reject positional arguments")
	}
	if err := ciFixCmd.Args(ciFixCmd, []string{"unexpected"}); err == nil {
		t.Fatal("ci fix command should fail on positional arguments")
	}
}

func TestRunCIPushWithDeps_JSONOnlyOutput(t *testing.T) {
	want := ci.PushResult{
		ContractVersion: ci.PushContractVersion,
		Branch:          "hal/ci-push",
		Pushed:          true,
		DryRun:          false,
		PullRequest: ci.PullRequest{
			Number:   42,
			URL:      "https://github.com/acme/repo/pull/42",
			Title:    "ci push",
			HeadRef:  "hal/ci-push",
			BaseRef:  "main",
			Draft:    true,
			Existing: false,
		},
		Summary: "pushed branch hal/ci-push and created pull request",
	}

	var buf bytes.Buffer
	err := runCIPushWithDeps(context.Background(), ciPushRunOptions{JSON: true}, &buf, ciPushDeps{
		pushAndCreatePR: func(context.Context, ci.PushOptions) (ci.PushResult, error) {
			return want, nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "", nil
		},
	})
	if err != nil {
		t.Fatalf("runCIPushWithDeps() error = %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(output, "{") || !strings.HasSuffix(output, "}") {
		t.Fatalf("expected JSON-only output, got %q", output)
	}
	if strings.Contains(output, "Pull request:") {
		t.Fatalf("JSON output should not include human text, got %q", output)
	}

	var got ci.PushResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}

	if got.ContractVersion != ci.PushContractVersion {
		t.Fatalf("contractVersion = %q, want %q", got.ContractVersion, ci.PushContractVersion)
	}
	if got.Branch != want.Branch {
		t.Fatalf("branch = %q, want %q", got.Branch, want.Branch)
	}
	if got.PullRequest.URL != want.PullRequest.URL {
		t.Fatalf("pullRequest.url = %q, want %q", got.PullRequest.URL, want.PullRequest.URL)
	}
}

func TestRunCIPushWithDeps_DryRunSkipsSideEffects(t *testing.T) {
	pushCalls := 0

	var buf bytes.Buffer
	err := runCIPushWithDeps(context.Background(), ciPushRunOptions{DryRun: true}, &buf, ciPushDeps{
		pushAndCreatePR: func(context.Context, ci.PushOptions) (ci.PushResult, error) {
			pushCalls++
			return ci.PushResult{}, nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "hal/preview", nil
		},
	})
	if err != nil {
		t.Fatalf("runCIPushWithDeps() error = %v", err)
	}

	if pushCalls != 0 {
		t.Fatalf("pushAndCreatePR called %d times, want 0 in dry-run", pushCalls)
	}

	output := buf.String()
	if !strings.Contains(output, "Dry run: would push branch hal/preview") {
		t.Fatalf("dry-run output %q missing expected preview text", output)
	}
	if strings.Contains(strings.TrimSpace(output), "{") {
		t.Fatalf("dry-run human output should not be JSON, got %q", output)
	}
}

func TestRunCIPush_UsesCommandFlagValues(t *testing.T) {
	preserveCIPushGlobals(t)

	ciPushDryRunFlag = false
	ciPushJSONFlag = false

	pushCalled := false
	defaultCIPushDeps = ciPushDeps{
		pushAndCreatePR: func(context.Context, ci.PushOptions) (ci.PushResult, error) {
			pushCalled = true
			return ci.PushResult{}, nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "hal/from-flags", nil
		},
	}

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "push"}
	cmd.SetOut(&out)
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set --dry-run: %v", err)
	}
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}

	if err := runCIPush(cmd, nil); err != nil {
		t.Fatalf("runCIPush() error = %v", err)
	}
	if pushCalled {
		t.Fatal("runCIPush should not call pushAndCreatePR when command dry-run flag is true")
	}

	var got ci.PushResult
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("runCIPush JSON output parse failed: %v\noutput: %s", err, out.String())
	}
	if !got.DryRun {
		t.Fatal("got.DryRun = false, want true")
	}
	if got.Pushed {
		t.Fatal("got.Pushed = true, want false for dry-run")
	}
	if got.Branch != "hal/from-flags" {
		t.Fatalf("got.Branch = %q, want %q", got.Branch, "hal/from-flags")
	}
}

func TestRunCIStatusWithDeps_JSONOnlyOutput(t *testing.T) {
	want := ci.StatusResult{
		ContractVersion:    ci.StatusContractVersion,
		Branch:             "hal/ci-status",
		SHA:                "deadbeef",
		Status:             ci.StatusPending,
		ChecksDiscovered:   false,
		Wait:               true,
		WaitTerminalReason: ci.WaitTerminalReasonNoChecksDetected,
		Checks:             []ci.StatusCheck{},
		Totals:             ci.StatusTotals{},
		Summary:            "no CI contexts discovered; status pending",
	}

	var buf bytes.Buffer
	err := runCIStatusWithDeps(context.Background(), ciStatusRunOptions{Wait: true, JSON: true}, &buf, ciStatusDeps{
		getStatus: func(context.Context) (ci.StatusResult, error) {
			t.Fatal("getStatus should not be called when wait=true")
			return ci.StatusResult{}, nil
		},
		waitForChecks: func(context.Context, ci.WaitOptions) (ci.StatusResult, error) {
			return want, nil
		},
	})
	if err != nil {
		t.Fatalf("runCIStatusWithDeps() error = %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(output, "{") || !strings.HasSuffix(output, "}") {
		t.Fatalf("expected JSON-only output, got %q", output)
	}
	if strings.Contains(output, "Wait terminal reason:") {
		t.Fatalf("JSON output should not include human text, got %q", output)
	}

	var got ci.StatusResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}

	if got.ContractVersion != ci.StatusContractVersion {
		t.Fatalf("contractVersion = %q, want %q", got.ContractVersion, ci.StatusContractVersion)
	}
	if got.WaitTerminalReason != ci.WaitTerminalReasonNoChecksDetected {
		t.Fatalf("waitTerminalReason = %q, want %q", got.WaitTerminalReason, ci.WaitTerminalReasonNoChecksDetected)
	}
	if !got.Wait {
		t.Fatal("wait = false, want true")
	}
}

func TestRunCIStatus_UsesCommandFlagValues(t *testing.T) {
	preserveCIPushGlobals(t)

	ciStatusWaitFlag = false
	ciStatusTimeoutFlag = 0
	ciStatusPollIntervalFlag = 0
	ciStatusNoChecksGraceFlag = 0
	ciStatusJSONFlag = false

	getCalled := false
	waitCalled := false
	capturedOpts := ci.WaitOptions{}
	defaultCIStatusDeps = ciStatusDeps{
		getStatus: func(context.Context) (ci.StatusResult, error) {
			getCalled = true
			return ci.StatusResult{}, nil
		},
		waitForChecks: func(_ context.Context, opts ci.WaitOptions) (ci.StatusResult, error) {
			waitCalled = true
			capturedOpts = opts
			return ci.StatusResult{
				ContractVersion:    ci.StatusContractVersion,
				Branch:             "hal/from-flags",
				Status:             ci.StatusPending,
				ChecksDiscovered:   false,
				Wait:               true,
				WaitTerminalReason: ci.WaitTerminalReasonNoChecksDetected,
				Summary:            "no CI contexts discovered; status pending",
			}, nil
		},
	}

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "status"}
	cmd.SetOut(&out)
	cmd.Flags().Bool("wait", false, "")
	cmd.Flags().Duration("timeout", 0, "")
	cmd.Flags().Duration("poll-interval", 0, "")
	cmd.Flags().Duration("no-checks-grace", 0, "")
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("wait", "true"); err != nil {
		t.Fatalf("set --wait: %v", err)
	}
	if err := cmd.Flags().Set("timeout", "2m"); err != nil {
		t.Fatalf("set --timeout: %v", err)
	}
	if err := cmd.Flags().Set("poll-interval", "5s"); err != nil {
		t.Fatalf("set --poll-interval: %v", err)
	}
	if err := cmd.Flags().Set("no-checks-grace", "45s"); err != nil {
		t.Fatalf("set --no-checks-grace: %v", err)
	}
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}

	if err := runCIStatus(cmd, nil); err != nil {
		t.Fatalf("runCIStatus() error = %v", err)
	}
	if getCalled {
		t.Fatal("runCIStatus should not call getStatus when command wait flag is true")
	}
	if !waitCalled {
		t.Fatal("runCIStatus should call waitForChecks when command wait flag is true")
	}
	if capturedOpts.Timeout != 2*time.Minute {
		t.Fatalf("wait timeout = %s, want %s", capturedOpts.Timeout, 2*time.Minute)
	}
	if capturedOpts.PollInterval != 5*time.Second {
		t.Fatalf("wait poll interval = %s, want %s", capturedOpts.PollInterval, 5*time.Second)
	}
	if capturedOpts.NoChecksGrace != 45*time.Second {
		t.Fatalf("wait no-checks grace = %s, want %s", capturedOpts.NoChecksGrace, 45*time.Second)
	}

	var got ci.StatusResult
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("runCIStatus JSON output parse failed: %v\noutput: %s", err, out.String())
	}
	if !got.Wait {
		t.Fatal("got.Wait = false, want true")
	}
	if got.WaitTerminalReason != ci.WaitTerminalReasonNoChecksDetected {
		t.Fatalf("got.WaitTerminalReason = %q, want %q", got.WaitTerminalReason, ci.WaitTerminalReasonNoChecksDetected)
	}
	if got.Branch != "hal/from-flags" {
		t.Fatalf("got.Branch = %q, want %q", got.Branch, "hal/from-flags")
	}
}

func TestRunCIFixWithDeps_JSONOnlyOutput(t *testing.T) {
	want := ci.FixResult{
		ContractVersion: ci.FixContractVersion,
		Attempt:         1,
		MaxAttempts:     3,
		Applied:         true,
		Branch:          "hal/ci-fix",
		CommitSHA:       "deadbeef",
		Pushed:          true,
		FilesChanged:    []string{"cmd/ci.go", "cmd/ci_test.go"},
		Summary:         "applied ci fix attempt 1 on branch hal/ci-fix and pushed 2 files",
	}

	newEngineCalls := 0
	fixCalls := 0
	waitCalls := 0

	var buf bytes.Buffer
	err := runCIFixWithDeps(context.Background(), ciFixRunOptions{MaxAttempts: 3, Engine: "codex", JSON: true}, &buf, ciFixDeps{
		newEngine: func(string) (engine.Engine, error) {
			newEngineCalls++
			return ciFakeEngine{}, nil
		},
		getStatus: func(context.Context) (ci.StatusResult, error) {
			return ci.StatusResult{Status: ci.StatusFailing, Branch: "hal/ci-fix"}, nil
		},
		waitForChecks: func(context.Context, ci.WaitOptions) (ci.StatusResult, error) {
			waitCalls++
			return ci.StatusResult{Status: ci.StatusPassing, Branch: "hal/ci-fix"}, nil
		},
		fixWithEngine: func(_ context.Context, status ci.StatusResult, opts ci.FixOptions) (ci.FixResult, error) {
			fixCalls++
			if status.Status != ci.StatusFailing {
				t.Fatalf("status.Status = %q, want %q", status.Status, ci.StatusFailing)
			}
			if opts.Attempt != 1 {
				t.Fatalf("opts.Attempt = %d, want %d", opts.Attempt, 1)
			}
			if opts.MaxAttempts != 3 {
				t.Fatalf("opts.MaxAttempts = %d, want %d", opts.MaxAttempts, 3)
			}
			return want, nil
		},
	})
	if err != nil {
		t.Fatalf("runCIFixWithDeps() error = %v", err)
	}
	if newEngineCalls != 1 {
		t.Fatalf("newEngine calls = %d, want 1", newEngineCalls)
	}
	if fixCalls != 1 {
		t.Fatalf("fixWithEngine calls = %d, want 1", fixCalls)
	}
	if waitCalls != 1 {
		t.Fatalf("waitForChecks calls = %d, want 1", waitCalls)
	}

	output := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(output, "{") || !strings.HasSuffix(output, "}") {
		t.Fatalf("expected JSON-only output, got %q", output)
	}
	if strings.Contains(output, "Commit:") {
		t.Fatalf("JSON output should not include human text, got %q", output)
	}

	var got ci.FixResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}
	if got.ContractVersion != ci.FixContractVersion {
		t.Fatalf("contractVersion = %q, want %q", got.ContractVersion, ci.FixContractVersion)
	}
	if got.Attempt != want.Attempt {
		t.Fatalf("attempt = %d, want %d", got.Attempt, want.Attempt)
	}
	if got.CommitSHA != want.CommitSHA {
		t.Fatalf("commitSha = %q, want %q", got.CommitSHA, want.CommitSHA)
	}
}

func TestRunCIFixWithDeps_StopsWithoutAttemptWhenStatusNotFailing(t *testing.T) {
	newEngineCalled := false
	fixCalled := false
	waitCalled := false

	var buf bytes.Buffer
	err := runCIFixWithDeps(context.Background(), ciFixRunOptions{MaxAttempts: 3, Engine: "codex", JSON: true}, &buf, ciFixDeps{
		newEngine: func(string) (engine.Engine, error) {
			newEngineCalled = true
			return ciFakeEngine{}, nil
		},
		getStatus: func(context.Context) (ci.StatusResult, error) {
			return ci.StatusResult{Status: ci.StatusPassing, Branch: "hal/ci-fix"}, nil
		},
		waitForChecks: func(context.Context, ci.WaitOptions) (ci.StatusResult, error) {
			waitCalled = true
			return ci.StatusResult{}, nil
		},
		fixWithEngine: func(context.Context, ci.StatusResult, ci.FixOptions) (ci.FixResult, error) {
			fixCalled = true
			return ci.FixResult{}, nil
		},
	})
	if err != nil {
		t.Fatalf("runCIFixWithDeps() error = %v", err)
	}
	if newEngineCalled {
		t.Fatal("newEngine should not be called when status is not failing")
	}
	if fixCalled {
		t.Fatal("fixWithEngine should not be called when status is not failing")
	}
	if waitCalled {
		t.Fatal("waitForChecks should not be called when no attempt is made")
	}

	var got ci.FixResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}
	if got.Attempt != 0 {
		t.Fatalf("attempt = %d, want 0", got.Attempt)
	}
	if got.Applied {
		t.Fatal("applied = true, want false")
	}
	if !strings.Contains(got.Summary, "no fix attempt needed") {
		t.Fatalf("summary = %q, want no-attempt text", got.Summary)
	}
}

func TestRunCIFixWithDeps_StopsAtMaxAttempts(t *testing.T) {
	fixAttempts := make([]int, 0, 2)
	waitCalls := 0
	newEngineCalls := 0

	err := runCIFixWithDeps(context.Background(), ciFixRunOptions{MaxAttempts: 2, Engine: "codex"}, io.Discard, ciFixDeps{
		newEngine: func(string) (engine.Engine, error) {
			newEngineCalls++
			return ciFakeEngine{}, nil
		},
		getStatus: func(context.Context) (ci.StatusResult, error) {
			return ci.StatusResult{Status: ci.StatusFailing, Branch: "hal/ci-fix"}, nil
		},
		waitForChecks: func(context.Context, ci.WaitOptions) (ci.StatusResult, error) {
			waitCalls++
			return ci.StatusResult{Status: ci.StatusFailing, Branch: "hal/ci-fix"}, nil
		},
		fixWithEngine: func(_ context.Context, _ ci.StatusResult, opts ci.FixOptions) (ci.FixResult, error) {
			fixAttempts = append(fixAttempts, opts.Attempt)
			return ci.FixResult{ContractVersion: ci.FixContractVersion, Attempt: opts.Attempt, MaxAttempts: opts.MaxAttempts, Applied: true, Branch: "hal/ci-fix", Pushed: true, Summary: "attempt"}, nil
		},
	})
	if err == nil {
		t.Fatal("runCIFixWithDeps() error = nil, want max-attempts error")
	}
	wantErr := "ci status is failing after 2 attempt(s); run 'hal ci status --wait' for details"
	if err.Error() != wantErr {
		t.Fatalf("error = %q, want %q", err.Error(), wantErr)
	}
	if newEngineCalls != 1 {
		t.Fatalf("newEngine calls = %d, want 1", newEngineCalls)
	}
	if waitCalls != 2 {
		t.Fatalf("waitForChecks calls = %d, want 2", waitCalls)
	}
	if !reflect.DeepEqual(fixAttempts, []int{1, 2}) {
		t.Fatalf("fix attempts = %v, want [1 2]", fixAttempts)
	}
}

func TestRunCIFix_UsesCommandFlagValues(t *testing.T) {
	preserveCIPushGlobals(t)

	ciFixMaxAttemptsFlag = 3
	ciFixEngineFlag = "codex"
	ciFixJSONFlag = false

	newEngineName := ""
	fixOptions := ci.FixOptions{}
	getStatusCalls := 0
	waitCalls := 0
	defaultCIFixDeps = ciFixDeps{
		newEngine: func(name string) (engine.Engine, error) {
			newEngineName = name
			return ciFakeEngine{}, nil
		},
		getStatus: func(context.Context) (ci.StatusResult, error) {
			getStatusCalls++
			return ci.StatusResult{Status: ci.StatusFailing, Branch: "hal/from-flags"}, nil
		},
		waitForChecks: func(context.Context, ci.WaitOptions) (ci.StatusResult, error) {
			waitCalls++
			return ci.StatusResult{Status: ci.StatusPassing, Branch: "hal/from-flags"}, nil
		},
		fixWithEngine: func(_ context.Context, status ci.StatusResult, opts ci.FixOptions) (ci.FixResult, error) {
			fixOptions = opts
			return ci.FixResult{
				ContractVersion: ci.FixContractVersion,
				Attempt:         opts.Attempt,
				MaxAttempts:     opts.MaxAttempts,
				Applied:         true,
				Branch:          status.Branch,
				CommitSHA:       "deadbeef",
				Pushed:          true,
				FilesChanged:    []string{"cmd/ci.go"},
				Summary:         "fixed",
			}, nil
		},
	}

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "fix"}
	cmd.SetOut(&out)
	cmd.Flags().Int("max-attempts", 3, "")
	cmd.Flags().String("engine", "codex", "")
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("max-attempts", "2"); err != nil {
		t.Fatalf("set --max-attempts: %v", err)
	}
	if err := cmd.Flags().Set("engine", "claude"); err != nil {
		t.Fatalf("set --engine: %v", err)
	}
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}

	if err := runCIFix(cmd, nil); err != nil {
		t.Fatalf("runCIFix() error = %v", err)
	}
	if newEngineName != "claude" {
		t.Fatalf("newEngine name = %q, want %q", newEngineName, "claude")
	}
	if getStatusCalls != 1 {
		t.Fatalf("getStatus calls = %d, want 1", getStatusCalls)
	}
	if waitCalls != 1 {
		t.Fatalf("waitForChecks calls = %d, want 1", waitCalls)
	}
	if fixOptions.Attempt != 1 {
		t.Fatalf("fix attempt = %d, want 1", fixOptions.Attempt)
	}
	if fixOptions.MaxAttempts != 2 {
		t.Fatalf("fix max attempts = %d, want 2", fixOptions.MaxAttempts)
	}

	var got ci.FixResult
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("runCIFix JSON output parse failed: %v\noutput: %s", err, out.String())
	}
	if got.ContractVersion != ci.FixContractVersion {
		t.Fatalf("contractVersion = %q, want %q", got.ContractVersion, ci.FixContractVersion)
	}
	if got.Attempt != 1 {
		t.Fatalf("attempt = %d, want 1", got.Attempt)
	}
	if got.MaxAttempts != 2 {
		t.Fatalf("maxAttempts = %d, want 2", got.MaxAttempts)
	}
	if got.Branch != "hal/from-flags" {
		t.Fatalf("branch = %q, want %q", got.Branch, "hal/from-flags")
	}
}
