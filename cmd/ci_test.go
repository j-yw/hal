package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	ci "github.com/jywlabs/hal/internal/ci"
	"github.com/spf13/cobra"
)

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
