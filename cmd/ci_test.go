package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	ci "github.com/jywlabs/hal/internal/ci"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/factory"
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

	origMergeStrategy := ciMergeStrategyFlag
	origMergeDeleteBranch := ciMergeDeleteBranchFlag
	origMergeAllowNoChecks := ciMergeAllowNoChecksFlag
	origMergeDryRun := ciMergeDryRunFlag
	origMergeJSON := ciMergeJSONFlag
	origMergeDeps := defaultCIMergeDeps

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

		ciMergeStrategyFlag = origMergeStrategy
		ciMergeDeleteBranchFlag = origMergeDeleteBranch
		ciMergeAllowNoChecksFlag = origMergeAllowNoChecks
		ciMergeDryRunFlag = origMergeDryRun
		ciMergeJSONFlag = origMergeJSON
		defaultCIMergeDeps = origMergeDeps
	})
}

func TestCICommandHelpMetadata(t *testing.T) {
	tests := []struct {
		name                 string
		cmd                  *cobra.Command
		requiredLongPhrases  []string
		requiredExampleLines []string
	}{
		{
			name: "ci root command",
			cmd:  ciCmd,
			requiredLongPhrases: []string{
				"Run CI-aware workflow commands",
				"push branches",
				"merge safely",
			},
			requiredExampleLines: []string{
				"hal ci push",
				"hal ci status --wait",
				"hal ci fix --max-attempts 2",
				"hal ci merge --strategy squash",
			},
		},
		{
			name: "ci push command",
			cmd:  ciPushCmd,
			requiredLongPhrases: []string{
				"create or reuse an open pull request",
				"--dry-run",
				"--json",
			},
			requiredExampleLines: []string{
				"hal ci push",
				"hal ci push --dry-run",
				"hal ci push --json",
			},
		},
		{
			name: "ci status command",
			cmd:  ciStatusCmd,
			requiredLongPhrases: []string{
				"Use --wait",
				"no checks are detected",
				"--json",
			},
			requiredExampleLines: []string{
				"hal ci status",
				"hal ci status --wait",
				"hal ci status --wait --json",
			},
		},
		{
			name: "ci fix command",
			cmd:  ciFixCmd,
			requiredLongPhrases: []string{
				"--max-attempts",
				"single-attempt CI fix core operation",
				"--json",
			},
			requiredExampleLines: []string{
				"hal ci fix",
				"hal ci fix --max-attempts 3",
				"hal ci fix -e claude",
				"hal ci fix --json",
			},
		},
		{
			name: "ci merge command",
			cmd:  ciMergeCmd,
			requiredLongPhrases: []string{
				"--allow-no-checks",
				"--dry-run",
				"--json",
			},
			requiredExampleLines: []string{
				"hal ci merge",
				"hal ci merge --strategy rebase",
				"hal ci merge --delete-branch",
				"hal ci merge --dry-run --json",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.cmd == nil {
				t.Fatal("command is nil")
			}
			if missing := missingCommandMetadataFields(tt.cmd); len(missing) > 0 {
				t.Fatalf("command %q is missing metadata fields: %s", commandPathLabel(tt.cmd), strings.Join(missing, ", "))
			}

			commandPath := commandPathLabel(tt.cmd)
			if !strings.Contains(tt.cmd.Example, commandPath) {
				t.Fatalf("command %q example must include %q, got %q", commandPath, commandPath, tt.cmd.Example)
			}

			for _, phrase := range tt.requiredLongPhrases {
				if !strings.Contains(tt.cmd.Long, phrase) {
					t.Fatalf("command %q long help must include %q, got %q", commandPath, phrase, tt.cmd.Long)
				}
			}

			for _, line := range tt.requiredExampleLines {
				if !strings.Contains(tt.cmd.Example, line) {
					t.Fatalf("command %q example must include %q, got %q", commandPath, line, tt.cmd.Example)
				}
			}
		})
	}
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

	if ciMergeCmd.Use != "merge" {
		t.Fatalf("ciMergeCmd.Use = %q, want %q", ciMergeCmd.Use, "merge")
	}
	if !strings.Contains(ciMergeCmd.Example, "hal ci merge") {
		t.Fatalf("ciMergeCmd.Example should include command path, got %q", ciMergeCmd.Example)
	}

	strategyFlag := ciMergeCmd.Flags().Lookup("strategy")
	if strategyFlag == nil {
		t.Fatal("ci merge command missing --strategy flag")
	}
	if strategyFlag.DefValue != "squash" {
		t.Fatalf("ci merge --strategy default = %q, want %q", strategyFlag.DefValue, "squash")
	}

	deleteBranchFlag := ciMergeCmd.Flags().Lookup("delete-branch")
	if deleteBranchFlag == nil {
		t.Fatal("ci merge command missing --delete-branch flag")
	}
	if deleteBranchFlag.DefValue != "false" {
		t.Fatalf("ci merge --delete-branch default = %q, want %q", deleteBranchFlag.DefValue, "false")
	}

	allowNoChecksFlag := ciMergeCmd.Flags().Lookup("allow-no-checks")
	if allowNoChecksFlag == nil {
		t.Fatal("ci merge command missing --allow-no-checks flag")
	}
	if allowNoChecksFlag.DefValue != "false" {
		t.Fatalf("ci merge --allow-no-checks default = %q, want %q", allowNoChecksFlag.DefValue, "false")
	}

	mergeDryRunFlag := ciMergeCmd.Flags().Lookup("dry-run")
	if mergeDryRunFlag == nil {
		t.Fatal("ci merge command missing --dry-run flag")
	}
	if mergeDryRunFlag.DefValue != "false" {
		t.Fatalf("ci merge --dry-run default = %q, want %q", mergeDryRunFlag.DefValue, "false")
	}

	mergeJSONFlag := ciMergeCmd.Flags().Lookup("json")
	if mergeJSONFlag == nil {
		t.Fatal("ci merge command missing --json flag")
	}
	if mergeJSONFlag.DefValue != "false" {
		t.Fatalf("ci merge --json default = %q, want %q", mergeJSONFlag.DefValue, "false")
	}

	if ciMergeCmd.Args == nil {
		t.Fatal("ci merge command should reject positional arguments")
	}
	if err := ciMergeCmd.Args(ciMergeCmd, []string{"unexpected"}); err == nil {
		t.Fatal("ci merge command should fail on positional arguments")
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
	if !strings.Contains(output, "dry-run: preview push and pull request actions") {
		t.Fatalf("dry-run output %q missing header context", output)
	}
	if !strings.Contains(output, "CI Push (dry run)") {
		t.Fatalf("dry-run output %q missing title", output)
	}
	if !strings.Contains(output, "Branch:") || !strings.Contains(output, "hal/preview") {
		t.Fatalf("dry-run output %q missing branch details", output)
	}
	if !strings.Contains(output, "PR:") || !strings.Contains(output, "draft pull request") {
		t.Fatalf("dry-run output %q missing pull request mode", output)
	}
	if !strings.Contains(output, "Would push branch and create or reuse a pull request.") {
		t.Fatalf("dry-run output %q missing expected preview text", output)
	}
	if strings.Contains(output, "dry-run: would push branch") {
		t.Fatalf("dry-run output %q should use fixed human copy, not summary text", output)
	}
	if strings.Contains(strings.TrimSpace(output), "{") {
		t.Fatalf("dry-run human output should not be JSON, got %q", output)
	}
}

func TestRunCIPushWithDeps_HumanOutputIncludesBaseBranch(t *testing.T) {
	var buf bytes.Buffer
	err := runCIPushWithDeps(context.Background(), ciPushRunOptions{}, &buf, ciPushDeps{
		pushAndCreatePR: func(context.Context, ci.PushOptions) (ci.PushResult, error) {
			return ci.PushResult{
				ContractVersion: ci.PushContractVersion,
				Branch:          "hal/ci-push",
				Pushed:          true,
				DryRun:          false,
				PullRequest: ci.PullRequest{
					Number:   7,
					URL:      "https://github.com/acme/repo/pull/7",
					BaseRef:  "main",
					Draft:    false,
					Existing: true,
				},
				Summary: "pushed branch hal/ci-push and reused existing pull request",
			}, nil
		},
		currentBranch: func(context.Context) (string, error) {
			t.Fatal("currentBranch should not be called when dry-run=false")
			return "", nil
		},
	})
	if err != nil {
		t.Fatalf("runCIPushWithDeps() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "push current branch and create or reuse a pull request") {
		t.Fatalf("human output %q missing header context", output)
	}
	if !strings.Contains(output, "CI Push") {
		t.Fatalf("human output %q missing title", output)
	}
	if !strings.Contains(output, "Branch:") || !strings.Contains(output, "hal/ci-push") {
		t.Fatalf("human output %q missing branch", output)
	}
	if !strings.Contains(output, "Base:") || !strings.Contains(output, "main") {
		t.Fatalf("human output %q missing base branch", output)
	}
	if !strings.Contains(output, "PR #7:") || !strings.Contains(output, "https://github.com/acme/repo/pull/7") {
		t.Fatalf("human output %q missing PR URL", output)
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

func TestRunCIStatusWithDeps_WaitRendersChecksWhenDiscovered(t *testing.T) {
	want := ci.StatusResult{
		ContractVersion:    ci.StatusContractVersion,
		Branch:             "hal/ci-status",
		SHA:                "deadbeefcafebabe",
		Status:             ci.StatusPassing,
		ChecksDiscovered:   true,
		Wait:               true,
		WaitTerminalReason: ci.WaitTerminalReasonCompleted,
		Checks: []ci.StatusCheck{
			{Key: "check:tests", Name: "tests", Status: ci.StatusPassing},
			{Key: "status:lint", Name: "lint", Status: ci.StatusFailing},
		},
		Totals: ci.StatusTotals{Passing: 1, Failing: 1},
	}

	var buf bytes.Buffer
	err := runCIStatusWithDeps(context.Background(), ciStatusRunOptions{Wait: true}, &buf, ciStatusDeps{
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

	output := buf.String()
	if !strings.Contains(output, "wait for CI checks to complete") {
		t.Fatalf("wait output %q missing header context", output)
	}
	if !strings.Contains(output, "Wait:") || !strings.Contains(output, ci.WaitTerminalReasonCompleted) {
		t.Fatalf("wait output %q missing terminal reason", output)
	}
	if !strings.Contains(output, "Checks:") {
		t.Fatalf("wait output %q missing checks section", output)
	}
	if !strings.Contains(output, "tests") || !strings.Contains(output, "lint") {
		t.Fatalf("wait output %q missing check names", output)
	}
	if !strings.Contains(output, "Totals:") || !strings.Contains(output, "1 passing") || !strings.Contains(output, "1 failing") {
		t.Fatalf("wait output %q missing totals", output)
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
			if opts.Display != nil {
				t.Fatal("opts.Display should be nil in --json mode")
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

func TestRunCIFixWithDeps_HumanOutputShowsProgressAndPassesDisplay(t *testing.T) {
	want := ci.FixResult{
		ContractVersion: ci.FixContractVersion,
		Attempt:         1,
		MaxAttempts:     3,
		Applied:         true,
		Branch:          "hal/ci-fix",
		CommitSHA:       "deadbeef",
		Pushed:          true,
		FilesChanged:    []string{"cmd/ci.go"},
		Summary:         "applied ci fix attempt 1 on branch hal/ci-fix and pushed 1 file",
	}

	displayPassed := false

	var buf bytes.Buffer
	err := runCIFixWithDeps(context.Background(), ciFixRunOptions{MaxAttempts: 3, Engine: "codex"}, &buf, ciFixDeps{
		newEngine: func(string) (engine.Engine, error) {
			return ciFakeEngine{}, nil
		},
		getStatus: func(context.Context) (ci.StatusResult, error) {
			return ci.StatusResult{Status: ci.StatusFailing, Branch: "hal/ci-fix"}, nil
		},
		waitForChecks: func(context.Context, ci.WaitOptions) (ci.StatusResult, error) {
			return ci.StatusResult{Status: ci.StatusPassing, Branch: "hal/ci-fix"}, nil
		},
		fixWithEngine: func(_ context.Context, _ ci.StatusResult, opts ci.FixOptions) (ci.FixResult, error) {
			if opts.Display == nil {
				t.Fatal("opts.Display should be non-nil in human mode")
			}
			displayPassed = true
			return want, nil
		},
	})
	if err != nil {
		t.Fatalf("runCIFixWithDeps() error = %v", err)
	}

	output := buf.String()
	for _, needle := range []string{
		"fix failing checks (max attempts: 3)",
		"Checking current CI status...",
		"Running fix attempt 1/3...",
		"Waiting for CI checks after attempt 1/3...",
		"CI Fix",
		"Status:",
	} {
		if !strings.Contains(output, needle) {
			t.Fatalf("human output %q missing %q", output, needle)
		}
	}
	if strings.Contains(strings.TrimSpace(output), "{\"") {
		t.Fatalf("human output should not be JSON, got %q", output)
	}
	if !displayPassed {
		t.Fatal("expected fixWithEngine to receive non-nil display")
	}
}

func TestRunCIFixWithDeps_ReturnsLastFixResultWhenStatusClearsBeforeNextAttempt(t *testing.T) {
	want := ci.FixResult{
		ContractVersion: ci.FixContractVersion,
		Attempt:         1,
		MaxAttempts:     3,
		Applied:         true,
		Branch:          "hal/ci-fix",
		CommitSHA:       "deadbeef",
		Pushed:          true,
		FilesChanged:    []string{"cmd/ci.go"},
		Summary:         "applied ci fix attempt 1 on branch hal/ci-fix and pushed 1 file",
	}

	statusCalls := 0
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
			statusCalls++
			if statusCalls == 1 {
				return ci.StatusResult{Status: ci.StatusFailing, Branch: "hal/ci-fix"}, nil
			}
			return ci.StatusResult{Status: ci.StatusPassing, Branch: "hal/ci-fix"}, nil
		},
		waitForChecks: func(context.Context, ci.WaitOptions) (ci.StatusResult, error) {
			waitCalls++
			return ci.StatusResult{Status: ci.StatusFailing, Branch: "hal/ci-fix"}, nil
		},
		fixWithEngine: func(context.Context, ci.StatusResult, ci.FixOptions) (ci.FixResult, error) {
			fixCalls++
			return want, nil
		},
	})
	if err != nil {
		t.Fatalf("runCIFixWithDeps() error = %v", err)
	}
	if statusCalls != 2 {
		t.Fatalf("getStatus calls = %d, want 2", statusCalls)
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

	var got ci.FixResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}
	if got.Attempt != want.Attempt {
		t.Fatalf("attempt = %d, want %d", got.Attempt, want.Attempt)
	}
	if !got.Applied {
		t.Fatal("applied = false, want true")
	}
	if got.CommitSHA != want.CommitSHA {
		t.Fatalf("commitSha = %q, want %q", got.CommitSHA, want.CommitSHA)
	}
	if got.Summary != want.Summary {
		t.Fatalf("summary = %q, want %q", got.Summary, want.Summary)
	}
}

func TestRunCIFixWithDeps_ReturnsErrorWhenStatusPendingBeforeNextAttempt(t *testing.T) {
	statusCalls := 0
	fixCalls := 0
	waitCalls := 0

	err := runCIFixWithDeps(context.Background(), ciFixRunOptions{MaxAttempts: 3, Engine: "codex"}, io.Discard, ciFixDeps{
		newEngine: func(string) (engine.Engine, error) {
			return ciFakeEngine{}, nil
		},
		getStatus: func(context.Context) (ci.StatusResult, error) {
			statusCalls++
			if statusCalls == 1 {
				return ci.StatusResult{Status: ci.StatusFailing, Branch: "hal/ci-fix"}, nil
			}
			return ci.StatusResult{Status: ci.StatusPending, Branch: "hal/ci-fix"}, nil
		},
		waitForChecks: func(context.Context, ci.WaitOptions) (ci.StatusResult, error) {
			waitCalls++
			return ci.StatusResult{Status: ci.StatusFailing, Branch: "hal/ci-fix"}, nil
		},
		fixWithEngine: func(context.Context, ci.StatusResult, ci.FixOptions) (ci.FixResult, error) {
			fixCalls++
			return ci.FixResult{
				ContractVersion: ci.FixContractVersion,
				Attempt:         1,
				MaxAttempts:     3,
				Applied:         true,
				Branch:          "hal/ci-fix",
				Pushed:          true,
				Summary:         "attempt",
			}, nil
		},
	})
	if err == nil {
		t.Fatal("runCIFixWithDeps() error = nil, want pending-status error")
	}
	wantErr := "ci status is pending after attempt 1; run 'hal ci status --wait' for details"
	if err.Error() != wantErr {
		t.Fatalf("error = %q, want %q", err.Error(), wantErr)
	}
	if statusCalls != 2 {
		t.Fatalf("getStatus calls = %d, want 2", statusCalls)
	}
	if fixCalls != 1 {
		t.Fatalf("fixWithEngine calls = %d, want 1", fixCalls)
	}
	if waitCalls != 1 {
		t.Fatalf("waitForChecks calls = %d, want 1", waitCalls)
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

func TestRunCIFixWithDeps_HumanOutputIncludesBranchWhenNoAttemptNeeded(t *testing.T) {
	newEngineCalled := false

	var buf bytes.Buffer
	err := runCIFixWithDeps(context.Background(), ciFixRunOptions{MaxAttempts: 3, Engine: "codex"}, &buf, ciFixDeps{
		newEngine: func(string) (engine.Engine, error) {
			newEngineCalled = true
			return ciFakeEngine{}, nil
		},
		getStatus: func(context.Context) (ci.StatusResult, error) {
			return ci.StatusResult{Status: ci.StatusPassing, Branch: "hal/ci-fix"}, nil
		},
		waitForChecks: func(context.Context, ci.WaitOptions) (ci.StatusResult, error) {
			t.Fatal("waitForChecks should not be called when no attempt is made")
			return ci.StatusResult{}, nil
		},
		fixWithEngine: func(context.Context, ci.StatusResult, ci.FixOptions) (ci.FixResult, error) {
			t.Fatal("fixWithEngine should not be called when no attempt is made")
			return ci.FixResult{}, nil
		},
	})
	if err != nil {
		t.Fatalf("runCIFixWithDeps() error = %v", err)
	}
	if newEngineCalled {
		t.Fatal("newEngine should not be called when status is not failing")
	}

	output := buf.String()
	if !strings.Contains(output, "CI Fix") {
		t.Fatalf("human output %q missing title", output)
	}
	if !strings.Contains(output, "Branch:") || !strings.Contains(output, "hal/ci-fix") {
		t.Fatalf("human output %q missing branch", output)
	}
	if !strings.Contains(output, "Status:") || !strings.Contains(output, "no fix attempt needed") {
		t.Fatalf("human output %q missing no-attempt status", output)
	}
	if strings.Contains(strings.TrimSpace(output), "{") {
		t.Fatalf("human output should not be JSON, got %q", output)
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

func TestRunCIFix_DefersEngineResolutionWhenStatusNotFailing(t *testing.T) {
	preserveCIPushGlobals(t)

	ciFixMaxAttemptsFlag = 3
	ciFixEngineFlag = "codex"
	ciFixJSONFlag = true

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmpDir := t.TempDir()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})

	halDir := filepath.Join(tmpDir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "config.yaml"), []byte("engine: ["), 0o644); err != nil {
		t.Fatalf("write malformed config: %v", err)
	}

	newEngineCalled := false
	statusCalls := 0
	defaultCIFixDeps = ciFixDeps{
		newEngine: func(string) (engine.Engine, error) {
			newEngineCalled = true
			return ciFakeEngine{}, nil
		},
		getStatus: func(context.Context) (ci.StatusResult, error) {
			statusCalls++
			return ci.StatusResult{Status: ci.StatusPassing, Branch: "hal/noop"}, nil
		},
		waitForChecks: func(context.Context, ci.WaitOptions) (ci.StatusResult, error) {
			t.Fatal("waitForChecks should not be called when status is not failing")
			return ci.StatusResult{}, nil
		},
		fixWithEngine: func(context.Context, ci.StatusResult, ci.FixOptions) (ci.FixResult, error) {
			t.Fatal("fixWithEngine should not be called when status is not failing")
			return ci.FixResult{}, nil
		},
	}

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "fix"}
	cmd.SetOut(&out)
	cmd.Flags().Int("max-attempts", 3, "")
	cmd.Flags().String("engine", "codex", "")
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}

	if err := runCIFix(cmd, nil); err != nil {
		t.Fatalf("runCIFix() error = %v", err)
	}
	if statusCalls != 1 {
		t.Fatalf("getStatus calls = %d, want 1", statusCalls)
	}
	if newEngineCalled {
		t.Fatal("newEngine should not be called when status is not failing")
	}

	var got ci.FixResult
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("runCIFix JSON output parse failed: %v\noutput: %s", err, out.String())
	}
	if got.Attempt != 0 {
		t.Fatalf("attempt = %d, want 0", got.Attempt)
	}
	if !strings.Contains(got.Summary, "no fix attempt needed") {
		t.Fatalf("summary = %q, want no-attempt text", got.Summary)
	}
}

func TestRunCIMergeWithDeps_JSONOnlyOutput(t *testing.T) {
	want := ci.MergeResult{
		ContractVersion: ci.MergeContractVersion,
		PRNumber:        77,
		Strategy:        "rebase",
		DryRun:          false,
		Merged:          true,
		MergeCommitSHA:  "deadbeef",
		BranchDeleted:   true,
		Summary:         "merged pull request #77 using rebase strategy and deleted the remote branch",
	}

	var buf bytes.Buffer
	err := runCIMergeWithDeps(context.Background(), ciMergeRunOptions{Strategy: "rebase", DeleteBranch: true, JSON: true}, &buf, ciMergeDeps{
		mergePR: func(_ context.Context, opts ci.MergeOptions) (ci.MergeResult, error) {
			if opts.Strategy != "rebase" {
				t.Fatalf("opts.Strategy = %q, want %q", opts.Strategy, "rebase")
			}
			if !opts.DeleteBranch {
				t.Fatal("opts.DeleteBranch = false, want true")
			}
			return want, nil
		},
		repoRoot: func(context.Context) (string, error) {
			return ".", nil
		},
		currentBranch: func(context.Context) (string, error) {
			t.Fatal("currentBranch should not be called when dry-run=false")
			return "", nil
		},
	})
	if err != nil {
		t.Fatalf("runCIMergeWithDeps() error = %v", err)
	}

	output := strings.TrimSpace(buf.String())
	if !strings.HasPrefix(output, "{") || !strings.HasSuffix(output, "}") {
		t.Fatalf("expected JSON-only output, got %q", output)
	}
	if strings.Contains(output, "Merge commit:") {
		t.Fatalf("JSON output should not include human text, got %q", output)
	}

	var got ci.MergeResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal JSON output: %v", err)
	}
	if got.ContractVersion != ci.MergeContractVersion {
		t.Fatalf("contractVersion = %q, want %q", got.ContractVersion, ci.MergeContractVersion)
	}
	if got.PRNumber != want.PRNumber {
		t.Fatalf("prNumber = %d, want %d", got.PRNumber, want.PRNumber)
	}
	if got.Strategy != want.Strategy {
		t.Fatalf("strategy = %q, want %q", got.Strategy, want.Strategy)
	}
	if got.MergeCommitSHA != want.MergeCommitSHA {
		t.Fatalf("mergeCommitSha = %q, want %q", got.MergeCommitSHA, want.MergeCommitSHA)
	}
}

func TestRunCIMergeWithDeps_DryRunSkipsSideEffects(t *testing.T) {
	mergeCalls := 0

	var buf bytes.Buffer
	err := runCIMergeWithDeps(context.Background(), ciMergeRunOptions{Strategy: "merge", DeleteBranch: true, DryRun: true}, &buf, ciMergeDeps{
		mergePR: func(context.Context, ci.MergeOptions) (ci.MergeResult, error) {
			mergeCalls++
			return ci.MergeResult{}, nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "hal/ci-merge", nil
		},
		findOpenPR: func(context.Context, string) (*ci.PullRequest, error) {
			return &ci.PullRequest{Number: 21, BaseRef: "main"}, nil
		},
	})
	if err != nil {
		t.Fatalf("runCIMergeWithDeps() error = %v", err)
	}
	if mergeCalls != 0 {
		t.Fatalf("mergePR called %d times, want 0 in dry-run", mergeCalls)
	}

	output := buf.String()
	if !strings.Contains(output, "dry-run: preview merge (strategy: merge)") {
		t.Fatalf("dry-run output %q missing header context", output)
	}
	if !strings.Contains(output, "CI Merge (dry run)") {
		t.Fatalf("dry-run output %q missing title", output)
	}
	if !strings.Contains(output, "Branch:") || !strings.Contains(output, "hal/ci-merge") {
		t.Fatalf("dry-run output %q missing branch", output)
	}
	if !strings.Contains(output, "PR:") || !strings.Contains(output, "#21") {
		t.Fatalf("dry-run output %q missing PR details", output)
	}
	if !strings.Contains(output, "Base:") || !strings.Contains(output, "main") {
		t.Fatalf("dry-run output %q missing base branch", output)
	}
	if !strings.Contains(output, "Strategy:") || !strings.Contains(output, "merge") {
		t.Fatalf("dry-run output %q missing strategy", output)
	}
	if !strings.Contains(output, "Delete:") || !strings.Contains(output, "Yes") {
		t.Fatalf("dry-run output %q missing delete intent", output)
	}
	if !strings.Contains(output, "Would merge pull request and delete the remote branch.") {
		t.Fatalf("dry-run output %q missing expected preview text", output)
	}
	if strings.Contains(output, "dry-run: would merge pull request for branch") {
		t.Fatalf("dry-run output %q should use fixed human copy, not summary text", output)
	}
	if strings.Contains(strings.TrimSpace(output), "{") {
		t.Fatalf("dry-run human output should not be JSON, got %q", output)
	}
}

func TestRunCIMergeWithDeps_DryRunRequiresOpenPR(t *testing.T) {
	mergeCalls := 0

	var buf bytes.Buffer
	err := runCIMergeWithDeps(context.Background(), ciMergeRunOptions{Strategy: "merge", DryRun: true}, &buf, ciMergeDeps{
		mergePR: func(context.Context, ci.MergeOptions) (ci.MergeResult, error) {
			mergeCalls++
			return ci.MergeResult{}, nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "hal/ci-merge", nil
		},
		findOpenPR: func(context.Context, string) (*ci.PullRequest, error) {
			return nil, nil
		},
	})
	if !errors.Is(err, ci.ErrMergePRNotFound) {
		t.Fatalf("errors.Is(err, ci.ErrMergePRNotFound) = false, err=%v", err)
	}
	if mergeCalls != 0 {
		t.Fatalf("mergePR called %d times, want 0 when open pull request is missing", mergeCalls)
	}
}

func TestRunCIMergeWithDeps_BlocksWhenMergePolicyDisabled(t *testing.T) {
	mergeCalls := 0

	var buf bytes.Buffer
	err := runCIMergeWithDeps(context.Background(), ciMergeRunOptions{Strategy: "merge"}, &buf, ciMergeDeps{
		mergePR: func(context.Context, ci.MergeOptions) (ci.MergeResult, error) {
			mergeCalls++
			return ci.MergeResult{}, nil
		},
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			policy := factory.DefaultFactoryPolicy()
			policy.MergeAllowed = false
			return &policy, nil
		},
		repoRoot: func(context.Context) (string, error) {
			return ".", nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "factory.policy.mergeAllowed=false") {
		t.Fatalf("runCIMergeWithDeps() error = %v, want merge policy block", err)
	}
	if mergeCalls != 0 {
		t.Fatalf("mergePR called %d times, want 0 when merge policy is disabled", mergeCalls)
	}
}

func TestRunCIMergeWithDeps_LoadsPolicyFromRepoRoot(t *testing.T) {
	root := t.TempDir()
	subdir := filepath.Join(root, "nested", "package")
	if err := os.MkdirAll(filepath.Join(root, ".hal"), 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".hal", "config.yaml"), []byte("factory:\n  policy:\n    mergeAllowed: false\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error: %v", err)
	}
	if err := os.Chdir(subdir); err != nil {
		t.Fatalf("chdir subdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})

	mergeCalls := 0
	var buf bytes.Buffer
	err = runCIMergeWithDeps(context.Background(), ciMergeRunOptions{Strategy: "merge"}, &buf, ciMergeDeps{
		mergePR: func(context.Context, ci.MergeOptions) (ci.MergeResult, error) {
			mergeCalls++
			return ci.MergeResult{}, nil
		},
		repoRoot: func(context.Context) (string, error) {
			return root, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "factory.policy.mergeAllowed=false") {
		t.Fatalf("runCIMergeWithDeps() error = %v, want root merge policy block", err)
	}
	if mergeCalls != 0 {
		t.Fatalf("mergePR called %d times, want 0 when root merge policy is disabled", mergeCalls)
	}
}

func TestRunCIMergeWithDeps_HumanOutputShowsBranchAlreadyAbsent(t *testing.T) {
	var buf bytes.Buffer
	err := runCIMergeWithDeps(context.Background(), ciMergeRunOptions{Strategy: "squash", DeleteBranch: true}, &buf, ciMergeDeps{
		mergePR: func(context.Context, ci.MergeOptions) (ci.MergeResult, error) {
			return ci.MergeResult{
				ContractVersion: ci.MergeContractVersion,
				PRNumber:        42,
				Strategy:        "squash",
				Merged:          true,
				MergeCommitSHA:  "deadbeef",
				BranchDeleted:   false,
				DeleteWarning:   "",
				Summary:         "merged pull request #42 using squash strategy; remote branch already absent",
			}, nil
		},
		repoRoot: func(context.Context) (string, error) {
			return ".", nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "hal/ci-merge", nil
		},
		findOpenPR: func(context.Context, string) (*ci.PullRequest, error) {
			return &ci.PullRequest{Number: 42, BaseRef: "main"}, nil
		},
	})
	if err != nil {
		t.Fatalf("runCIMergeWithDeps() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "merge pull request (strategy: squash)") {
		t.Fatalf("human output %q missing header context", output)
	}
	if !strings.Contains(output, "CI Merge") {
		t.Fatalf("human output %q missing title", output)
	}
	if !strings.Contains(output, "Branch:") || !strings.Contains(output, "hal/ci-merge") {
		t.Fatalf("human output %q missing source branch", output)
	}
	if !strings.Contains(output, "PR:") || !strings.Contains(output, "#42") {
		t.Fatalf("human output %q missing PR details", output)
	}
	if !strings.Contains(output, "Base:") || !strings.Contains(output, "main") {
		t.Fatalf("human output %q missing base branch", output)
	}
	if !strings.Contains(output, "Commit:") || !strings.Contains(output, "deadbee") {
		t.Fatalf("human output %q missing shortened commit sha", output)
	}
	if !strings.Contains(output, "Branch:") || !strings.Contains(output, "Already absent") {
		t.Fatalf("human output %q missing already-absent branch outcome", output)
	}
}

func TestRunCIMerge_UsesCommandFlagValues(t *testing.T) {
	preserveCIPushGlobals(t)

	ciMergeStrategyFlag = "squash"
	ciMergeDeleteBranchFlag = false
	ciMergeAllowNoChecksFlag = false
	ciMergeDryRunFlag = false
	ciMergeJSONFlag = false

	mergeCalled := false
	captured := ci.MergeOptions{}
	defaultCIMergeDeps = ciMergeDeps{
		mergePR: func(_ context.Context, opts ci.MergeOptions) (ci.MergeResult, error) {
			mergeCalled = true
			captured = opts
			return ci.MergeResult{
				ContractVersion: ci.MergeContractVersion,
				PRNumber:        88,
				Strategy:        opts.Strategy,
				DryRun:          false,
				Merged:          true,
				MergeCommitSHA:  "cafebabe",
				BranchDeleted:   opts.DeleteBranch,
				Summary:         "merged pull request #88",
			}, nil
		},
		currentBranch: func(context.Context) (string, error) {
			return "hal/unused", nil
		},
	}

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "merge"}
	cmd.SetOut(&out)
	cmd.Flags().String("strategy", "squash", "")
	cmd.Flags().Bool("delete-branch", false, "")
	cmd.Flags().Bool("allow-no-checks", false, "")
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("strategy", "rebase"); err != nil {
		t.Fatalf("set --strategy: %v", err)
	}
	if err := cmd.Flags().Set("delete-branch", "true"); err != nil {
		t.Fatalf("set --delete-branch: %v", err)
	}
	if err := cmd.Flags().Set("allow-no-checks", "true"); err != nil {
		t.Fatalf("set --allow-no-checks: %v", err)
	}
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}

	if err := runCIMerge(cmd, nil); err != nil {
		t.Fatalf("runCIMerge() error = %v", err)
	}
	if !mergeCalled {
		t.Fatal("runCIMerge should call mergePR when dry-run=false")
	}
	if captured.Strategy != "rebase" {
		t.Fatalf("merge options strategy = %q, want %q", captured.Strategy, "rebase")
	}
	if !captured.DeleteBranch {
		t.Fatal("merge options deleteBranch = false, want true")
	}
	if !captured.AllowNoChecks {
		t.Fatal("merge options allowNoChecks = false, want true")
	}

	var got ci.MergeResult
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("runCIMerge JSON output parse failed: %v\noutput: %s", err, out.String())
	}
	if got.ContractVersion != ci.MergeContractVersion {
		t.Fatalf("contractVersion = %q, want %q", got.ContractVersion, ci.MergeContractVersion)
	}
	if got.Strategy != "rebase" {
		t.Fatalf("strategy = %q, want %q", got.Strategy, "rebase")
	}
	if got.PRNumber != 88 {
		t.Fatalf("prNumber = %d, want 88", got.PRNumber)
	}
	if got.DryRun {
		t.Fatal("dryRun = true, want false")
	}
}
