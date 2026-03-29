package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	ci "github.com/jywlabs/hal/internal/ci"
	"github.com/spf13/cobra"
)

func preserveCIPushGlobals(t *testing.T) {
	t.Helper()
	origDryRun := ciPushDryRunFlag
	origJSON := ciPushJSONFlag
	origDeps := defaultCIPushDeps
	t.Cleanup(func() {
		ciPushDryRunFlag = origDryRun
		ciPushJSONFlag = origJSON
		defaultCIPushDeps = origDeps
	})
}

func TestCIPushCommandMetadataAndFlags(t *testing.T) {
	if ciCmd.Use != "ci" {
		t.Fatalf("ciCmd.Use = %q, want %q", ciCmd.Use, "ci")
	}
	if ciPushCmd.Use != "push" {
		t.Fatalf("ciPushCmd.Use = %q, want %q", ciPushCmd.Use, "push")
	}
	if strings.TrimSpace(ciCmd.Long) == "" {
		t.Fatal("ciCmd.Long should not be empty")
	}
	if !strings.Contains(ciPushCmd.Example, "hal ci push") {
		t.Fatalf("ciPushCmd.Example should include command path, got %q", ciPushCmd.Example)
	}

	dryRun := ciPushCmd.Flags().Lookup("dry-run")
	if dryRun == nil {
		t.Fatal("ci push command missing --dry-run flag")
	}
	if dryRun.DefValue != "false" {
		t.Fatalf("--dry-run default = %q, want %q", dryRun.DefValue, "false")
	}

	jsonFlag := ciPushCmd.Flags().Lookup("json")
	if jsonFlag == nil {
		t.Fatal("ci push command missing --json flag")
	}
	if jsonFlag.DefValue != "false" {
		t.Fatalf("--json default = %q, want %q", jsonFlag.DefValue, "false")
	}

	if ciPushCmd.Args == nil {
		t.Fatal("ci push command should reject positional arguments")
	}
	if err := ciPushCmd.Args(ciPushCmd, []string{"unexpected"}); err == nil {
		t.Fatal("ci push command should fail on positional arguments")
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
