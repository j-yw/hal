//go:build integration
// +build integration

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/cloud"
	cloudconfig "github.com/jywlabs/hal/internal/cloud/config"
	"github.com/jywlabs/hal/internal/template"
)

// cloudLifecycleCommandInvocation describes one lifecycle command execution.
type cloudLifecycleCommandInvocation struct {
	Args   []string
	RunID  string
	JSON   bool
	Stdin  io.Reader
	Stdout io.Writer

	Context context.Context
}

// cloudLifecycleCommandResult captures command output and execution error.
type cloudLifecycleCommandResult struct {
	Output string
	Err    error
}

// cloudLifecycleCommandRunner executes lifecycle commands with injected IO while
// keeping output capture deterministic for assertions.
type cloudLifecycleCommandRunner struct {
	halDir  string
	baseDir string

	storeFactory        func() (cloud.Store, error)
	runConfigFactory    func() cloud.SubmitConfig
	autoConfigFactory   func() cloud.SubmitConfig
	reviewConfigFactory func() cloud.SubmitConfig
}

func newCloudLifecycleCommandRunner(h *cloudLifecycleIntegrationHarness) *cloudLifecycleCommandRunner {
	runner := &cloudLifecycleCommandRunner{
		halDir:  h.HalDir,
		baseDir: h.WorkspaceDir,
		storeFactory: func() (cloud.Store, error) {
			return h.Store, nil
		},
		runConfigFactory:    runCloudConfigFactory,
		autoConfigFactory:   autoCloudConfigFactory,
		reviewConfigFactory: reviewCloudConfigFactory,
	}

	if runner.runConfigFactory == nil {
		runner.runConfigFactory = defaultCloudSubmitConfig
	}
	if runner.autoConfigFactory == nil {
		runner.autoConfigFactory = defaultCloudSubmitConfig
	}
	if runner.reviewConfigFactory == nil {
		runner.reviewConfigFactory = defaultCloudSubmitConfig
	}

	return runner
}

func (r *cloudLifecycleCommandRunner) Run(inv cloudLifecycleCommandInvocation) cloudLifecycleCommandResult {
	args := replaceLifecycleRunIDPlaceholder(inv.Args, inv.RunID)
	args = appendLifecycleJSONFlag(args, inv.JSON)

	var capture bytes.Buffer
	stdout := io.Writer(&capture)
	if inv.Stdout != nil {
		stdout = io.MultiWriter(&capture, inv.Stdout)
	}

	commandName := lifecycleCommandName(args)
	stdin := inv.Stdin
	if stdin == nil {
		stdin = defaultLifecycleStdin(commandName)
	}

	ctx := inv.Context
	if ctx == nil {
		ctx = context.Background()
	}

	err := r.execute(args, stdin, stdout, ctx)
	return cloudLifecycleCommandResult{
		Output: capture.String(),
		Err:    err,
	}
}

func (r *cloudLifecycleCommandRunner) execute(args []string, in io.Reader, out io.Writer, ctx context.Context) error {
	if len(args) == 0 {
		return fmt.Errorf("command args must not be empty")
	}

	switch args[0] {
	case "run":
		flags, err := parseLifecycleWorkflowFlags("run", args[1:])
		if err != nil {
			return err
		}
		return runHalRunCloud(flags, r.halDir, r.baseDir, r.storeFactory, r.runConfigFactory, out)
	case "auto":
		flags, err := parseLifecycleWorkflowFlags("auto", args[1:])
		if err != nil {
			return err
		}
		return runHalAutoCloud(flags, r.halDir, r.baseDir, r.storeFactory, r.autoConfigFactory, out)
	case "review":
		flags, err := parseLifecycleWorkflowFlags("review", args[1:])
		if err != nil {
			return err
		}
		return runHalReviewCloud(flags, r.halDir, r.baseDir, r.storeFactory, r.reviewConfigFactory, out)
	case "cloud":
		return r.executeCloudCommand(args, in, out, ctx)
	default:
		return fmt.Errorf("unsupported lifecycle command %q", args[0])
	}
}

func (r *cloudLifecycleCommandRunner) executeCloudCommand(args []string, in io.Reader, out io.Writer, ctx context.Context) error {
	if len(args) < 2 {
		return fmt.Errorf("cloud command requires a subcommand")
	}

	subcommand := args[1]
	subArgs := args[2:]

	switch subcommand {
	case "setup":
		profile, err := parseCloudSetupFlags(subArgs)
		if err != nil {
			return err
		}
		return runCloudSetup(r.halDir, profile, in, out)
	case "list":
		jsonOutput, err := parseCloudListFlags(subArgs)
		if err != nil {
			return err
		}
		return runCloudList(jsonOutput, r.storeFactory, out)
	case "status":
		runID, jsonOutput, err := parseCloudRunIDFlags("status", subArgs)
		if err != nil {
			return err
		}
		return runCloudStatus(runID, jsonOutput, r.storeFactory, out)
	case "logs":
		runID, follow, jsonOutput, err := parseCloudLogsFlags(subArgs)
		if err != nil {
			return err
		}
		return runCloudLogs(runID, follow, jsonOutput, r.storeFactory, out, ctx)
	case "cancel":
		runID, jsonOutput, err := parseCloudRunIDFlags("cancel", subArgs)
		if err != nil {
			return err
		}
		return runCloudCancel(runID, jsonOutput, r.storeFactory, out)
	case "pull":
		runID, force, jsonOutput, artifacts, err := parseCloudPullFlags(subArgs)
		if err != nil {
			return err
		}
		return runCloudPull(runID, force, jsonOutput, artifacts, r.storeFactory, r.baseDir, out)
	default:
		return fmt.Errorf("unsupported cloud lifecycle subcommand %q", subcommand)
	}
}

func parseLifecycleWorkflowFlags(command string, args []string) (*CloudFlags, error) {
	flags := &CloudFlags{}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			continue
		}

		switch arg {
		case "--cloud":
			flags.Cloud = true
		case "--detach":
			flags.Detach = true
		case "--wait":
			flags.Wait = true
		case "--json":
			flags.JSON = true
		case "--cloud-profile":
			value, next, err := lifecycleFlagValue(args, i)
			if err != nil {
				return nil, err
			}
			flags.CloudProfile = value
			i = next
		case "--cloud-mode":
			value, next, err := lifecycleFlagValue(args, i)
			if err != nil {
				return nil, err
			}
			flags.CloudMode = value
			i = next
		case "--cloud-endpoint":
			value, next, err := lifecycleFlagValue(args, i)
			if err != nil {
				return nil, err
			}
			flags.CloudEndpoint = value
			i = next
		case "--cloud-repo":
			value, next, err := lifecycleFlagValue(args, i)
			if err != nil {
				return nil, err
			}
			flags.CloudRepo = value
			i = next
		case "--cloud-base":
			value, next, err := lifecycleFlagValue(args, i)
			if err != nil {
				return nil, err
			}
			flags.CloudBase = value
			i = next
		case "--cloud-auth-profile":
			value, next, err := lifecycleFlagValue(args, i)
			if err != nil {
				return nil, err
			}
			flags.CloudAuthProfile = value
			i = next
		case "--cloud-auth-scope":
			value, next, err := lifecycleFlagValue(args, i)
			if err != nil {
				return nil, err
			}
			flags.CloudAuthScope = value
			i = next
		default:
			return nil, fmt.Errorf("unsupported %s flag %q", command, arg)
		}
	}

	if !flags.Cloud {
		return nil, fmt.Errorf("%s command requires --cloud", command)
	}

	// The harness does not run workers, so default to detach when neither
	// --detach nor --wait is explicitly provided.
	if !flags.Detach && !flags.Wait {
		flags.Detach = true
	}

	return flags, nil
}

func parseCloudSetupFlags(args []string) (string, error) {
	profile := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--profile":
			value, next, err := lifecycleFlagValue(args, i)
			if err != nil {
				return "", err
			}
			profile = value
			i = next
		default:
			return "", fmt.Errorf("unsupported cloud setup flag %q", args[i])
		}
	}
	return profile, nil
}

func parseCloudListFlags(args []string) (bool, error) {
	jsonOutput := false
	for _, arg := range args {
		switch arg {
		case "--json":
			jsonOutput = true
		default:
			return false, fmt.Errorf("unsupported cloud list flag %q", arg)
		}
	}
	return jsonOutput, nil
}

func parseCloudRunIDFlags(command string, args []string) (string, bool, error) {
	if len(args) == 0 {
		return "", false, fmt.Errorf("cloud %s requires <run-id>", command)
	}

	runID := args[0]
	jsonOutput := false
	for _, arg := range args[1:] {
		switch arg {
		case "--json":
			jsonOutput = true
		default:
			return "", false, fmt.Errorf("unsupported cloud %s flag %q", command, arg)
		}
	}

	return runID, jsonOutput, nil
}

func parseCloudLogsFlags(args []string) (string, bool, bool, error) {
	if len(args) == 0 {
		return "", false, false, fmt.Errorf("cloud logs requires <run-id>")
	}

	runID := args[0]
	follow := false
	jsonOutput := false

	for _, arg := range args[1:] {
		switch arg {
		case "--follow":
			follow = true
		case "--json":
			jsonOutput = true
		default:
			return "", false, false, fmt.Errorf("unsupported cloud logs flag %q", arg)
		}
	}

	return runID, follow, jsonOutput, nil
}

func parseCloudPullFlags(args []string) (string, bool, bool, string, error) {
	if len(args) == 0 {
		return "", false, false, "", fmt.Errorf("cloud pull requires <run-id>")
	}

	runID := args[0]
	force := false
	jsonOutput := false
	artifacts := "all"

	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--force":
			force = true
		case "--json":
			jsonOutput = true
		case "--artifacts":
			value, next, err := lifecycleFlagValue(args, i)
			if err != nil {
				return "", false, false, "", err
			}
			artifacts = value
			i = next
		default:
			return "", false, false, "", fmt.Errorf("unsupported cloud pull flag %q", args[i])
		}
	}

	return runID, force, jsonOutput, artifacts, nil
}

func lifecycleFlagValue(args []string, index int) (string, int, error) {
	if index+1 >= len(args) {
		return "", index, fmt.Errorf("flag %s requires a value", args[index])
	}
	return args[index+1], index + 1, nil
}

func replaceLifecycleRunIDPlaceholder(args []string, runID string) []string {
	resolved := make([]string, len(args))
	copy(resolved, args)

	for i, arg := range resolved {
		if arg == cloudLifecycleRunIDPlaceholder && runID != "" {
			resolved[i] = runID
		}
	}
	return resolved
}

func appendLifecycleJSONFlag(args []string, forceJSON bool) []string {
	if !forceJSON || len(args) == 0 || containsLifecycleArg(args, "--json") {
		return args
	}

	if !cloudLifecycleSupportsJSON(lifecycleCommandName(args)) {
		return args
	}

	withJSON := make([]string, len(args), len(args)+1)
	copy(withJSON, args)
	return append(withJSON, "--json")
}

func lifecycleCommandName(args []string) string {
	if len(args) == 0 {
		return ""
	}
	if args[0] == "cloud" && len(args) > 1 {
		return args[1]
	}
	return args[0]
}

func cloudLifecycleSupportsJSON(commandName string) bool {
	for _, command := range cloudLifecycleCommandSurface {
		if command.Name == commandName {
			return command.SupportsJSON
		}
	}
	return false
}

func containsLifecycleArg(args []string, target string) bool {
	for _, arg := range args {
		if arg == target {
			return true
		}
	}
	return false
}

func defaultLifecycleStdin(commandName string) io.Reader {
	if commandName == "setup" {
		return strings.NewReader(strings.Repeat("\n", 9))
	}
	return strings.NewReader("")
}

func lifecycleCommandArgs(t *testing.T, name string) []string {
	t.Helper()
	for _, command := range cloudLifecycleCommandSurface {
		if command.Name == name {
			args := make([]string, len(command.Args))
			copy(args, command.Args)
			return args
		}
	}
	t.Fatalf("command %q not found in cloudLifecycleCommandSurface", name)
	return nil
}

func TestCloudLifecycleCommandRunner_ExecutesCommandsWithInjectedIO(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	runner := newCloudLifecycleCommandRunner(h)

	var mirrored bytes.Buffer
	result := runner.Run(cloudLifecycleCommandInvocation{
		Args:   []string{"cloud", "setup", "--profile", "ci"},
		Stdin:  strings.NewReader(strings.Repeat("\n", 8)),
		Stdout: &mirrored,
	})
	if result.Err != nil {
		t.Fatalf("setup command returned error: %v", result.Err)
	}
	if !strings.Contains(result.Output, "Cloud profile configured.") {
		t.Fatalf("captured output missing setup summary: %s", result.Output)
	}
	if !strings.Contains(mirrored.String(), "Cloud profile configured.") {
		t.Fatalf("injected stdout missing setup summary: %s", mirrored.String())
	}

	cfg, err := cloudconfig.Load(filepath.Join(h.HalDir, template.CloudConfigFile))
	if err != nil {
		t.Fatalf("failed to load generated cloud config: %v", err)
	}
	if cfg.GetProfile("ci") == nil {
		t.Fatalf("expected configured profile %q to be written", "ci")
	}
}

func TestCloudLifecycleCommandRunner_ReturnsCapturedOutputAndErrors(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	runner := newCloudLifecycleCommandRunner(h)

	result := runner.Run(cloudLifecycleCommandInvocation{
		Args: []string{"run", "--cloud", "--detach", "--wait"},
	})
	if result.Err == nil {
		t.Fatal("expected run command error for conflicting flags")
	}
	if !strings.Contains(result.Output, "error_code: invalid_flag_combination") {
		t.Fatalf("captured output missing error code: %s", result.Output)
	}
}

func TestCloudLifecycleCommandRunner_SupportsJSONModeInSameFlow(t *testing.T) {
	h := setupCloudLifecycleIntegrationHarness(t)
	runner := newCloudLifecycleCommandRunner(h)

	runResult := runner.Run(cloudLifecycleCommandInvocation{
		Args: lifecycleCommandArgs(t, "run"),
		JSON: true,
	})
	if runResult.Err != nil {
		t.Fatalf("run command failed: %v", runResult.Err)
	}

	runPayload := make(map[string]interface{})
	if err := json.Unmarshal([]byte(strings.TrimSpace(runResult.Output)), &runPayload); err != nil {
		t.Fatalf("run JSON output is invalid: %v\noutput: %s", err, runResult.Output)
	}
	runID, ok := jsonStringField(runPayload, cloudLifecycleJSONKeyRunID)
	if !ok {
		t.Fatalf("run JSON output missing %q: %v", cloudLifecycleJSONKeyRunID, runPayload)
	}

	statusArgs := lifecycleCommandArgs(t, "status")
	humanStatus := runner.Run(cloudLifecycleCommandInvocation{
		Args:  statusArgs,
		RunID: runID,
	})
	if humanStatus.Err != nil {
		t.Fatalf("human status command failed: %v", humanStatus.Err)
	}
	if !strings.Contains(humanStatus.Output, runID) {
		t.Fatalf("human status output missing run ID %q: %s", runID, humanStatus.Output)
	}

	jsonStatus := runner.Run(cloudLifecycleCommandInvocation{
		Args:  statusArgs,
		RunID: runID,
		JSON:  true,
	})
	if jsonStatus.Err != nil {
		t.Fatalf("json status command failed: %v", jsonStatus.Err)
	}

	statusPayload := make(map[string]interface{})
	if err := json.Unmarshal([]byte(strings.TrimSpace(jsonStatus.Output)), &statusPayload); err != nil {
		t.Fatalf("status JSON output is invalid: %v\noutput: %s", err, jsonStatus.Output)
	}
	statusRunID, ok := jsonStringField(statusPayload, "runId", "run_id")
	if !ok {
		t.Fatalf("status JSON output missing run ID field: %v", statusPayload)
	}
	if statusRunID != runID {
		t.Fatalf("status run ID = %q, want %q", statusRunID, runID)
	}
}

func jsonStringField(payload map[string]interface{}, keys ...string) (string, bool) {
	for _, key := range keys {
		value, ok := payload[key]
		if !ok {
			continue
		}
		str, ok := value.(string)
		if !ok || str == "" {
			return "", false
		}
		return str, true
	}
	return "", false
}
