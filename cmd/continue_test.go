package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
)

func TestRunContinueFn_HealthyRepo(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: pi\n"), 0644)

	// Install skills and commands
	skillsDir := filepath.Join(halDir, "skills")
	for _, name := range skills.ManagedSkillNames {
		os.MkdirAll(filepath.Join(skillsDir, name), 0755)
		os.WriteFile(filepath.Join(skillsDir, name, "SKILL.md"), []byte("# "+name), 0644)
	}
	commandsDir := filepath.Join(halDir, template.CommandsDir)
	os.MkdirAll(commandsDir, 0755)
	for _, name := range skills.CommandNames {
		os.WriteFile(filepath.Join(commandsDir, name+".md"), []byte("# "+name), 0644)
	}

	var buf bytes.Buffer
	if err := runContinueFn(dir, false, &buf); err != nil {
		t.Fatalf("runContinueFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Next:") {
		t.Fatalf("healthy output should contain 'Next:'\n%s", output)
	}
	if strings.Contains(output, "Fix:") {
		t.Fatalf("healthy output should not contain 'Fix:'\n%s", output)
	}
}

func TestRunContinueFn_UnhealthyRepo(t *testing.T) {
	dir := t.TempDir()
	// No .hal dir — doctor will fail

	var buf bytes.Buffer
	if err := runContinueFn(dir, false, &buf); err != nil {
		t.Fatalf("runContinueFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Fix:") {
		t.Fatalf("unhealthy output should contain 'Fix:'\n%s", output)
	}
	if !strings.Contains(output, "hal init") {
		t.Fatalf("unhealthy output should recommend 'hal init'\n%s", output)
	}
}

func TestRunContinueFn_JSONOutput(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	if err := runContinueFn(dir, true, &buf); err != nil {
		t.Fatalf("runContinueFn() error = %v", err)
	}

	var result ContinueResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\noutput: %s", err, buf.String())
	}

	if result.ContractVersion != 1 {
		t.Fatalf("contractVersion = %d, want 1", result.ContractVersion)
	}
	if result.NextCommand == "" {
		t.Fatal("nextCommand should not be empty")
	}
	if result.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestContinueCmdHelp(t *testing.T) {
	cmd := continueCmd

	if cmd.Use != "continue" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "continue")
	}
	if cmd.Short == "" {
		t.Fatal("Short is empty")
	}
	if !strings.Contains(cmd.Example, "hal continue") {
		t.Fatalf("Example missing 'hal continue': %s", cmd.Example)
	}
}
