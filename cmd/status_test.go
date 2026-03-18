package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/status"
	"github.com/jywlabs/hal/internal/template"
)

func TestRunStatusFn_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	var buf bytes.Buffer
	if err := runStatusFn(dir, true, &buf); err != nil {
		t.Fatalf("runStatusFn() error = %v", err)
	}

	var result status.StatusResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\noutput: %s", err, buf.String())
	}

	if result.ContractVersion != status.ContractVersion {
		t.Fatalf("contractVersion = %d, want %d", result.ContractVersion, status.ContractVersion)
	}
	if result.State != status.StateInitializedNoPRD {
		t.Fatalf("state = %q, want %q", result.State, status.StateInitializedNoPRD)
	}
}

func TestRunStatusFn_HumanOutput(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	var buf bytes.Buffer
	if err := runStatusFn(dir, false, &buf); err != nil {
		t.Fatalf("runStatusFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Workflow:") {
		t.Fatalf("human output missing 'Workflow:'\n%s", output)
	}
	if !strings.Contains(output, "State:") {
		t.Fatalf("human output missing 'State:'\n%s", output)
	}
	if !strings.Contains(output, "Next:") {
		t.Fatalf("human output missing 'Next:'\n%s", output)
	}
}

func TestRunStatusFn_JSONStdoutOnly(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	if err := runStatusFn(dir, true, &buf); err != nil {
		t.Fatalf("runStatusFn() error = %v", err)
	}

	// JSON should be valid and parseable
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("JSON output is not valid: %v\n%s", err, buf.String())
	}

	// Required fields
	for _, field := range []string{"contractVersion", "workflowTrack", "state", "artifacts", "nextAction", "summary"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("JSON missing required field %q", field)
		}
	}
}

func TestStatusCmdHelp(t *testing.T) {
	cmd := statusCmd

	if cmd.Use != "status" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "status")
	}
	if cmd.Short == "" {
		t.Fatal("Short is empty")
	}
	if cmd.Long == "" {
		t.Fatal("Long is empty")
	}
	if cmd.Example == "" {
		t.Fatal("Example is empty")
	}
	if !strings.Contains(cmd.Example, "hal status") {
		t.Fatalf("Example missing 'hal status': %s", cmd.Example)
	}
}
