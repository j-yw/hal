package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/doctor"
	"github.com/jywlabs/hal/internal/template"
)

func TestRunDoctorFn_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	// Create minimal .hal with config
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: pi\n"), 0644)

	var buf bytes.Buffer
	if err := runDoctorFn(dir, true, &buf); err != nil {
		t.Fatalf("runDoctorFn() error = %v", err)
	}

	var result doctor.DoctorResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\noutput: %s", err, buf.String())
	}

	if result.ContractVersion != doctor.ContractVersion {
		t.Fatalf("contractVersion = %d, want %d", result.ContractVersion, doctor.ContractVersion)
	}

	// Should have checks
	if len(result.Checks) == 0 {
		t.Fatal("checks is empty")
	}
}

func TestRunDoctorFn_HumanOutput(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: pi\n"), 0644)

	var buf bytes.Buffer
	if err := runDoctorFn(dir, false, &buf); err != nil {
		t.Fatalf("runDoctorFn() error = %v", err)
	}

	output := buf.String()
	// Should have check symbols
	if !strings.Contains(output, "✓") && !strings.Contains(output, "✗") && !strings.Contains(output, "⚠") && !strings.Contains(output, "−") {
		t.Fatalf("human output missing check symbols:\n%s", output)
	}
}

func TestRunDoctorFn_JSONRequiredFields(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	if err := runDoctorFn(dir, true, &buf); err != nil {
		t.Fatalf("runDoctorFn() error = %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	for _, field := range []string{"contractVersion", "overallStatus", "checks", "failures", "warnings", "summary"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("JSON missing required field %q", field)
		}
	}
}

func TestRunDoctorFn_NoHalDirFails(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	if err := runDoctorFn(dir, true, &buf); err != nil {
		t.Fatalf("runDoctorFn() error = %v", err)
	}

	var result doctor.DoctorResult
	json.Unmarshal(buf.Bytes(), &result)

	if result.OverallStatus != doctor.StatusFail {
		t.Fatalf("overallStatus = %q, want %q", result.OverallStatus, doctor.StatusFail)
	}
}

func TestDoctorCmdHelp(t *testing.T) {
	cmd := doctorCmd

	if cmd.Use != "doctor" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "doctor")
	}
	if cmd.Short == "" {
		t.Fatal("Short is empty")
	}
	if !strings.Contains(cmd.Long, "engine-aware") {
		t.Fatalf("Long missing 'engine-aware': %s", cmd.Long)
	}
	if !strings.Contains(cmd.Example, "hal doctor") {
		t.Fatalf("Example missing 'hal doctor': %s", cmd.Example)
	}
}

func TestDoctorFixFlag(t *testing.T) {
	cmd := doctorCmd
	flag := cmd.Flags().Lookup("fix")
	if flag == nil {
		t.Fatal("doctor command should have --fix flag")
	}
	if flag.DefValue != "false" {
		t.Fatalf("--fix default should be false, got %q", flag.DefValue)
	}
}
