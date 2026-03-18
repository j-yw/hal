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

func setupHealthyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: pi\n"), 0644)
	os.WriteFile(filepath.Join(halDir, template.PromptFile), []byte("# Agent\n"), 0644)
	os.WriteFile(filepath.Join(halDir, template.ProgressFile), []byte("## Patterns\n"), 0644)
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
	return dir
}

func TestRunRepairFn_HealthyRepo(t *testing.T) {
	dir := setupHealthyDir(t)

	var buf bytes.Buffer
	if err := runRepairFn(dir, false, false, &buf); err != nil {
		t.Fatalf("runRepairFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No repairs needed") {
		t.Fatalf("healthy repo should say no repairs needed\n%s", output)
	}
}

func TestRunRepairFn_HealthyJSON(t *testing.T) {
	dir := setupHealthyDir(t)

	var buf bytes.Buffer
	if err := runRepairFn(dir, false, true, &buf); err != nil {
		t.Fatalf("runRepairFn() error = %v", err)
	}

	var result RepairResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if !result.OK {
		t.Fatal("healthy repo should be OK")
	}
}

func TestRunRepairFn_DryRun(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	// No .hal/ — needs init

	var buf bytes.Buffer
	if err := runRepairFn(dir, true, false, &buf); err != nil {
		t.Fatalf("runRepairFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "[dry-run]") {
		t.Fatalf("dry-run output should contain [dry-run]\n%s", output)
	}
	if !strings.Contains(output, "hal init") {
		t.Fatalf("dry-run should suggest hal init\n%s", output)
	}
}

func TestRunRepairFn_DryRunJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	var buf bytes.Buffer
	if err := runRepairFn(dir, true, true, &buf); err != nil {
		t.Fatalf("runRepairFn() error = %v", err)
	}

	var result RepairResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if len(result.Applied) == 0 {
		t.Fatal("should have repair steps even in dry-run")
	}
	for _, a := range result.Applied {
		if a.Status != "skipped" {
			t.Fatalf("dry-run actions should be 'skipped', got %q", a.Status)
		}
	}
}

func TestRepairCmdHelp(t *testing.T) {
	if repairCmd.Use != "repair" {
		t.Fatalf("Use = %q, want %q", repairCmd.Use, "repair")
	}
	if repairCmd.Short == "" {
		t.Fatal("Short is empty")
	}
	if !strings.Contains(repairCmd.Example, "hal repair") {
		t.Fatalf("Example missing 'hal repair': %s", repairCmd.Example)
	}
}

func TestRunRepairFn_FixesUnhealthyRepo(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
	// No .hal/ — repo is unhealthy

	// First, verify it's unhealthy
	var diagBuf bytes.Buffer
	runDoctorFn(dir, true, &diagBuf)
	if !strings.Contains(diagBuf.String(), `"fail"`) {
		t.Fatalf("expected doctor to detect issues before repair")
	}

	// Run repair
	var repairBuf bytes.Buffer
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)
	if err := runRepairFn(dir, false, false, &repairBuf); err != nil {
		t.Fatalf("runRepairFn() error = %v", err)
	}

	output := repairBuf.String()
	if !strings.Contains(output, "✓") || !strings.Contains(output, "hal init") {
		t.Fatalf("repair should apply hal init\n%s", output)
	}

	// Verify it's now healthier (at least .hal/ exists)
	halDir := filepath.Join(dir, template.HalDir)
	if _, err := os.Stat(halDir); os.IsNotExist(err) {
		t.Fatal(".hal/ should exist after repair")
	}
}

func TestRunRepairFn_ReRunsDoctor(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)

	// First run: should apply hal init
	var buf bytes.Buffer
	origDir, _ := os.Getwd()
	os.Chdir(dir)
	defer os.Chdir(origDir)

	if err := runRepairFn(dir, false, true, &buf); err != nil {
		t.Fatalf("runRepairFn() error = %v", err)
	}

	var result RepairResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if len(result.Applied) == 0 {
		t.Fatal("should have applied at least one repair")
	}

	// The re-check should show improvement
	if result.Summary == "" {
		t.Fatal("summary should not be empty")
	}
}

func TestRunRepairFn_HealthyRepoJSON(t *testing.T) {
	dir := setupHealthyDir(t)

	var buf bytes.Buffer
	if err := runRepairFn(dir, false, true, &buf); err != nil {
		t.Fatalf("runRepairFn() error = %v", err)
	}

	var result RepairResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}

	if !result.OK {
		t.Fatal("healthy repo repair should report OK")
	}
	if len(result.Applied) > 0 {
		t.Fatalf("healthy repo should not apply repairs: %+v", result.Applied)
	}
	if !strings.Contains(result.Summary, "No repairs needed") {
		t.Fatalf("summary should say no repairs needed: %q", result.Summary)
	}
}
