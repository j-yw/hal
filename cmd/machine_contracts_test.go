package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
)

// TestMachineContractFields locks the required field names for all machine-readable
// JSON contracts. If a field name changes, this test catches the regression so
// downstream consumers don't silently break.
func TestMachineContractFields(t *testing.T) {
	// Not parallel: some sub-tests share global command tree state

	t.Run("status contract v1 fields", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, template.HalDir)
		os.MkdirAll(halDir, 0755)

		prd := map[string]interface{}{
			"branchName": "hal/test",
			"stories": []map[string]interface{}{
				{"id": "US-001", "title": "Story", "status": "pending"},
			},
		}
		data, _ := json.Marshal(prd)
		os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)

		var buf bytes.Buffer
		if err := runStatusFn(dir, true, &buf); err != nil {
			t.Fatalf("runStatusFn error: %v", err)
		}

		var raw map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
			t.Fatalf("JSON parse error: %v", err)
		}

		// v1 required fields
		requiredFields := []string{
			"contractVersion", "workflowTrack", "state",
			"artifacts", "nextAction", "summary",
		}
		for _, f := range requiredFields {
			if _, ok := raw[f]; !ok {
				t.Errorf("status JSON missing required field %q", f)
			}
		}

		// Check manual detail when present
		if manual, ok := raw["manual"]; ok {
			m := manual.(map[string]interface{})
			for _, f := range []string{"totalStories", "completedStories"} {
				if _, ok := m[f]; !ok {
					t.Errorf("status.manual missing field %q", f)
				}
			}
		}
	})

	t.Run("doctor contract v1 fields", func(t *testing.T) {
		dir := t.TempDir()

		var buf bytes.Buffer
		if err := runDoctorFn(dir, true, &buf); err != nil {
			t.Fatalf("runDoctorFn error: %v", err)
		}

		var raw map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
			t.Fatalf("JSON parse error: %v", err)
		}

		requiredFields := []string{
			"contractVersion", "overallStatus", "checks",
			"failures", "warnings", "summary",
		}
		for _, f := range requiredFields {
			if _, ok := raw[f]; !ok {
				t.Errorf("doctor JSON missing required field %q", f)
			}
		}
	})

	t.Run("continue contract fields", func(t *testing.T) {
		dir := t.TempDir()

		var buf bytes.Buffer
		if err := runContinueFn(dir, true, &buf); err != nil {
			t.Fatalf("runContinueFn error: %v", err)
		}

		var raw map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
			t.Fatalf("JSON parse error: %v", err)
		}

		requiredFields := []string{
			"contractVersion", "ready", "status", "doctor",
			"nextCommand", "nextDescription", "summary",
		}
		for _, f := range requiredFields {
			if _, ok := raw[f]; !ok {
				t.Errorf("continue JSON missing required field %q", f)
			}
		}
	})

	t.Run("status contract version is 1", func(t *testing.T) {
		dir := t.TempDir()
		os.MkdirAll(filepath.Join(dir, template.HalDir), 0755)

		var buf bytes.Buffer
		runStatusFn(dir, true, &buf)

		var raw map[string]interface{}
		json.Unmarshal(buf.Bytes(), &raw)

		if v, ok := raw["contractVersion"].(float64); !ok || int(v) != 1 {
			t.Fatalf("contractVersion = %v, want 1", raw["contractVersion"])
		}
	})

	t.Run("doctor contract version is 1", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, template.HalDir)
		os.MkdirAll(filepath.Join(dir, ".git"), 0755)
		os.MkdirAll(halDir, 0755)
		os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: pi\n"), 0644)
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
		runDoctorFn(dir, true, &buf)

		var raw map[string]interface{}
		json.Unmarshal(buf.Bytes(), &raw)

		if v, ok := raw["contractVersion"].(float64); !ok || int(v) != 1 {
			t.Fatalf("contractVersion = %v, want 1", raw["contractVersion"])
		}
	})
}

func TestMachineContractFields_StatusDetail(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	prd := map[string]interface{}{
		"branchName": "hal/feature",
		"stories": []map[string]interface{}{
			{"id": "US-001", "title": "First", "status": "passed"},
			{"id": "US-002", "title": "Second", "status": "pending"},
		},
	}
	data, _ := json.Marshal(prd)
	os.WriteFile(filepath.Join(halDir, template.PRDFile), data, 0644)

	var buf bytes.Buffer
	if err := runStatusFn(dir, true, &buf); err != nil {
		t.Fatalf("runStatusFn error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	// Check manual detail
	manual, ok := raw["manual"].(map[string]interface{})
	if !ok {
		t.Fatal("manual detail missing from in-progress status")
	}

	// Verify key fields exist and have correct types
	if _, ok := manual["totalStories"].(float64); !ok {
		t.Fatal("manual.totalStories should be a number")
	}
	if _, ok := manual["completedStories"].(float64); !ok {
		t.Fatal("manual.completedStories should be a number")
	}

	// Verify nextStory
	nextStory, ok := manual["nextStory"].(map[string]interface{})
	if !ok {
		t.Fatal("manual.nextStory should be present for in-progress workflow")
	}
	if _, ok := nextStory["id"].(string); !ok {
		t.Fatal("manual.nextStory.id should be a string")
	}

	// Verify paths
	paths, ok := raw["paths"].(map[string]interface{})
	if !ok {
		t.Fatal("paths should be present")
	}
	if _, ok := paths["prdJson"].(string); !ok {
		t.Fatal("paths.prdJson should be a string")
	}
}

func TestMachineContractFields_DoctorChecksHaveScopeAndApplicability(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(filepath.Join(dir, ".git"), 0755)
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

	var buf bytes.Buffer
	if err := runDoctorFn(dir, true, &buf); err != nil {
		t.Fatalf("runDoctorFn error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	checks, ok := raw["checks"].([]interface{})
	if !ok {
		t.Fatal("checks should be an array")
	}

	for _, c := range checks {
		check, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		id := check["id"].(string)

		scope, hasScope := check["scope"].(string)
		applicability, hasApplicability := check["applicability"].(string)

		if !hasScope || scope == "" {
			t.Errorf("check %q missing scope", id)
		}
		if !hasApplicability || applicability == "" {
			t.Errorf("check %q missing applicability", id)
		}
	}
}

func TestMachineContractFields_Repair(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	var buf bytes.Buffer
	if err := runRepairFn(dir, true, true, &buf); err != nil {
		t.Fatalf("runRepairFn error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("JSON parse error: %v\n%s", err, buf.String())
	}

	for _, field := range []string{"contractVersion", "ok", "summary"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("repair JSON missing field %q", field)
		}
	}
}

func TestMachineContractFields_LinksStatus(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, template.HalDir, "skills"), 0755)

	var buf bytes.Buffer
	if err := runLinksStatusFn(dir, true, "", &buf); err != nil {
		t.Fatalf("runLinksStatusFn error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("JSON parse error: %v\n%s", err, buf.String())
	}

	for _, field := range []string{"contractVersion", "engines", "summary"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("links status JSON missing field %q", field)
		}
	}
}

func TestMachineContractFields_PRDAudit(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)

	var buf bytes.Buffer
	if err := runPRDAuditFn(dir, true, &buf); err != nil {
		t.Fatalf("runPRDAuditFn error: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("JSON parse error: %v\n%s", err, buf.String())
	}

	for _, field := range []string{"contractVersion", "ok", "jsonExists", "markdownExists", "summary"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("prd audit JSON missing field %q", field)
		}
	}
}
