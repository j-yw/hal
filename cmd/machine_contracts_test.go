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
