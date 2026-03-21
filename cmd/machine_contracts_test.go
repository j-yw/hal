package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/loop"
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

func TestMachineContractFields_SandboxList(t *testing.T) {
	t.Run("required JSON keys", func(t *testing.T) {
		cost := 3.50
		now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
		stopped := now.Add(-time.Hour)

		resp := SandboxListResponse{
			ContractVersion: "sandbox-list-v1",
			Sandboxes: []SandboxListEntry{
				{
					ID:                "0192d4e5-6f78-7abc-def0-123456789abc",
					Name:              "api-backend",
					Provider:          "hetzner",
					Status:            "running",
					CreatedAt:         now,
					WorkspaceID:       "srv-12345",
					IP:                "203.0.113.10",
					TailscaleIP:       "100.64.0.1",
					TailscaleHostname: "hal-api-backend",
					StoppedAt:         &stopped,
					AutoShutdown:      true,
					IdleHours:         48,
					Size:              "cpx21",
					Repo:              "github.com/myorg/api",
					SnapshotID:        "snap-001",
					EstimatedCost:     &cost,
				},
			},
			Totals: SandboxListTotals{
				Total:         1,
				Running:       1,
				Stopped:       0,
				EstimatedCost: &cost,
			},
		}

		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}

		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		// Top-level required fields
		for _, f := range []string{"contractVersion", "sandboxes", "totals"} {
			if _, ok := raw[f]; !ok {
				t.Errorf("sandbox list JSON missing required top-level field %q", f)
			}
		}

		// Sandbox entry required fields
		sandboxes := raw["sandboxes"].([]interface{})
		entry := sandboxes[0].(map[string]interface{})
		for _, f := range []string{"id", "name", "provider", "status", "createdAt"} {
			if _, ok := entry[f]; !ok {
				t.Errorf("sandbox entry JSON missing required field %q", f)
			}
		}

		// Sandbox entry optional fields (present when populated)
		for _, f := range []string{
			"workspaceId", "ip", "tailscaleIp", "tailscaleHostname",
			"stoppedAt", "autoShutdown", "idleHours", "size",
			"repo", "snapshotId", "estimatedCost",
		} {
			if _, ok := entry[f]; !ok {
				t.Errorf("sandbox entry JSON missing optional field %q (should be present when populated)", f)
			}
		}

		// Totals required fields
		totals := raw["totals"].(map[string]interface{})
		for _, f := range []string{"total", "running", "stopped"} {
			if _, ok := totals[f]; !ok {
				t.Errorf("totals JSON missing required field %q", f)
			}
		}

		// Totals optional fields
		if _, ok := totals["estimatedCost"]; !ok {
			t.Error("totals JSON missing optional field \"estimatedCost\" (should be present when populated)")
		}
	})

	t.Run("contract version value", func(t *testing.T) {
		resp := SandboxListResponse{
			ContractVersion: "sandbox-list-v1",
			Sandboxes:       []SandboxListEntry{},
			Totals:          SandboxListTotals{},
		}

		data, _ := json.Marshal(resp)
		var raw map[string]interface{}
		json.Unmarshal(data, &raw)

		if v := raw["contractVersion"]; v != "sandbox-list-v1" {
			t.Fatalf("contractVersion = %v, want \"sandbox-list-v1\"", v)
		}
	})

	t.Run("optional fields omitted when zero", func(t *testing.T) {
		resp := SandboxListResponse{
			ContractVersion: "sandbox-list-v1",
			Sandboxes: []SandboxListEntry{
				{
					ID:        "test-id",
					Name:      "minimal",
					Provider:  "daytona",
					Status:    "running",
					CreatedAt: time.Now(),
				},
			},
			Totals: SandboxListTotals{Total: 1, Running: 1},
		}

		data, _ := json.Marshal(resp)
		var raw map[string]interface{}
		json.Unmarshal(data, &raw)

		entry := raw["sandboxes"].([]interface{})[0].(map[string]interface{})
		omittedFields := []string{
			"workspaceId", "ip", "tailscaleIp", "tailscaleHostname",
			"stoppedAt", "autoShutdown", "idleHours", "size",
			"repo", "snapshotId", "estimatedCost",
		}
		for _, f := range omittedFields {
			if _, ok := entry[f]; ok {
				t.Errorf("field %q should be omitted when zero/nil, but was present", f)
			}
		}

		totals := raw["totals"].(map[string]interface{})
		if _, ok := totals["estimatedCost"]; ok {
			t.Error("totals.estimatedCost should be omitted when nil")
		}
	})

	t.Run("round-trip marshal/unmarshal", func(t *testing.T) {
		cost := 5.40
		totalCost := 5.40
		now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
		stopped := time.Date(2026, 3, 20, 18, 0, 0, 0, time.UTC)

		original := SandboxListResponse{
			ContractVersion: "sandbox-list-v1",
			Sandboxes: []SandboxListEntry{
				{
					ID:                "0192d4e5-6f78-7abc-def0-123456789abc",
					Name:              "api-backend",
					Provider:          "hetzner",
					Status:            "running",
					CreatedAt:         now,
					WorkspaceID:       "srv-12345",
					IP:                "203.0.113.10",
					TailscaleIP:       "100.64.0.1",
					TailscaleHostname: "hal-api-backend",
					StoppedAt:         &stopped,
					AutoShutdown:      true,
					IdleHours:         48,
					Size:              "cpx21",
					Repo:              "github.com/myorg/api",
					SnapshotID:        "snap-001",
					EstimatedCost:     &cost,
				},
				{
					ID:        "0192d4e5-6f78-7abc-def0-123456789abd",
					Name:      "worker",
					Provider:  "daytona",
					Status:    "stopped",
					CreatedAt: now,
				},
			},
			Totals: SandboxListTotals{
				Total:         2,
				Running:       1,
				Stopped:       1,
				EstimatedCost: &totalCost,
			},
		}

		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("marshal error: %v", err)
		}

		var decoded SandboxListResponse
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}

		// Structural equality checks
		if decoded.ContractVersion != original.ContractVersion {
			t.Errorf("ContractVersion = %q, want %q", decoded.ContractVersion, original.ContractVersion)
		}
		if len(decoded.Sandboxes) != len(original.Sandboxes) {
			t.Fatalf("Sandboxes count = %d, want %d", len(decoded.Sandboxes), len(original.Sandboxes))
		}

		// First entry full check
		got := decoded.Sandboxes[0]
		want := original.Sandboxes[0]
		if got.ID != want.ID {
			t.Errorf("Sandboxes[0].ID = %q, want %q", got.ID, want.ID)
		}
		if got.Name != want.Name {
			t.Errorf("Sandboxes[0].Name = %q, want %q", got.Name, want.Name)
		}
		if got.Provider != want.Provider {
			t.Errorf("Sandboxes[0].Provider = %q, want %q", got.Provider, want.Provider)
		}
		if got.Status != want.Status {
			t.Errorf("Sandboxes[0].Status = %q, want %q", got.Status, want.Status)
		}
		if !got.CreatedAt.Equal(want.CreatedAt) {
			t.Errorf("Sandboxes[0].CreatedAt = %v, want %v", got.CreatedAt, want.CreatedAt)
		}
		if got.WorkspaceID != want.WorkspaceID {
			t.Errorf("Sandboxes[0].WorkspaceID = %q, want %q", got.WorkspaceID, want.WorkspaceID)
		}
		if got.IP != want.IP {
			t.Errorf("Sandboxes[0].IP = %q, want %q", got.IP, want.IP)
		}
		if got.TailscaleIP != want.TailscaleIP {
			t.Errorf("Sandboxes[0].TailscaleIP = %q, want %q", got.TailscaleIP, want.TailscaleIP)
		}
		if got.TailscaleHostname != want.TailscaleHostname {
			t.Errorf("Sandboxes[0].TailscaleHostname = %q, want %q", got.TailscaleHostname, want.TailscaleHostname)
		}
		if got.AutoShutdown != want.AutoShutdown {
			t.Errorf("Sandboxes[0].AutoShutdown = %v, want %v", got.AutoShutdown, want.AutoShutdown)
		}
		if got.IdleHours != want.IdleHours {
			t.Errorf("Sandboxes[0].IdleHours = %d, want %d", got.IdleHours, want.IdleHours)
		}
		if got.Size != want.Size {
			t.Errorf("Sandboxes[0].Size = %q, want %q", got.Size, want.Size)
		}
		if got.Repo != want.Repo {
			t.Errorf("Sandboxes[0].Repo = %q, want %q", got.Repo, want.Repo)
		}
		if got.SnapshotID != want.SnapshotID {
			t.Errorf("Sandboxes[0].SnapshotID = %q, want %q", got.SnapshotID, want.SnapshotID)
		}
		if got.EstimatedCost == nil || want.EstimatedCost == nil {
			t.Fatal("Sandboxes[0].EstimatedCost should not be nil")
		}
		if *got.EstimatedCost != *want.EstimatedCost {
			t.Errorf("Sandboxes[0].EstimatedCost = %f, want %f", *got.EstimatedCost, *want.EstimatedCost)
		}
		if got.StoppedAt == nil || want.StoppedAt == nil {
			t.Fatal("Sandboxes[0].StoppedAt should not be nil")
		}
		if !got.StoppedAt.Equal(*want.StoppedAt) {
			t.Errorf("Sandboxes[0].StoppedAt = %v, want %v", *got.StoppedAt, *want.StoppedAt)
		}

		// Second entry minimal check
		got2 := decoded.Sandboxes[1]
		if got2.Name != "worker" {
			t.Errorf("Sandboxes[1].Name = %q, want %q", got2.Name, "worker")
		}
		if got2.EstimatedCost != nil {
			t.Error("Sandboxes[1].EstimatedCost should be nil for minimal entry")
		}

		// Totals check
		if decoded.Totals.Total != original.Totals.Total {
			t.Errorf("Totals.Total = %d, want %d", decoded.Totals.Total, original.Totals.Total)
		}
		if decoded.Totals.Running != original.Totals.Running {
			t.Errorf("Totals.Running = %d, want %d", decoded.Totals.Running, original.Totals.Running)
		}
		if decoded.Totals.Stopped != original.Totals.Stopped {
			t.Errorf("Totals.Stopped = %d, want %d", decoded.Totals.Stopped, original.Totals.Stopped)
		}
		if decoded.Totals.EstimatedCost == nil || *decoded.Totals.EstimatedCost != *original.Totals.EstimatedCost {
			t.Errorf("Totals.EstimatedCost mismatch")
		}
	})
}

func TestNextActionFieldsConsistent(t *testing.T) {
	// Verify that nextAction fields in various commands use consistent ID values
	// that match the status contract's action IDs
	validActionIDs := map[string]bool{
		"run_init":    true,
		"run_plan":    true,
		"run_convert": true,
		"run_manual":  true,
		"run_report":  true,
		"run_auto":    true,
		"resume_auto": true,
	}

	// Test RunResult nextActions
	tests := []struct {
		name   string
		result loop.Result
	}{
		{"complete", loop.Result{Success: true, Complete: true, Iterations: 1}},
		{"in_progress", loop.Result{Success: true, Complete: false, Iterations: 5}},
		{"failed", loop.Result{Success: false, Iterations: 3, Error: fmt.Errorf("test")}},
	}

	for _, tt := range tests {
		t.Run("run_"+tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := outputRunJSON(&buf, tt.result, "", false); err != nil {
				t.Fatalf("outputRunJSON error: %v", err)
			}
			var jr RunResult
			json.Unmarshal(buf.Bytes(), &jr)
			if jr.NextAction == nil {
				t.Fatal("nextAction should not be nil")
			}
			if !validActionIDs[jr.NextAction.ID] {
				t.Fatalf("nextAction.id %q is not a recognized action ID", jr.NextAction.ID)
			}
		})
	}
}
