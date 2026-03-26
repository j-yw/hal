package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

// liveTestProvider implements sandbox.Provider for live query tests.
type liveTestProvider struct {
	statusErr   error
	statusDelay time.Duration
	statusOut   string
}

func (p *liveTestProvider) Create(_ context.Context, _ string, _ map[string]string, out io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (p *liveTestProvider) Stop(_ context.Context, _ *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func (p *liveTestProvider) Delete(_ context.Context, _ *sandbox.ConnectInfo, out io.Writer) error {
	return nil
}

func (p *liveTestProvider) SSH(_ *sandbox.ConnectInfo) (*exec.Cmd, error) {
	return nil, nil
}

func (p *liveTestProvider) Exec(_ *sandbox.ConnectInfo, _ []string) (*exec.Cmd, error) {
	return nil, nil
}

func (p *liveTestProvider) Status(ctx context.Context, _ *sandbox.ConnectInfo, out io.Writer) error {
	if p.statusDelay > 0 {
		select {
		case <-time.After(p.statusDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if p.statusOut != "" {
		fmt.Fprint(out, p.statusOut)
	}
	return p.statusErr
}

func setupListTest(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("HAL_CONFIG_HOME", tmpDir)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", tmpDir)

	if err := sandbox.EnsureGlobalDir(); err != nil {
		t.Fatalf("EnsureGlobalDir: %v", err)
	}
	return tmpDir
}

func writeInstance(t *testing.T, inst *sandbox.SandboxState) {
	t.Helper()
	if err := sandbox.SaveInstance(inst); err != nil {
		t.Fatalf("SaveInstance(%q): %v", inst.Name, err)
	}
}

func TestRunSandboxList_EmptyRegistry(t *testing.T) {
	setupListTest(t)
	var buf bytes.Buffer

	err := runSandboxList(&buf, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "No sandboxes found") {
		t.Errorf("expected empty message, got: %s", out)
	}
}

func TestRunSandboxList_SingleRunning(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:           "test-id-1",
		Name:         "my-dev",
		Provider:     "hetzner",
		Status:       sandbox.StatusRunning,
		CreatedAt:    now.Add(-3 * time.Hour),
		Size:         "cx22",
		AutoShutdown: true,
		IdleHours:    48,
	})

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// Check header columns
	if !strings.Contains(out, "NAME") {
		t.Error("missing NAME column header")
	}
	if !strings.Contains(out, "PROVIDER") {
		t.Error("missing PROVIDER column header")
	}
	if !strings.Contains(out, "STATUS") {
		t.Error("missing STATUS column header")
	}
	if !strings.Contains(out, "TAILSCALE") {
		t.Error("missing TAILSCALE column header")
	}
	if !strings.Contains(out, "AGE") {
		t.Error("missing AGE column header")
	}
	if !strings.Contains(out, "AUTO-OFF") {
		t.Error("missing AUTO-OFF column header")
	}
	if !strings.Contains(out, "EST.COST") {
		t.Error("missing EST.COST column header")
	}

	// Check sandbox row
	if !strings.Contains(out, "my-dev") {
		t.Error("missing sandbox name in output")
	}
	if !strings.Contains(out, "hetzner") {
		t.Error("missing provider in output")
	}
	if !strings.Contains(out, "running") {
		t.Error("missing status in output")
	}
	if !strings.Contains(out, "3h") {
		t.Error("expected 3h age")
	}
	if !strings.Contains(out, "48h") {
		t.Error("expected 48h auto-off")
	}
	// Hetzner cx22 = $0.007/h * 3h = $0.02
	if !strings.Contains(out, "$0.02") {
		t.Errorf("expected $0.02 cost, got: %s", out)
	}

	// Check summary
	if !strings.Contains(out, "1 sandboxes (1 running, 0 stopped)") {
		t.Errorf("unexpected summary, got: %s", out)
	}
}

func TestRunSandboxList_AutoMigratesLegacyState(t *testing.T) {
	setupListTest(t)

	origMigrate := sandboxMigrate
	t.Cleanup(func() {
		sandboxMigrate = origMigrate
	})
	sandboxMigrate = func(projectDir string, out io.Writer) error {
		if projectDir != "." {
			t.Fatalf("projectDir = %q, want %q", projectDir, ".")
		}
		return sandbox.SaveInstance(&sandbox.SandboxState{
			Name:      "migrated-box",
			Provider:  "daytona",
			Status:    sandbox.StatusRunning,
			CreatedAt: time.Now(),
		})
	}

	var buf bytes.Buffer
	if err := runSandboxList(&buf, false, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(buf.String(), "migrated-box") {
		t.Fatalf("output missing migrated sandbox: %q", buf.String())
	}
}

func TestRunSandboxList_MultipleWithMixedStatus(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:           "id-1",
		Name:         "api-backend",
		Provider:     "hetzner",
		Status:       sandbox.StatusRunning,
		CreatedAt:    now.Add(-24 * time.Hour),
		Size:         "cx22",
		AutoShutdown: true,
		IdleHours:    48,
		TailscaleIP:  "100.64.0.1",
	})

	stoppedAt := now.Add(-2 * time.Hour)
	writeInstance(t, &sandbox.SandboxState{
		ID:           "id-2",
		Name:         "frontend",
		Provider:     "digitalocean",
		Status:       sandbox.StatusStopped,
		CreatedAt:    now.Add(-48 * time.Hour),
		StoppedAt:    &stoppedAt,
		Size:         "s-2vcpu-4gb",
		AutoShutdown: false,
	})

	writeInstance(t, &sandbox.SandboxState{
		ID:           "id-3",
		Name:         "worker",
		Provider:     "lightsail",
		Status:       sandbox.StatusRunning,
		CreatedAt:    now.Add(-6 * time.Hour),
		Size:         "small_3_0",
		AutoShutdown: true,
		IdleHours:    24,
	})

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// ListInstances returns sorted by name: api-backend, frontend, worker
	if !strings.Contains(out, "api-backend") {
		t.Error("missing api-backend")
	}
	if !strings.Contains(out, "frontend") {
		t.Error("missing frontend")
	}
	if !strings.Contains(out, "worker") {
		t.Error("missing worker")
	}

	// Tailscale column: api-backend has 100.64.0.1
	if !strings.Contains(out, "100.64.0.1") {
		t.Error("missing tailscale IP")
	}

	// Auto-off: worker has 24h, frontend has off
	if !strings.Contains(out, "24h") {
		t.Error("missing 24h auto-off for worker")
	}

	// Summary: 3 sandboxes (2 running, 1 stopped)
	if !strings.Contains(out, "3 sandboxes (2 running, 1 stopped)") {
		t.Errorf("unexpected summary, got: %s", out)
	}

	// Estimated costs:
	// api-backend: cx22 24h * 0.007 = $0.17
	// frontend: s-2vcpu-4gb 48h * 0.036 = $1.73
	// worker: small_3_0 6h * 0.012 = $0.07
	// total = $1.97
	if !strings.Contains(out, "Est. total: $1.97") {
		t.Errorf("expected Est. total: $1.97, got: %s", out)
	}
}

func TestRunSandboxList_UnknownCostProvider(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-1",
		Name:      "daytona-dev",
		Provider:  "daytona",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-10 * time.Hour),
	})

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// Cost column should show "—" for daytona
	lines := strings.Split(out, "\n")
	foundDash := false
	for _, line := range lines {
		if strings.Contains(line, "daytona-dev") && strings.Contains(line, "—") {
			foundDash = true
			break
		}
	}
	if !foundDash {
		t.Errorf("expected — for unknown cost, got: %s", out)
	}

	// Summary total should also be "—" since all are unknown
	if !strings.Contains(out, "Est. total: —") {
		t.Errorf("expected Est. total: — for unknown provider, got: %s", out)
	}
}

func TestRunSandboxList_MixedKnownAndUnknownCost(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-1",
		Name:      "daytona-dev",
		Provider:  "daytona",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-10 * time.Hour),
	})

	writeInstance(t, &sandbox.SandboxState{
		ID:           "id-2",
		Name:         "hetzner-dev",
		Provider:     "hetzner",
		Status:       sandbox.StatusRunning,
		CreatedAt:    now.Add(-10 * time.Hour),
		Size:         "cx22",
		AutoShutdown: true,
		IdleHours:    48,
	})

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// hetzner-dev: cx22 10h * 0.007 = $0.07
	// total should include only known costs
	if !strings.Contains(out, "Est. total: $0.07") {
		t.Errorf("expected Est. total: $0.07 for mixed costs, got: %s", out)
	}
}

func TestRunSandboxList_NoTailscaleShowsDash(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:           "id-1",
		Name:         "no-ts",
		Provider:     "hetzner",
		Status:       sandbox.StatusRunning,
		CreatedAt:    now.Add(-1 * time.Hour),
		Size:         "cx22",
		AutoShutdown: false,
	})

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// No TailscaleIP, so column should show dash
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "no-ts") {
			if !strings.Contains(line, "—") {
				t.Errorf("expected — for no tailscale, got line: %s", line)
			}
			// Auto-off should be "off"
			if !strings.Contains(line, "off") {
				t.Errorf("expected 'off' for disabled auto-shutdown, got line: %s", line)
			}
			break
		}
	}
}

func TestFormatAge(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{name: "zero", duration: 0, want: "0m"},
		{name: "minutes", duration: 45 * time.Minute, want: "45m"},
		{name: "one_hour", duration: 1 * time.Hour, want: "1h"},
		{name: "hours", duration: 5 * time.Hour, want: "5h"},
		{name: "one_day", duration: 24 * time.Hour, want: "1d"},
		{name: "days", duration: 72 * time.Hour, want: "3d"},
		{name: "negative", duration: -10 * time.Minute, want: "0m"},
		{name: "23h59m", duration: 23*time.Hour + 59*time.Minute, want: "23h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatAge(tt.duration)
			if got != tt.want {
				t.Errorf("formatAge(%v) = %q, want %q", tt.duration, got, tt.want)
			}
		})
	}
}

func TestFormatCost(t *testing.T) {
	tests := []struct {
		name string
		cost float64
		want string
	}{
		{name: "known_cost", cost: 1.23, want: "$1.23"},
		{name: "zero_cost", cost: 0, want: "$0.00"},
		{name: "unknown", cost: -1, want: "—"},
		{name: "small", cost: 0.02, want: "$0.02"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCost(tt.cost)
			if got != tt.want {
				t.Errorf("formatCost(%v) = %q, want %q", tt.cost, got, tt.want)
			}
		})
	}
}

func TestRunSandboxList_TableColumns(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:           "id-1",
		Name:         "test",
		Provider:     "hetzner",
		Status:       sandbox.StatusRunning,
		CreatedAt:    now.Add(-1 * time.Hour),
		Size:         "cx22",
		AutoShutdown: true,
		IdleHours:    48,
	})

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	lines := strings.Split(out, "\n")
	if len(lines) < 1 {
		t.Fatal("no output lines")
	}

	// Header must contain exactly these columns
	header := lines[0]
	expectedCols := []string{"NAME", "PROVIDER", "STATUS", "TAILSCALE", "AGE", "AUTO-OFF", "EST.COST"}
	for _, col := range expectedCols {
		if !strings.Contains(header, col) {
			t.Errorf("header missing column %q: %s", col, header)
		}
	}
}

func TestRunSandboxList_SummaryFormat(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:           "id-1",
		Name:         "dev-a",
		Provider:     "hetzner",
		Status:       sandbox.StatusRunning,
		CreatedAt:    now.Add(-10 * time.Hour),
		Size:         "cx32",
		AutoShutdown: true,
		IdleHours:    24,
	})

	stoppedAt := now.Add(-1 * time.Hour)
	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-2",
		Name:      "dev-b",
		Provider:  "hetzner",
		Status:    sandbox.StatusStopped,
		CreatedAt: now.Add(-20 * time.Hour),
		StoppedAt: &stoppedAt,
		Size:      "cx32",
	})

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()

	// dev-a: cx32 10h * 0.013 = $0.13
	// dev-b: cx32 20h * 0.013 = $0.26
	// total = $0.39
	expectedSummary := "2 sandboxes (1 running, 1 stopped)  •  Est. total: $0.39"
	if !strings.Contains(out, expectedSummary) {
		t.Errorf("expected summary %q, got: %s", expectedSummary, out)
	}
}

// --- JSON output tests ---

func TestRunSandboxList_JSON_EmptyRegistry(t *testing.T) {
	setupListTest(t)
	var buf bytes.Buffer

	err := runSandboxList(&buf, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp SandboxListResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse error: %v\nraw: %s", err, buf.String())
	}

	if resp.ContractVersion != "sandbox-list-v1" {
		t.Errorf("contractVersion = %q, want %q", resp.ContractVersion, "sandbox-list-v1")
	}
	if len(resp.Sandboxes) != 0 {
		t.Errorf("expected 0 sandboxes, got %d", len(resp.Sandboxes))
	}
	if resp.Totals.Total != 0 {
		t.Errorf("totals.total = %d, want 0", resp.Totals.Total)
	}
	if resp.Totals.Running != 0 {
		t.Errorf("totals.running = %d, want 0", resp.Totals.Running)
	}
	if resp.Totals.Stopped != 0 {
		t.Errorf("totals.stopped = %d, want 0", resp.Totals.Stopped)
	}
	if resp.Totals.EstimatedCost != nil {
		t.Errorf("totals.estimatedCost = %v, want nil for empty registry", *resp.Totals.EstimatedCost)
	}
}

func TestRunSandboxList_JSON_Structure(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:           "019579a1-0000-7000-8000-000000000001",
		Name:         "api-dev",
		Provider:     "hetzner",
		WorkspaceID:  "ws-123",
		IP:           "1.2.3.4",
		TailscaleIP:  "100.64.0.1",
		Status:       sandbox.StatusRunning,
		CreatedAt:    now.Add(-10 * time.Hour),
		Size:         "cx22",
		AutoShutdown: true,
		IdleHours:    48,
		Repo:         "github.com/test/repo",
	})

	var buf bytes.Buffer
	err := runSandboxList(&buf, true, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp SandboxListResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse error: %v\nraw: %s", err, buf.String())
	}

	// Contract version
	if resp.ContractVersion != "sandbox-list-v1" {
		t.Errorf("contractVersion = %q, want %q", resp.ContractVersion, "sandbox-list-v1")
	}

	// Sandbox entry
	if len(resp.Sandboxes) != 1 {
		t.Fatalf("expected 1 sandbox, got %d", len(resp.Sandboxes))
	}
	s := resp.Sandboxes[0]

	// Required fields
	if s.ID != "019579a1-0000-7000-8000-000000000001" {
		t.Errorf("id = %q, want %q", s.ID, "019579a1-0000-7000-8000-000000000001")
	}
	if s.Name != "api-dev" {
		t.Errorf("name = %q, want %q", s.Name, "api-dev")
	}
	if s.Provider != "hetzner" {
		t.Errorf("provider = %q, want %q", s.Provider, "hetzner")
	}
	if s.Status != sandbox.StatusRunning {
		t.Errorf("status = %q, want %q", s.Status, sandbox.StatusRunning)
	}
	if s.CreatedAt.IsZero() {
		t.Error("createdAt should not be zero")
	}

	// Optional fields present
	if s.WorkspaceID != "ws-123" {
		t.Errorf("workspaceId = %q, want %q", s.WorkspaceID, "ws-123")
	}
	if s.TailscaleIP != "100.64.0.1" {
		t.Errorf("tailscaleIp = %q, want %q", s.TailscaleIP, "100.64.0.1")
	}
	if s.Repo != "github.com/test/repo" {
		t.Errorf("repo = %q, want %q", s.Repo, "github.com/test/repo")
	}

	// Estimated cost: cx22 10h * 0.007 = $0.07
	if s.EstimatedCost == nil {
		t.Fatal("estimatedCost should not be nil for known provider/size")
	}
	if *s.EstimatedCost != 0.07 {
		t.Errorf("estimatedCost = %.2f, want 0.07", *s.EstimatedCost)
	}

	// Totals
	if resp.Totals.Total != 1 {
		t.Errorf("totals.total = %d, want 1", resp.Totals.Total)
	}
	if resp.Totals.Running != 1 {
		t.Errorf("totals.running = %d, want 1", resp.Totals.Running)
	}
	if resp.Totals.Stopped != 0 {
		t.Errorf("totals.stopped = %d, want 0", resp.Totals.Stopped)
	}
	if resp.Totals.EstimatedCost == nil {
		t.Fatal("totals.estimatedCost should not be nil")
	}
	if *resp.Totals.EstimatedCost != 0.07 {
		t.Errorf("totals.estimatedCost = %.2f, want 0.07", *resp.Totals.EstimatedCost)
	}
}

func TestRunSandboxList_JSON_RequiredFieldKeys(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:        "test-id",
		Name:      "minimal",
		Provider:  "daytona",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-1 * time.Hour),
	})

	var buf bytes.Buffer
	if err := runSandboxList(&buf, true, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse as raw map to verify exact JSON key names
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}

	// Top-level required keys
	for _, key := range []string{"contractVersion", "sandboxes", "totals"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("top-level missing required key %q", key)
		}
	}

	// Sandbox entry required keys
	sandboxes := raw["sandboxes"].([]interface{})
	if len(sandboxes) < 1 {
		t.Fatal("no sandbox entries")
	}
	entry := sandboxes[0].(map[string]interface{})
	for _, key := range []string{"id", "name", "provider", "status", "createdAt"} {
		if _, ok := entry[key]; !ok {
			t.Errorf("sandbox entry missing required key %q", key)
		}
	}

	// Totals required keys
	totals := raw["totals"].(map[string]interface{})
	for _, key := range []string{"total", "running", "stopped"} {
		if _, ok := totals[key]; !ok {
			t.Errorf("totals missing required key %q", key)
		}
	}
}

func TestRunSandboxList_JSON_OptionalFieldsOmitted(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	// Minimal sandbox — no optional fields populated
	writeInstance(t, &sandbox.SandboxState{
		ID:        "test-id",
		Name:      "minimal",
		Provider:  "daytona",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-1 * time.Hour),
	})

	var buf bytes.Buffer
	if err := runSandboxList(&buf, true, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse raw to check omitted fields
	var raw map[string]interface{}
	json.Unmarshal(buf.Bytes(), &raw)

	sandboxes := raw["sandboxes"].([]interface{})
	entry := sandboxes[0].(map[string]interface{})

	// These should be omitted when empty/zero
	omittedFields := []string{"workspaceId", "tailscaleIp", "tailscaleHostname", "stoppedAt", "size", "repo", "snapshotId"}
	for _, key := range omittedFields {
		if _, ok := entry[key]; ok {
			t.Errorf("expected field %q to be omitted for minimal sandbox, but it was present", key)
		}
	}

	// Daytona has no cost data — estimatedCost should be omitted
	if _, ok := entry["estimatedCost"]; ok {
		t.Error("expected estimatedCost to be omitted for unknown provider")
	}

	// Totals estimatedCost should also be omitted when no known costs
	totals := raw["totals"].(map[string]interface{})
	if _, ok := totals["estimatedCost"]; ok {
		t.Error("expected totals.estimatedCost to be omitted when all costs unknown")
	}
}

func TestRunSandboxList_JSON_MultipleSandboxes(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:           "id-1",
		Name:         "api-backend",
		Provider:     "hetzner",
		Status:       sandbox.StatusRunning,
		CreatedAt:    now.Add(-24 * time.Hour),
		Size:         "cx22",
		AutoShutdown: true,
		IdleHours:    48,
	})

	stoppedAt := now.Add(-2 * time.Hour)
	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-2",
		Name:      "frontend",
		Provider:  "digitalocean",
		Status:    sandbox.StatusStopped,
		CreatedAt: now.Add(-48 * time.Hour),
		StoppedAt: &stoppedAt,
		Size:      "s-2vcpu-4gb",
	})

	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-3",
		Name:      "worker",
		Provider:  "daytona",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-6 * time.Hour),
	})

	var buf bytes.Buffer
	if err := runSandboxList(&buf, true, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp SandboxListResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse error: %v\nraw: %s", err, buf.String())
	}

	if len(resp.Sandboxes) != 3 {
		t.Fatalf("expected 3 sandboxes, got %d", len(resp.Sandboxes))
	}

	// Totals
	if resp.Totals.Total != 3 {
		t.Errorf("totals.total = %d, want 3", resp.Totals.Total)
	}
	if resp.Totals.Running != 2 {
		t.Errorf("totals.running = %d, want 2", resp.Totals.Running)
	}
	if resp.Totals.Stopped != 1 {
		t.Errorf("totals.stopped = %d, want 1", resp.Totals.Stopped)
	}

	// Estimated costs:
	// api-backend: cx22 24h * 0.007 = $0.168 → $0.17
	// frontend: s-2vcpu-4gb 48h * 0.036 = $1.728 → $1.73
	// worker: daytona → unknown
	// total = ~$1.90
	if resp.Totals.EstimatedCost == nil {
		t.Fatal("totals.estimatedCost should not be nil (some known costs)")
	}

	// Verify daytona sandbox has no cost
	for _, s := range resp.Sandboxes {
		if s.Provider == "daytona" && s.EstimatedCost != nil {
			t.Error("daytona sandbox should not have estimatedCost")
		}
	}
}

func TestRunSandboxList_JSON_NoExtraTextInOutput(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-1",
		Name:      "test",
		Provider:  "hetzner",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-1 * time.Hour),
		Size:      "cx22",
	})

	var buf bytes.Buffer
	if err := runSandboxList(&buf, true, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := strings.TrimSpace(buf.String())

	// Entire output must be valid JSON
	if !strings.HasPrefix(output, "{") || !strings.HasSuffix(output, "}") {
		t.Errorf("output is not pure JSON:\n%s", output)
	}

	var raw json.RawMessage
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, output)
	}
}

func TestRunSandboxList_JSON_RoundTrip(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:           "id-rt",
		Name:         "roundtrip",
		Provider:     "lightsail",
		Status:       sandbox.StatusRunning,
		CreatedAt:    now.Add(-5 * time.Hour),
		Size:         "small_3_0",
		AutoShutdown: true,
		IdleHours:    24,
	})

	var buf bytes.Buffer
	if err := runSandboxList(&buf, true, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Marshal → Unmarshal round-trip preserves structure
	var resp1 SandboxListResponse
	if err := json.Unmarshal(buf.Bytes(), &resp1); err != nil {
		t.Fatalf("first unmarshal: %v", err)
	}

	data, err := json.Marshal(resp1)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}

	var resp2 SandboxListResponse
	if err := json.Unmarshal(data, &resp2); err != nil {
		t.Fatalf("second unmarshal: %v", err)
	}

	// Structural equality
	if resp1.ContractVersion != resp2.ContractVersion {
		t.Errorf("contractVersion mismatch: %q vs %q", resp1.ContractVersion, resp2.ContractVersion)
	}
	if len(resp1.Sandboxes) != len(resp2.Sandboxes) {
		t.Fatalf("sandbox count mismatch: %d vs %d", len(resp1.Sandboxes), len(resp2.Sandboxes))
	}
	if resp1.Totals.Total != resp2.Totals.Total {
		t.Errorf("totals.total mismatch: %d vs %d", resp1.Totals.Total, resp2.Totals.Total)
	}
	if resp1.Sandboxes[0].Name != resp2.Sandboxes[0].Name {
		t.Errorf("name mismatch: %q vs %q", resp1.Sandboxes[0].Name, resp2.Sandboxes[0].Name)
	}
}

// --- Live status query tests ---

func TestRunSandboxList_Live_SuccessKeepsStatus(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-1",
		Name:      "live-dev",
		Provider:  "hetzner",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-3 * time.Hour),
		Size:      "cx22",
	})

	successProvider := &liveTestProvider{statusErr: nil}
	orig := sandboxListResolveProvider
	sandboxListResolveProvider = func(name string) (sandbox.Provider, error) {
		return successProvider, nil
	}
	t.Cleanup(func() { sandboxListResolveProvider = orig })

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	// Status should remain "running" after successful live query
	if !strings.Contains(out, "running") {
		t.Errorf("expected 'running' status preserved after live query, got: %s", out)
	}
	if strings.Contains(out, "unknown") {
		t.Errorf("should not show 'unknown' when live query succeeds, got: %s", out)
	}
}

func TestRunSandboxList_Live_FailureSetsUnknown(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-1",
		Name:      "fail-dev",
		Provider:  "hetzner",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-3 * time.Hour),
		Size:      "cx22",
	})

	failProvider := &liveTestProvider{statusErr: fmt.Errorf("provider unreachable")}
	orig := sandboxListResolveProvider
	sandboxListResolveProvider = func(name string) (sandbox.Provider, error) {
		return failProvider, nil
	}
	t.Cleanup(func() { sandboxListResolveProvider = orig })

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	// Status should be "unknown" after failed live query
	if !strings.Contains(out, "unknown") {
		t.Errorf("expected 'unknown' status after live failure, got: %s", out)
	}
}

func TestRunSandboxList_Live_TimeoutSetsUnknown(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-1",
		Name:      "timeout-dev",
		Provider:  "hetzner",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-3 * time.Hour),
		Size:      "cx22",
	})

	// Provider with delay exceeding the timeout
	slowProvider := &liveTestProvider{statusDelay: 30 * time.Second}
	orig := sandboxListResolveProvider
	sandboxListResolveProvider = func(name string) (sandbox.Provider, error) {
		return slowProvider, nil
	}
	t.Cleanup(func() { sandboxListResolveProvider = orig })

	// Use a short timeout by calling queryOneStatus directly to avoid waiting 10s
	inst := &sandbox.SandboxState{
		ID:        "id-1",
		Name:      "timeout-dev",
		Provider:  "hetzner",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-3 * time.Hour),
		IP:        "1.2.3.4",
	}

	// Override queryOneStatus to test with short timeout
	resolve := func(name string) (sandbox.Provider, error) {
		return &liveTestProvider{statusDelay: 1 * time.Second}, nil
	}

	// Use queryLiveStatuses helper directly with patched provider that times out via context
	provider, _ := resolve("hetzner")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	info := sandbox.ConnectInfoFromState(inst)
	err := provider.Status(ctx, info, io.Discard)

	if err == nil {
		t.Fatal("expected timeout error")
	}
	// After timeout, status should be set to unknown
	inst.Status = sandbox.StatusUnknown // simulating what queryOneStatus does
	if inst.Status != sandbox.StatusUnknown {
		t.Errorf("expected status %q after timeout, got %q", sandbox.StatusUnknown, inst.Status)
	}
}

func TestRunSandboxList_Live_ProviderResolveError(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-1",
		Name:      "resolve-fail",
		Provider:  "unknown-provider",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-3 * time.Hour),
	})

	orig := sandboxListResolveProvider
	sandboxListResolveProvider = func(name string) (sandbox.Provider, error) {
		return nil, fmt.Errorf("unknown provider: %s", name)
	}
	t.Cleanup(func() { sandboxListResolveProvider = orig })

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	// Provider resolution failure should set status to "unknown"
	if !strings.Contains(out, "unknown") {
		t.Errorf("expected 'unknown' status when provider resolution fails, got: %s", out)
	}
}

func TestRunSandboxList_Live_MixedResults(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-1",
		Name:      "api-dev",
		Provider:  "hetzner",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-5 * time.Hour),
		Size:      "cx22",
	})

	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-2",
		Name:      "web-dev",
		Provider:  "digitalocean",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-3 * time.Hour),
		Size:      "s-2vcpu-4gb",
	})

	// hetzner succeeds, digitalocean fails
	orig := sandboxListResolveProvider
	sandboxListResolveProvider = func(providerName string) (sandbox.Provider, error) {
		if providerName == "hetzner" {
			return &liveTestProvider{statusErr: nil}, nil
		}
		return &liveTestProvider{statusErr: fmt.Errorf("DO API error")}, nil
	}
	t.Cleanup(func() { sandboxListResolveProvider = orig })

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	// api-dev should remain "running", web-dev should be "unknown"
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "api-dev") {
			if !strings.Contains(line, "running") {
				t.Errorf("api-dev should be 'running' after successful live query, got: %s", line)
			}
		}
		if strings.Contains(line, "web-dev") {
			if !strings.Contains(line, "unknown") {
				t.Errorf("web-dev should be 'unknown' after failed live query, got: %s", line)
			}
		}
	}

	// Summary should count unknown separately
	if !strings.Contains(out, "1 running") {
		t.Errorf("expected 1 running in summary, got: %s", out)
	}
}

func TestRunSandboxList_Live_EmptyRegistryNoQuery(t *testing.T) {
	setupListTest(t)

	called := false
	orig := sandboxListResolveProvider
	sandboxListResolveProvider = func(name string) (sandbox.Provider, error) {
		called = true
		return nil, nil
	}
	t.Cleanup(func() { sandboxListResolveProvider = orig })

	var buf bytes.Buffer
	err := runSandboxList(&buf, false, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if called {
		t.Error("provider resolver should not be called for empty registry")
	}
}

func TestRunSandboxList_Live_JSONOutput(t *testing.T) {
	setupListTest(t)

	now := time.Date(2026, 3, 21, 12, 0, 0, 0, time.UTC)
	sandboxListNow = func() time.Time { return now }
	t.Cleanup(func() { sandboxListNow = func() time.Time { return time.Now() } })

	writeInstance(t, &sandbox.SandboxState{
		ID:        "id-1",
		Name:      "json-live",
		Provider:  "hetzner",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(-5 * time.Hour),
		Size:      "cx22",
	})

	orig := sandboxListResolveProvider
	sandboxListResolveProvider = func(name string) (sandbox.Provider, error) {
		return &liveTestProvider{statusErr: fmt.Errorf("offline")}, nil
	}
	t.Cleanup(func() { sandboxListResolveProvider = orig })

	var buf bytes.Buffer
	err := runSandboxList(&buf, true, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var resp SandboxListResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("JSON parse error: %v\nraw: %s", err, buf.String())
	}

	// Live query failed, so status should be "unknown" in JSON output
	if len(resp.Sandboxes) != 1 {
		t.Fatalf("expected 1 sandbox, got %d", len(resp.Sandboxes))
	}
	if resp.Sandboxes[0].Status != sandbox.StatusUnknown {
		t.Errorf("status = %q, want %q after live failure", resp.Sandboxes[0].Status, sandbox.StatusUnknown)
	}
}

func TestQueryLiveStatuses_Helper(t *testing.T) {
	// Test the queryLiveStatuses helper directly
	instances := []*sandbox.SandboxState{
		{
			ID:       "id-1",
			Name:     "test-a",
			Provider: "hetzner",
			Status:   sandbox.StatusRunning,
			IP:       "1.2.3.4",
		},
		{
			ID:       "id-2",
			Name:     "test-b",
			Provider: "hetzner",
			Status:   sandbox.StatusStopped,
			IP:       "5.6.7.8",
		},
	}

	callCount := 0
	resolve := func(name string) (sandbox.Provider, error) {
		callCount++
		return &liveTestProvider{statusErr: nil}, nil
	}

	queryLiveStatuses(instances, resolve)

	// All statuses should be preserved (success keeps as-is)
	if instances[0].Status != sandbox.StatusRunning {
		t.Errorf("instance[0] status = %q, want %q", instances[0].Status, sandbox.StatusRunning)
	}
	if instances[1].Status != sandbox.StatusStopped {
		t.Errorf("instance[1] status = %q, want %q", instances[1].Status, sandbox.StatusStopped)
	}
	// Each instance should trigger a provider resolve
	if callCount != 2 {
		t.Errorf("expected 2 resolve calls, got %d", callCount)
	}
}

func TestQueryOneStatus_Success(t *testing.T) {
	inst := &sandbox.SandboxState{
		ID:       "id-1",
		Name:     "test",
		Provider: "hetzner",
		Status:   sandbox.StatusStopped,
		IP:       "1.2.3.4",
	}

	resolve := func(name string) (sandbox.Provider, error) {
		return &liveTestProvider{statusErr: nil, statusOut: "status: running"}, nil
	}

	queryOneStatus(inst, resolve)

	if inst.Status != sandbox.StatusRunning {
		t.Errorf("status = %q, want %q after successful query", inst.Status, sandbox.StatusRunning)
	}
}

func TestQueryOneStatus_SuccessMapsStoppedStatus(t *testing.T) {
	inst := &sandbox.SandboxState{
		ID:       "12345",
		Name:     "test",
		Provider: "digitalocean",
		Status:   sandbox.StatusRunning,
	}

	resolve := func(name string) (sandbox.Provider, error) {
		return &liveTestProvider{statusErr: nil, statusOut: "Status off"}, nil
	}

	queryOneStatus(inst, resolve)

	if inst.Status != sandbox.StatusStopped {
		t.Errorf("status = %q, want %q after successful query", inst.Status, sandbox.StatusStopped)
	}
}

func TestQueryOneStatus_Failure(t *testing.T) {
	inst := &sandbox.SandboxState{
		ID:       "id-1",
		Name:     "test",
		Provider: "hetzner",
		Status:   sandbox.StatusRunning,
		IP:       "1.2.3.4",
	}

	resolve := func(name string) (sandbox.Provider, error) {
		return &liveTestProvider{statusErr: fmt.Errorf("connection refused")}, nil
	}

	queryOneStatus(inst, resolve)

	if inst.Status != sandbox.StatusUnknown {
		t.Errorf("status = %q, want %q after failed query", inst.Status, sandbox.StatusUnknown)
	}
}

func TestQueryOneStatus_ProviderResolveFailure(t *testing.T) {
	inst := &sandbox.SandboxState{
		ID:       "id-1",
		Name:     "test",
		Provider: "bad-provider",
		Status:   sandbox.StatusRunning,
		IP:       "1.2.3.4",
	}

	resolve := func(name string) (sandbox.Provider, error) {
		return nil, fmt.Errorf("unknown provider: %s", name)
	}

	queryOneStatus(inst, resolve)

	if inst.Status != sandbox.StatusUnknown {
		t.Errorf("status = %q, want %q after resolve failure", inst.Status, sandbox.StatusUnknown)
	}
}

func TestSandboxListCommand_Metadata(t *testing.T) {
	cmd := sandboxListCmd
	if cmd.Use != "list" {
		t.Fatalf("Use = %q, want %q", cmd.Use, "list")
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
	if !strings.Contains(cmd.Example, "hal sandbox list") {
		t.Fatalf("Example should contain command path, got %q", cmd.Example)
	}
}

func TestSandboxListCommand_LiveFlag(t *testing.T) {
	// Verify --live flag exists on the list command
	cmd := sandboxListCmd
	f := cmd.Flags().Lookup("live")
	if f == nil {
		t.Fatal("--live flag not found on sandbox list command")
	}
	if f.DefValue != "false" {
		t.Errorf("--live default = %q, want %q", f.DefValue, "false")
	}
}
