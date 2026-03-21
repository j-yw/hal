package cmd

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

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

	err := runSandboxList(&buf)
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
	err := runSandboxList(&buf)
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
	err := runSandboxList(&buf)
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
	err := runSandboxList(&buf)
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
	err := runSandboxList(&buf)
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
	err := runSandboxList(&buf)
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
	err := runSandboxList(&buf)
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
	err := runSandboxList(&buf)
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
