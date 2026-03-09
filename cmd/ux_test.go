package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

func TestResolveEngine(t *testing.T) {
	t.Run("explicit engine short-circuits config parse", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, template.HalDir)
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("mkdir hal dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte(":::invalid-yaml"), 0644); err != nil {
			t.Fatalf("write config: %v", err)
		}

		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("engine", "codex", "")
		if err := cmd.Flags().Set("engine", "Pi"); err != nil {
			t.Fatalf("set engine flag: %v", err)
		}

		got, err := resolveEngine(cmd, "engine", "codex", dir)
		if err != nil {
			t.Fatalf("resolveEngine() unexpected error: %v", err)
		}
		if got != "pi" {
			t.Fatalf("engine = %q, want %q", got, "pi")
		}
	})

	t.Run("explicit empty engine rejected", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("engine", "codex", "")
		if err := cmd.Flags().Set("engine", "   "); err != nil {
			t.Fatalf("set engine flag: %v", err)
		}

		_, err := resolveEngine(cmd, "engine", "codex", t.TempDir())
		if err == nil {
			t.Fatal("expected error for empty explicit engine, got nil")
		}
		if !strings.Contains(err.Error(), "--engine must not be empty") {
			t.Fatalf("error = %q, want --engine message", err.Error())
		}
	})

	t.Run("config engine fallback", func(t *testing.T) {
		dir := t.TempDir()
		halDir := filepath.Join(dir, template.HalDir)
		if err := os.MkdirAll(halDir, 0755); err != nil {
			t.Fatalf("mkdir hal dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte("engine: claude\n"), 0644); err != nil {
			t.Fatalf("write config: %v", err)
		}

		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("engine", "codex", "")

		got, err := resolveEngine(cmd, "engine", "codex", dir)
		if err != nil {
			t.Fatalf("resolveEngine() unexpected error: %v", err)
		}
		if got != "claude" {
			t.Fatalf("engine = %q, want %q", got, "claude")
		}
	})

	t.Run("final fallback codex", func(t *testing.T) {
		cmd := &cobra.Command{Use: "test"}
		cmd.Flags().String("engine", "codex", "")

		got, err := resolveEngine(cmd, "engine", "codex", t.TempDir())
		if err != nil {
			t.Fatalf("resolveEngine() unexpected error: %v", err)
		}
		if got != "codex" {
			t.Fatalf("engine = %q, want %q", got, "codex")
		}
	})
}

func TestParseIterations(t *testing.T) {
	tests := []struct {
		name        string
		positional  []string
		flagValue   int
		flagChanged bool
		defaultVal  int
		want        int
		wantErr     string
	}{
		{name: "default", defaultVal: 10, want: 10},
		{name: "positional", positional: []string{"3"}, defaultVal: 10, want: 3},
		{name: "flag", flagValue: 5, flagChanged: true, defaultVal: 10, want: 5},
		{name: "conflict", positional: []string{"3"}, flagValue: 5, flagChanged: true, defaultVal: 10, wantErr: "both positionally"},
		{name: "non-numeric", positional: []string{"x"}, defaultVal: 10, wantErr: "must be a number"},
		{name: "zero", positional: []string{"0"}, defaultVal: 10, wantErr: "positive integer"},
		{name: "negative flag", flagValue: -1, flagChanged: true, defaultVal: 10, wantErr: "positive integer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIterations(tt.positional, tt.flagValue, tt.flagChanged, tt.defaultVal)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("iterations = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestValidateFormat(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr string
	}{
		{name: "valid and normalized", input: " JSON ", want: "json"},
		{name: "invalid", input: "xml", wantErr: "invalid format"},
		{name: "empty", input: "  ", wantErr: "must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateFormat(tt.input, "text", "json")
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("format = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestWarnDeprecated(t *testing.T) {
	var buf bytes.Buffer
	warnDeprecated(&buf, "use --format instead")
	output := buf.String()
	if !strings.Contains(output, "deprecated in v0.2.0") {
		t.Fatalf("warning = %q, missing introduced version", output)
	}
	if !strings.Contains(output, "removed in v1.0.0") {
		t.Fatalf("warning = %q, missing removal version", output)
	}
}
