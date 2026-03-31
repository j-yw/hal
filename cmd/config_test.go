package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestRunConfigShowFn_MissingConfigUsesDefaults(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	if err := runConfigShowFn(dir, &buf); err != nil {
		t.Fatalf("runConfigShowFn() error = %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, ".hal/config.yaml") {
		t.Fatalf("output should mention config path, got %q", out)
	}
	if !strings.Contains(out, "using defaults") {
		t.Fatalf("output should mention defaults, got %q", out)
	}
	if !strings.Contains(out, "Default settings:") {
		t.Fatalf("output should include defaults heading, got %q", out)
	}
	if !strings.Contains(out, "sourcePriority: report_first") {
		t.Fatalf("defaults should include auto source priority, got %q", out)
	}
	if !strings.Contains(out, "convertMode: auto") {
		t.Fatalf("defaults should include auto convert mode policy, got %q", out)
	}
	if !strings.Contains(out, "mode: balanced") {
		t.Fatalf("defaults should include auto policy mode, got %q", out)
	}
}

func TestRunConfigShowFn_ExistingConfig(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	cfg := "engine: pi\nauto:\n  mode: strict\n"
	if err := os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var buf bytes.Buffer
	if err := runConfigShowFn(dir, &buf); err != nil {
		t.Fatalf("runConfigShowFn() error = %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Configuration") {
		t.Fatalf("output should include title, got %q", out)
	}
	if !strings.Contains(out, "Path:") || !strings.Contains(out, ".hal/config.yaml") {
		t.Fatalf("output should include config path, got %q", out)
	}
	if !strings.Contains(out, "engine: pi") {
		t.Fatalf("output should include config content, got %q", out)
	}
}

func TestRunConfigJSONFn_MissingConfig(t *testing.T) {
	dir := t.TempDir()

	var buf bytes.Buffer
	if err := runConfigJSONFn(dir, &buf); err != nil {
		t.Fatalf("runConfigJSONFn() error = %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}
	if exists, ok := payload["exists"].(bool); !ok || exists {
		t.Fatalf("exists = %#v, want false", payload["exists"])
	}
}

func TestRunConfigJSONFn_ExistingConfig(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	cfg := "engine: codex\n"
	if err := os.WriteFile(filepath.Join(halDir, template.ConfigFile), []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var buf bytes.Buffer
	if err := runConfigJSONFn(dir, &buf); err != nil {
		t.Fatalf("runConfigJSONFn() error = %v", err)
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal JSON: %v", err)
	}

	exists, ok := payload["exists"].(bool)
	if !ok || !exists {
		t.Fatalf("exists = %#v, want true", payload["exists"])
	}
	if got := payload["path"]; got != ".hal/config.yaml" {
		t.Fatalf("path = %#v, want %q", got, ".hal/config.yaml")
	}
	if got := payload["content"]; got != cfg {
		t.Fatalf("content = %#v, want %q", got, cfg)
	}
}
