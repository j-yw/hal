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

func TestRunLinksStatusFn_JSONOutput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	halDir := filepath.Join(dir, template.HalDir)
	skillsDir := filepath.Join(halDir, "skills")
	os.MkdirAll(skillsDir, 0755)
	for _, name := range skills.ManagedSkillNames {
		os.MkdirAll(filepath.Join(skillsDir, name), 0755)
	}

	var buf bytes.Buffer
	if err := runLinksStatusFn(dir, true, &buf); err != nil {
		t.Fatalf("runLinksStatusFn() error = %v", err)
	}

	var result LinksResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\noutput: %s", err, buf.String())
	}

	if result.ContractVersion != 1 {
		t.Fatalf("contractVersion = %d, want 1", result.ContractVersion)
	}
	if len(result.Engines) == 0 {
		t.Fatal("engines should not be empty")
	}

	// Check that all 3 engines are listed
	engineNames := map[string]bool{}
	for _, es := range result.Engines {
		engineNames[es.Engine] = true
	}
	for _, name := range []string{"claude", "pi", "codex"} {
		if !engineNames[name] {
			t.Errorf("missing engine %q", name)
		}
	}
}

func TestRunLinksStatusFn_HumanOutput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(filepath.Join(halDir, "skills"), 0755)

	var buf bytes.Buffer
	if err := runLinksStatusFn(dir, false, &buf); err != nil {
		t.Fatalf("runLinksStatusFn() error = %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "claude") {
		t.Fatalf("human output should mention claude\n%s", output)
	}
	if !strings.Contains(output, "codex") {
		t.Fatalf("human output should mention codex\n%s", output)
	}
}

func TestRunLinksStatusFn_DetectsMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(filepath.Join(halDir, "skills"), 0755)
	// Create engine dirs but no links
	os.MkdirAll(filepath.Join(dir, ".claude", "skills"), 0755)

	var buf bytes.Buffer
	if err := runLinksStatusFn(dir, true, &buf); err != nil {
		t.Fatalf("runLinksStatusFn() error = %v", err)
	}

	var result LinksResult
	json.Unmarshal(buf.Bytes(), &result)

	// Claude should have missing links
	for _, es := range result.Engines {
		if es.Engine == "claude" {
			if es.Status != "warn" {
				t.Fatalf("claude status = %q, want %q (missing links)", es.Status, "warn")
			}
			return
		}
	}
	t.Fatal("claude engine not found")
}

func TestLinksCmdHelp(t *testing.T) {
	if linksCmd.Use != "links" {
		t.Fatalf("Use = %q, want %q", linksCmd.Use, "links")
	}
	if linksStatusCmd.Short == "" {
		t.Fatal("links status Short is empty")
	}
	if !strings.Contains(linksStatusCmd.Example, "hal links status") {
		t.Fatalf("links status Example missing 'hal links status': %s", linksStatusCmd.Example)
	}
	if !strings.Contains(linksRefreshCmd.Example, "hal links refresh") {
		t.Fatalf("links refresh Example missing 'hal links refresh': %s", linksRefreshCmd.Example)
	}
}

func TestRunLinksStatusFn_DetectsBroken(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(filepath.Join(halDir, "skills"), 0755)

	// Create engine dir with broken symlink
	claudeSkills := filepath.Join(dir, ".claude", "skills")
	os.MkdirAll(claudeSkills, 0755)
	os.Symlink("/nonexistent/target", filepath.Join(claudeSkills, "prd"))

	var buf bytes.Buffer
	if err := runLinksStatusFn(dir, true, &buf); err != nil {
		t.Fatalf("runLinksStatusFn() error = %v", err)
	}

	var result LinksResult
	json.Unmarshal(buf.Bytes(), &result)

	for _, es := range result.Engines {
		if es.Engine == "claude" {
			if es.Status != "warn" {
				t.Fatalf("claude status = %q, want %q (broken link)", es.Status, "warn")
			}
			// Check detail for broken link
			for _, link := range es.Links {
				if link.Name == "prd" && link.Status != "broken" {
					t.Fatalf("prd link status = %q, want %q", link.Status, "broken")
				}
			}
			return
		}
	}
	t.Fatal("claude engine not found")
}
