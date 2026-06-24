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
	setIsolatedCodexHomeFallback(t, dir)
	halDir := filepath.Join(dir, template.HalDir)
	skillsDir := filepath.Join(halDir, "skills")
	os.MkdirAll(skillsDir, 0755)
	for _, name := range skills.ManagedSkillNames {
		os.MkdirAll(filepath.Join(skillsDir, name), 0755)
	}

	var buf bytes.Buffer
	if err := runLinksStatusFn(dir, true, "", &buf); err != nil {
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
	setIsolatedCodexHomeFallback(t, dir)
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(filepath.Join(halDir, "skills"), 0755)

	var buf bytes.Buffer
	if err := runLinksStatusFn(dir, false, "", &buf); err != nil {
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
	setIsolatedCodexHomeFallback(t, dir)
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(filepath.Join(halDir, "skills"), 0755)
	// Create engine dirs but no links
	os.MkdirAll(filepath.Join(dir, ".claude", "skills"), 0755)

	var buf bytes.Buffer
	if err := runLinksStatusFn(dir, true, "", &buf); err != nil {
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
	setIsolatedCodexHomeFallback(t, dir)
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(filepath.Join(halDir, "skills"), 0755)

	// Create engine dir with broken symlink
	claudeSkills := filepath.Join(dir, ".claude", "skills")
	os.MkdirAll(claudeSkills, 0755)
	os.Symlink("/nonexistent/target", filepath.Join(claudeSkills, "prd"))

	var buf bytes.Buffer
	if err := runLinksStatusFn(dir, true, "", &buf); err != nil {
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

func TestRunLinksClean_RemovesDeprecated(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(origDir) })
	os.Chdir(dir)

	// Create deprecated ralph link
	claudeSkills := filepath.Join(dir, ".claude", "skills")
	os.MkdirAll(claudeSkills, 0755)
	os.Symlink("../../.hal/skills/hal", filepath.Join(claudeSkills, "ralph"))

	var buf bytes.Buffer
	cmd := linksCleanCmd
	cmd.SetOut(&buf)
	if err := runLinksClean(cmd, nil); err != nil {
		t.Fatalf("runLinksClean() error = %v", err)
	}

	if _, err := os.Lstat(filepath.Join(claudeSkills, "ralph")); !os.IsNotExist(err) {
		t.Fatal("ralph link should be removed")
	}

	if !strings.Contains(buf.String(), "ralph") {
		t.Fatalf("output should mention ralph\n%s", buf.String())
	}
}

func TestRunLinksClean_NothingToClean(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(origDir) })
	os.Chdir(dir)

	var buf bytes.Buffer
	cmd := linksCleanCmd
	cmd.SetOut(&buf)
	if err := runLinksClean(cmd, nil); err != nil {
		t.Fatalf("runLinksClean() error = %v", err)
	}

	if !strings.Contains(buf.String(), "No deprecated") {
		t.Fatalf("output should say nothing to clean\n%s", buf.String())
	}
}

func TestRunLinksRefresh_CreatesLinks(t *testing.T) {
	dir := t.TempDir()
	setIsolatedCodexHomeFallback(t, dir)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(origDir) })
	os.Chdir(dir)

	// Create .hal/skills with content
	halDir := filepath.Join(dir, template.HalDir)
	skillsDir := filepath.Join(halDir, "skills")
	for _, name := range skills.ManagedSkillNames {
		os.MkdirAll(filepath.Join(skillsDir, name), 0755)
		os.WriteFile(filepath.Join(skillsDir, name, "SKILL.md"), []byte("# "+name), 0644)
	}

	var buf bytes.Buffer
	cmd := linksRefreshCmd
	cmd.SetOut(&buf)
	if err := runLinksRefresh(cmd, nil); err != nil {
		t.Fatalf("runLinksRefresh() error = %v", err)
	}

	if !strings.Contains(buf.String(), "Refreshed") {
		t.Fatalf("output should say Refreshed\n%s", buf.String())
	}

	// Verify Claude links were created
	for _, name := range skills.ManagedSkillNames {
		linkPath := filepath.Join(dir, ".claude", "skills", name)
		info, err := os.Lstat(linkPath)
		if err != nil {
			// Some links might not be created if directory doesn't exist — that's OK
			continue
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Errorf(".claude/skills/%s should be a symlink", name)
		}
	}
}

func TestRunLinksRefresh_SpecificEngine(t *testing.T) {
	dir := t.TempDir()
	setIsolatedCodexHomeFallback(t, dir)

	origDir, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(origDir) })
	os.Chdir(dir)

	halDir := filepath.Join(dir, template.HalDir)
	skillsDir := filepath.Join(halDir, "skills")
	for _, name := range skills.ManagedSkillNames {
		os.MkdirAll(filepath.Join(skillsDir, name), 0755)
	}

	var buf bytes.Buffer
	cmd := linksRefreshCmd
	cmd.SetOut(&buf)
	if err := runLinksRefresh(cmd, []string{"pi"}); err != nil {
		t.Fatalf("runLinksRefresh(pi) error = %v", err)
	}

	if !strings.Contains(buf.String(), "pi") {
		t.Fatalf("output should mention pi\n%s", buf.String())
	}
}

func TestRunLinksRefreshFn_CodexIsolatesActiveHomesAcrossProjects(t *testing.T) {
	home := t.TempDir()
	setIsolatedCodexHomeFallback(t, home)

	projectA := newLinksRefreshProject(t)
	projectB := newLinksRefreshProject(t)
	codexHomeA := t.TempDir()
	codexHomeB := t.TempDir()

	t.Setenv("CODEX_HOME", codexHomeA)
	var outA bytes.Buffer
	if err := runLinksRefreshFn(projectA, []string{"codex"}, &outA); err != nil {
		t.Fatalf("runLinksRefreshFn(projectA, codex) error = %v", err)
	}
	if !strings.Contains(outA.String(), "codex") {
		t.Fatalf("output should mention codex\n%s", outA.String())
	}

	assertCodexRefreshTargets(t, codexHomeA, projectA)
	assertMissingLink(t, filepath.Join(codexHomeB, "skills", "prd"))
	assertMissingLink(t, filepath.Join(codexHomeB, "commands", "hal"))
	targetsBeforeB := snapshotCodexTargets(t, codexHomeA)

	t.Setenv("CODEX_HOME", codexHomeB)
	var outB bytes.Buffer
	if err := runLinksRefreshFn(projectB, []string{"codex"}, &outB); err != nil {
		t.Fatalf("runLinksRefreshFn(projectB, codex) error = %v", err)
	}
	if !strings.Contains(outB.String(), "codex") {
		t.Fatalf("output should mention codex\n%s", outB.String())
	}

	assertCodexRefreshTargets(t, codexHomeB, projectB)
	targetsAfterB := snapshotCodexTargets(t, codexHomeA)
	if !sameStringMap(targetsBeforeB, targetsAfterB) {
		t.Fatalf("refreshing projectB mutated Codex home A\nbefore: %#v\nafter: %#v", targetsBeforeB, targetsAfterB)
	}
}

func TestRunLinksStatusFn_CodexUsesActiveCodexHome(t *testing.T) {
	home := t.TempDir()
	projectDir := newLinksRefreshProject(t)
	codexHomeA := t.TempDir()
	codexHomeB := t.TempDir()
	setIsolatedCodexHomeFallback(t, home)

	t.Setenv("CODEX_HOME", codexHomeA)
	var refreshOut bytes.Buffer
	if err := runLinksRefreshFn(projectDir, []string{"codex"}, &refreshOut); err != nil {
		t.Fatalf("runLinksRefreshFn(projectDir, codex) error = %v", err)
	}

	statusA := runLinksStatusForEngine(t, projectDir, "codex")
	if statusA.Status != "pass" {
		t.Fatalf("codex status with CODEX_HOME A = %q, want pass; issues=%v", statusA.Status, statusA.Issues)
	}
	if statusA.SkillsDir != filepath.Join(codexHomeA, "skills") {
		t.Fatalf("codex skillsDir with CODEX_HOME A = %q, want %q", statusA.SkillsDir, filepath.Join(codexHomeA, "skills"))
	}
	if statusA.CommandsDir != filepath.Join(codexHomeA, "commands", "hal") {
		t.Fatalf("codex commandsDir with CODEX_HOME A = %q, want %q", statusA.CommandsDir, filepath.Join(codexHomeA, "commands", "hal"))
	}

	t.Setenv("CODEX_HOME", codexHomeB)
	statusB := runLinksStatusForEngine(t, projectDir, "codex")
	if statusB.Status != "warn" {
		t.Fatalf("codex status with empty CODEX_HOME B = %q, want warn", statusB.Status)
	}
	if statusB.SkillsDir != filepath.Join(codexHomeB, "skills") {
		t.Fatalf("codex skillsDir with CODEX_HOME B = %q, want %q", statusB.SkillsDir, filepath.Join(codexHomeB, "skills"))
	}
	for _, link := range statusB.Links {
		if strings.HasPrefix(link.Link, codexHomeA) {
			t.Fatalf("status under CODEX_HOME B reported link from CODEX_HOME A: %#v", link)
		}
		if !strings.HasPrefix(link.Link, filepath.Join(codexHomeB, "skills")) {
			t.Fatalf("status under CODEX_HOME B reported link outside CODEX_HOME B: %#v", link)
		}
	}
}

func TestRunLinksStatusFn_CodexDetectsOtherProjectTargets(t *testing.T) {
	home := t.TempDir()
	projectA := newLinksRefreshProject(t)
	projectB := newLinksRefreshProject(t)
	codexHome := t.TempDir()
	setIsolatedCodexHomeFallback(t, home)
	t.Setenv("CODEX_HOME", codexHome)

	var refreshOut bytes.Buffer
	if err := runLinksRefreshFn(projectB, []string{"codex"}, &refreshOut); err != nil {
		t.Fatalf("runLinksRefreshFn(projectB, codex) error = %v", err)
	}

	status := runLinksStatusForEngine(t, projectA, "codex")
	if status.Status != "warn" {
		t.Fatalf("codex status with links to another project = %q, want warn", status.Status)
	}
	for _, link := range status.Links {
		if link.Status != "stale" {
			t.Fatalf("link %s status = %q, want stale", link.Name, link.Status)
		}
	}
	if len(status.Issues) == 0 || !strings.Contains(status.Issues[0], "not this project") {
		t.Fatalf("issues = %v, want not-this-project warning", status.Issues)
	}
}

func TestRunLinksStatusFn_CodexDetectsMissingCommandLink(t *testing.T) {
	home := t.TempDir()
	projectDir := newLinksRefreshProject(t)
	codexHome := t.TempDir()
	setIsolatedCodexHomeFallback(t, home)
	t.Setenv("CODEX_HOME", codexHome)

	var refreshOut bytes.Buffer
	if err := runLinksRefreshFn(projectDir, []string{"codex"}, &refreshOut); err != nil {
		t.Fatalf("runLinksRefreshFn(projectDir, codex) error = %v", err)
	}
	if err := os.Remove(filepath.Join(codexHome, "commands", "hal")); err != nil {
		t.Fatalf("remove codex command link: %v", err)
	}

	status := runLinksStatusForEngine(t, projectDir, "codex")
	if status.Status != "warn" {
		t.Fatalf("codex status with missing command link = %q, want warn", status.Status)
	}
	if !containsIssue(status.Issues, "commands link missing") {
		t.Fatalf("issues = %v, want missing commands warning", status.Issues)
	}
}

func TestRunLinksStatusFn_CodexUsesHomeFallback(t *testing.T) {
	home := t.TempDir()
	projectDir := newLinksRefreshProject(t)
	setIsolatedCodexHomeFallback(t, home)

	var refreshOut bytes.Buffer
	if err := runLinksRefreshFn(projectDir, []string{"codex"}, &refreshOut); err != nil {
		t.Fatalf("runLinksRefreshFn(projectDir, codex) error = %v", err)
	}

	status := runLinksStatusForEngine(t, projectDir, "codex")
	if status.Status != "pass" {
		t.Fatalf("codex status with HOME fallback = %q, want pass; issues=%v", status.Status, status.Issues)
	}
	wantSkills := filepath.Join(home, ".codex", "skills")
	if status.SkillsDir != wantSkills {
		t.Fatalf("codex skillsDir with HOME fallback = %q, want %q", status.SkillsDir, wantSkills)
	}
	wantCommands := filepath.Join(home, ".codex", "commands", "hal")
	if status.CommandsDir != wantCommands {
		t.Fatalf("codex commandsDir with HOME fallback = %q, want %q", status.CommandsDir, wantCommands)
	}
}

func TestRunLinksRefresh_UnknownEngine(t *testing.T) {
	dir := t.TempDir()
	origDir, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(origDir) })
	os.Chdir(dir)

	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(filepath.Join(halDir, "skills"), 0755)

	err := runLinksRefresh(nil, []string{"nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown engine")
	}
	if !strings.Contains(err.Error(), "unknown engine") {
		t.Fatalf("error should mention unknown engine: %v", err)
	}
}

func TestRunLinksStatusFn_EngineFilter(t *testing.T) {
	dir := t.TempDir()
	setIsolatedCodexHomeFallback(t, dir)
	os.MkdirAll(filepath.Join(dir, template.HalDir, "skills"), 0755)

	var buf bytes.Buffer
	if err := runLinksStatusFn(dir, true, "claude", &buf); err != nil {
		t.Fatalf("runLinksStatusFn() error = %v", err)
	}

	var result LinksResult
	json.Unmarshal(buf.Bytes(), &result)

	if len(result.Engines) != 1 {
		t.Fatalf("expected 1 engine with filter, got %d", len(result.Engines))
	}
	if result.Engines[0].Engine != "claude" {
		t.Fatalf("expected claude, got %q", result.Engines[0].Engine)
	}
}

func TestRunLinksStatusFn_NoFilter(t *testing.T) {
	dir := t.TempDir()
	setIsolatedCodexHomeFallback(t, dir)
	os.MkdirAll(filepath.Join(dir, template.HalDir, "skills"), 0755)

	var buf bytes.Buffer
	if err := runLinksStatusFn(dir, true, "", &buf); err != nil {
		t.Fatalf("runLinksStatusFn() error = %v", err)
	}

	var result LinksResult
	json.Unmarshal(buf.Bytes(), &result)

	if len(result.Engines) < 3 {
		t.Fatalf("expected at least 3 engines without filter, got %d", len(result.Engines))
	}
}

func runLinksStatusForEngine(t *testing.T, projectDir, engine string) LinkStatus {
	t.Helper()

	var buf bytes.Buffer
	if err := runLinksStatusFn(projectDir, true, engine, &buf); err != nil {
		t.Fatalf("runLinksStatusFn(%q) error = %v", engine, err)
	}

	var result LinksResult
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("JSON unmarshal error: %v\noutput: %s", err, buf.String())
	}
	if len(result.Engines) != 1 {
		t.Fatalf("expected 1 engine for filter %q, got %d", engine, len(result.Engines))
	}
	if result.Engines[0].Engine != engine {
		t.Fatalf("engine = %q, want %q", result.Engines[0].Engine, engine)
	}
	return result.Engines[0]
}

func containsIssue(issues []string, want string) bool {
	for _, issue := range issues {
		if strings.Contains(issue, want) {
			return true
		}
	}
	return false
}

func newLinksRefreshProject(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	for _, name := range skills.ManagedSkillNames {
		skillDir := filepath.Join(dir, template.HalDir, "skills", name)
		if err := os.MkdirAll(skillDir, 0755); err != nil {
			t.Fatalf("failed to create skill dir %s: %v", skillDir, err)
		}
		if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("# "+name), 0644); err != nil {
			t.Fatalf("failed to write skill file for %s: %v", name, err)
		}
	}

	commandsDir := filepath.Join(dir, template.HalDir, template.CommandsDir)
	if err := os.MkdirAll(commandsDir, 0755); err != nil {
		t.Fatalf("failed to create commands dir %s: %v", commandsDir, err)
	}
	return dir
}

func assertCodexRefreshTargets(t *testing.T, codexHome, projectDir string) {
	t.Helper()

	absProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		t.Fatalf("filepath.Abs(%q) error = %v", projectDir, err)
	}

	for _, name := range skills.ManagedSkillNames {
		assertLinkTarget(t,
			filepath.Join(codexHome, "skills", name),
			filepath.Join(absProjectDir, template.HalDir, "skills", name),
		)
	}
	assertLinkTarget(t,
		filepath.Join(codexHome, "commands", "hal"),
		filepath.Join(absProjectDir, template.HalDir, template.CommandsDir),
	)
}

func snapshotCodexTargets(t *testing.T, codexHome string) map[string]string {
	t.Helper()

	targets := make(map[string]string)
	for _, name := range skills.ManagedSkillNames {
		link := filepath.Join(codexHome, "skills", name)
		targets[link] = readLinkTarget(t, link)
	}
	commandLink := filepath.Join(codexHome, "commands", "hal")
	targets[commandLink] = readLinkTarget(t, commandLink)
	return targets
}

func assertLinkTarget(t *testing.T, link, wantTarget string) {
	t.Helper()

	target := readLinkTarget(t, link)
	if target != wantTarget {
		t.Fatalf("Readlink(%s) = %q, want %q", link, target, wantTarget)
	}
}

func readLinkTarget(t *testing.T, link string) string {
	t.Helper()

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("expected symlink at %s: %v", link, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is not a symlink", link)
	}
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink(%s) error = %v", link, err)
	}
	return target
}

func assertMissingLink(t *testing.T, link string) {
	t.Helper()

	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("%s should not exist; err=%v", link, err)
	}
}

func sameStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
