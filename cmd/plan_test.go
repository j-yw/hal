package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestLoadPlanProductContext_AllFilesPresent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePlanProductFile(t, dir, template.ProductMissionFile, "# Mission\nMission content")
	writePlanProductFile(t, dir, template.ProductRoadmapFile, "# Roadmap\nRoadmap content")
	writePlanProductFile(t, dir, template.ProductTechStackFile, "# Tech Stack\nTech content")

	contextText, missing, err := loadPlanProductContext(dir)
	if err != nil {
		t.Fatalf("loadPlanProductContext() error = %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("missing = %v, want empty", missing)
	}

	for _, fileName := range template.ProductFiles() {
		if !strings.Contains(contextText, "### "+fileName) {
			t.Fatalf("context missing section header for %q\ncontext:\n%s", fileName, contextText)
		}
	}

	missionIdx := strings.Index(contextText, "### "+template.ProductMissionFile)
	roadmapIdx := strings.Index(contextText, "### "+template.ProductRoadmapFile)
	techIdx := strings.Index(contextText, "### "+template.ProductTechStackFile)
	if missionIdx == -1 || roadmapIdx == -1 || techIdx == -1 || !(missionIdx < roadmapIdx && roadmapIdx < techIdx) {
		t.Fatalf("context sections should follow mission -> roadmap -> tech-stack order\ncontext:\n%s", contextText)
	}
}

func TestLoadPlanProductContext_MissingFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writePlanProductFile(t, dir, template.ProductMissionFile, "Mission only")

	contextText, missing, err := loadPlanProductContext(dir)
	if err != nil {
		t.Fatalf("loadPlanProductContext() error = %v", err)
	}

	wantMissing := []string{template.ProductRoadmapFile, template.ProductTechStackFile}
	if !reflect.DeepEqual(missing, wantMissing) {
		t.Fatalf("missing = %v, want %v", missing, wantMissing)
	}
	if !strings.Contains(contextText, "### "+template.ProductMissionFile) {
		t.Fatalf("context should include mission content\ncontext:\n%s", contextText)
	}
	if strings.Contains(contextText, "### "+template.ProductRoadmapFile) {
		t.Fatalf("context should not include missing roadmap section\ncontext:\n%s", contextText)
	}
}

func TestLoadPlanProductContext_NoFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	contextText, missing, err := loadPlanProductContext(dir)
	if err != nil {
		t.Fatalf("loadPlanProductContext() error = %v", err)
	}
	if contextText != "" {
		t.Fatalf("context = %q, want empty", contextText)
	}
	if !reflect.DeepEqual(missing, template.ProductFiles()) {
		t.Fatalf("missing = %v, want %v", missing, template.ProductFiles())
	}
}

func TestWarnMissingPlanProductFiles(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	warnMissingPlanProductFiles(&buf, []string{template.ProductMissionFile, template.ProductTechStackFile})

	out := buf.String()
	if !strings.Contains(out, filepath.Join(template.HalDir, template.ProductDir, template.ProductMissionFile)) {
		t.Fatalf("warning output missing mission path: %q", out)
	}
	if !strings.Contains(out, filepath.Join(template.HalDir, template.ProductDir, template.ProductTechStackFile)) {
		t.Fatalf("warning output missing tech-stack path: %q", out)
	}
}

func writePlanProductFile(t *testing.T, dir, fileName, content string) {
	t.Helper()

	productDir := filepath.Join(dir, template.HalDir, template.ProductDir)
	if err := os.MkdirAll(productDir, 0755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", productDir, err)
	}
	path := filepath.Join(productDir, fileName)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
