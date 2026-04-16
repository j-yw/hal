package product

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestWriteSelectedFiles_CreatesProductDirLazily(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	productDir := filepath.Join(dir, template.HalDir, template.ProductDir)
	if _, err := os.Stat(productDir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected %s to not exist before write, stat error: %v", productDir, err)
	}

	mission := "Updated mission"
	err := WriteSelectedFiles(
		dir,
		SelectedTargets{Mission: true},
		GeneratedPayload{Mission: &mission},
	)
	if err != nil {
		t.Fatalf("WriteSelectedFiles() error = %v", err)
	}

	if _, err := os.Stat(productDir); err != nil {
		t.Fatalf("expected %s to exist after write, stat error: %v", productDir, err)
	}
	gotMission := readProductFileBytes(t, dir, template.ProductMissionFile)
	if string(gotMission) != mission {
		t.Fatalf("mission content = %q, want %q", string(gotMission), mission)
	}
}

func TestWriteSelectedFiles_LeavesNonSelectedFilesUnchanged(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	missionOriginal := "Mission stays exactly the same.\nwith newline.\n"
	roadmapOriginal := "Roadmap to replace."
	techStackOriginal := "Tech stack stays the same."
	writeProductFile(t, dir, template.ProductMissionFile, missionOriginal)
	writeProductFile(t, dir, template.ProductRoadmapFile, roadmapOriginal)
	writeProductFile(t, dir, template.ProductTechStackFile, techStackOriginal)

	missionBefore := readProductFileBytes(t, dir, template.ProductMissionFile)
	techStackBefore := readProductFileBytes(t, dir, template.ProductTechStackFile)

	updatedRoadmap := "Roadmap updated."
	err := WriteSelectedFiles(
		dir,
		SelectedTargets{Roadmap: true},
		GeneratedPayload{Roadmap: &updatedRoadmap},
	)
	if err != nil {
		t.Fatalf("WriteSelectedFiles() error = %v", err)
	}

	missionAfter := readProductFileBytes(t, dir, template.ProductMissionFile)
	roadmapAfter := readProductFileBytes(t, dir, template.ProductRoadmapFile)
	techStackAfter := readProductFileBytes(t, dir, template.ProductTechStackFile)

	if !bytes.Equal(missionBefore, missionAfter) {
		t.Fatalf("mission bytes changed unexpectedly: before=%q after=%q", string(missionBefore), string(missionAfter))
	}
	if !bytes.Equal(techStackBefore, techStackAfter) {
		t.Fatalf("tech-stack bytes changed unexpectedly: before=%q after=%q", string(techStackBefore), string(techStackAfter))
	}
	if string(roadmapAfter) != updatedRoadmap {
		t.Fatalf("roadmap content = %q, want %q", string(roadmapAfter), updatedRoadmap)
	}
}

func TestWriteSelectedFiles_IgnoresPayloadFieldsForNonSelectedTargets(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	missionOriginal := "Mission should not be touched."
	roadmapOriginal := "Roadmap original."
	writeProductFile(t, dir, template.ProductMissionFile, missionOriginal)
	writeProductFile(t, dir, template.ProductRoadmapFile, roadmapOriginal)

	missionBefore := readProductFileBytes(t, dir, template.ProductMissionFile)

	updatedMission := "Mission should be ignored."
	updatedRoadmap := "Roadmap updated."
	err := WriteSelectedFiles(
		dir,
		SelectedTargets{Roadmap: true},
		GeneratedPayload{
			Mission: &updatedMission,
			Roadmap: &updatedRoadmap,
		},
	)
	if err != nil {
		t.Fatalf("WriteSelectedFiles() error = %v", err)
	}

	missionAfter := readProductFileBytes(t, dir, template.ProductMissionFile)
	roadmapAfter := readProductFileBytes(t, dir, template.ProductRoadmapFile)

	if !bytes.Equal(missionAfter, missionBefore) {
		t.Fatalf("mission bytes changed unexpectedly: before=%q after=%q", string(missionBefore), string(missionAfter))
	}
	if string(roadmapAfter) != updatedRoadmap {
		t.Fatalf("roadmap content = %q, want %q", string(roadmapAfter), updatedRoadmap)
	}
}

func readProductFileBytes(t *testing.T, dir, name string) []byte {
	t.Helper()

	path := filepath.Join(dir, template.HalDir, template.ProductDir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return data
}
