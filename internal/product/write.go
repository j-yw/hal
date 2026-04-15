package product

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/template"
)

// WriteSelectedFiles writes generated content for selected product documents.
// Non-selected documents are never modified.
func WriteSelectedFiles(projectDir string, targets SelectedTargets, payload GeneratedPayload) error {
	writes := selectedFileWrites(targets, payload)
	if len(writes) == 0 {
		return nil
	}

	productDir := filepath.Join(projectDir, template.HalDir, template.ProductDir)
	if err := os.MkdirAll(productDir, 0755); err != nil {
		return fmt.Errorf("create product directory %s: %w", productDir, err)
	}

	for _, write := range writes {
		path := filepath.Join(productDir, write.name)
		if err := os.WriteFile(path, []byte(write.content), 0644); err != nil {
			return fmt.Errorf("write product file %s: %w", path, err)
		}
	}

	return nil
}

type fileWrite struct {
	name    string
	content string
}

func selectedFileWrites(targets SelectedTargets, payload GeneratedPayload) []fileWrite {
	writes := make([]fileWrite, 0, len(template.ProductFiles()))
	if targets.Mission && payload.Mission != nil {
		writes = append(writes, fileWrite{name: template.ProductMissionFile, content: *payload.Mission})
	}
	if targets.Roadmap && payload.Roadmap != nil {
		writes = append(writes, fileWrite{name: template.ProductRoadmapFile, content: *payload.Roadmap})
	}
	if targets.TechStack && payload.TechStack != nil {
		writes = append(writes, fileWrite{name: template.ProductTechStackFile, content: *payload.TechStack})
	}
	return writes
}
