package product

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/template"
)

// LoadExistingFiles reads current product-doc file state from .hal/product/.
func LoadExistingFiles(projectDir string) (ExistingFiles, error) {
	productDir := filepath.Join(projectDir, template.HalDir, template.ProductDir)

	mission, err := loadFileState(filepath.Join(productDir, template.ProductMissionFile))
	if err != nil {
		return ExistingFiles{}, err
	}
	roadmap, err := loadFileState(filepath.Join(productDir, template.ProductRoadmapFile))
	if err != nil {
		return ExistingFiles{}, err
	}
	techStack, err := loadFileState(filepath.Join(productDir, template.ProductTechStackFile))
	if err != nil {
		return ExistingFiles{}, err
	}

	return ExistingFiles{
		Mission:   mission,
		Roadmap:   roadmap,
		TechStack: techStack,
	}, nil
}

func loadFileState(path string) (FileState, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return FileState{
			Exists:  true,
			Content: string(data),
		}, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return FileState{}, nil
	}
	return FileState{}, fmt.Errorf("read product file %s: %w", path, err)
}
