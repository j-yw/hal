package cmd

import (
	"errors"
	"fmt"

	"github.com/jywlabs/hal/internal/sandboxexecution"
)

func appendSandboxArtifactCopyWarning(store sandboxexecution.Store, executionID string, err error) (bool, error) {
	var artifactErr *sandboxexecution.ArtifactCollectionError
	if !errors.As(err, &artifactErr) || artifactErr == nil {
		return false, nil
	}
	if artifactErr.Phase != sandboxexecution.ArtifactWarningPhaseCopyOut {
		return false, nil
	}
	if err := store.AppendArtifactMetadata(executionID, sandboxexecution.ArtifactMetadata{
		Warnings: []sandboxexecution.ArtifactWarning{artifactErr.Warning()},
	}); err != nil {
		return true, fmt.Errorf("persist sandbox execution artifact copy warning: %w", err)
	}
	return true, nil
}
