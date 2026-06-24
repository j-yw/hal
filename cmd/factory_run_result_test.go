package cmd

import (
	"testing"

	"github.com/jywlabs/hal/internal/factory"
)

func TestFactoryRunFailureClassificationMapsBootstrapCategories(t *testing.T) {
	tests := []struct {
		name     string
		category string
		want     string
	}{
		{
			name:     "repo maps to git",
			category: factory.BootstrapFailureCategoryRepo,
			want:     factory.FailureCategoryGit,
		},
		{
			name:     "auth maps to validation",
			category: factory.BootstrapFailureCategoryAuth,
			want:     factory.FailureCategoryValidation,
		},
		{
			name:     "dependency maps to validation",
			category: factory.BootstrapFailureCategoryDependency,
			want:     factory.FailureCategoryValidation,
		},
		{
			name:     "engine setup maps to engine",
			category: factory.BootstrapFailureCategoryEngineSetup,
			want:     factory.FailureCategoryEngine,
		},
		{
			name:     "unknown input remains unknown",
			category: "external",
			want:     factory.FailureCategoryUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := factory.RunRecord{
				Failure: &factory.FailureSummary{
					Category: tt.category,
					Message:  "failed",
				},
			}
			failure := newFactoryRunFailure(record)
			if failure == nil {
				t.Fatal("newFactoryRunFailure() = nil")
			}
			if failure.Classification != tt.want {
				t.Fatalf("classification = %q, want %q", failure.Classification, tt.want)
			}
		})
	}
}
