package deploy

import (
	"context"
	"strings"
	"testing"
)

// TestAdapterValidationParity ensures KnownAdapters, validateAdapter, and
// OpenStore stay in sync. If a new adapter is added to KnownAdapters but not
// handled in OpenStore (or vice versa), this test fails.
func TestAdapterValidationParity(t *testing.T) {
	// validFields returns a Config with all adapter-specific fields populated
	// so that validateAdapter will accept it.
	validFields := func(adapter string) Config {
		return Config{
			DBAdapter:      adapter,
			TursoURL:       "libsql://db.example.com",
			TursoAuthToken: "token",
			PostgresDSN:    "postgres://localhost:5432/hal",
		}
	}

	t.Run("known adapters accepted by validateAdapter", func(t *testing.T) {
		for _, adapter := range KnownAdapters {
			t.Run(adapter, func(t *testing.T) {
				cfg := validFields(adapter)
				if err := cfg.validateAdapter(); err != nil {
					t.Errorf("validateAdapter rejected known adapter %q: %v", adapter, err)
				}
			})
		}
	})

	t.Run("unknown adapter rejected by validateAdapter", func(t *testing.T) {
		cfg := Config{DBAdapter: "mysql"}
		err := cfg.validateAdapter()
		if err == nil {
			t.Fatal("expected error for unknown adapter, got nil")
		}
		if !strings.Contains(err.Error(), "must be") {
			t.Errorf("error %q does not contain %q", err.Error(), "must be")
		}
	})

	t.Run("known adapters do not produce unsupported adapter error from OpenStore", func(t *testing.T) {
		ctx := context.Background()
		for _, adapter := range KnownAdapters {
			t.Run(adapter, func(t *testing.T) {
				cfg := validFields(adapter)
				_, _, err := OpenStore(ctx, cfg)
				// OpenStore will fail (no real DB), but the error must NOT be
				// "unsupported adapter" — that would mean OpenStore doesn't
				// handle this known adapter.
				if err != nil && strings.Contains(err.Error(), "unsupported adapter") {
					t.Errorf("OpenStore returned 'unsupported adapter' for known adapter %q", adapter)
				}
			})
		}
	})

	t.Run("unknown adapter produces unsupported adapter error from OpenStore", func(t *testing.T) {
		ctx := context.Background()
		cfg := Config{DBAdapter: "mysql"}
		_, _, err := OpenStore(ctx, cfg)
		if err == nil {
			t.Fatal("expected error for unknown adapter, got nil")
		}
		if !strings.Contains(err.Error(), "unsupported adapter") {
			t.Errorf("error %q does not contain %q", err.Error(), "unsupported adapter")
		}
	})
}
