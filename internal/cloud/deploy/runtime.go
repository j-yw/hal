package deploy

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/cloud"
)

var (
	defaultStore cloud.Store
	defaultDB    *sql.DB
	defaultErr   error
	defaultOnce  sync.Once
)

// DefaultStoreFactory loads config from environment variables, validates the
// store configuration, and opens the database connection. It uses sync.Once
// to ensure initialization runs exactly once — subsequent calls return the
// cached store or error.
func DefaultStoreFactory() (cloud.Store, error) {
	defaultOnce.Do(func() {
		cfg := LoadConfigFromEnv()
		if err := cfg.ValidateStore(); err != nil {
			defaultErr = fmt.Errorf("validate store config: %w", err)
			return
		}
		store, db, err := OpenStore(context.Background(), cfg)
		if err != nil {
			defaultErr = fmt.Errorf("open store: %w", err)
			return
		}
		defaultStore = store
		defaultDB = db
	})
	return defaultStore, defaultErr
}

// CloseDefaultStore closes the cached database connection held by
// DefaultStoreFactory. It returns nil if no connection has been opened.
func CloseDefaultStore() error {
	if defaultDB != nil {
		return defaultDB.Close()
	}
	return nil
}

// ResetDefaultStoreForTest resets the package-level sync.Once and cached
// store/DB/error so that multiple tests can exercise DefaultStoreFactory
// in isolation.
func ResetDefaultStoreForTest(t *testing.T) {
	t.Helper()
	if err := CloseDefaultStore(); err != nil {
		t.Fatalf("close default store: %v", err)
	}
	defaultOnce = sync.Once{}
	defaultStore = nil
	defaultDB = nil
	defaultErr = nil
}

// newStoreFactory creates a store factory closure with its own sync.Once,
// using the provided config loader. This allows tests to create isolated
// factory instances with custom getenv functions.
func newStoreFactory(loadConfig func() Config) func() (cloud.Store, error) {
	var (
		store cloud.Store
		db    *sql.DB
		err   error
		once  sync.Once
	)
	_ = db // retained for future close/cleanup needs
	return func() (cloud.Store, error) {
		once.Do(func() {
			cfg := loadConfig()
			if valErr := cfg.ValidateStore(); valErr != nil {
				err = fmt.Errorf("validate store config: %w", valErr)
				return
			}
			var openErr error
			store, db, openErr = OpenStore(context.Background(), cfg)
			if openErr != nil {
				err = fmt.Errorf("open store: %w", openErr)
				return
			}
		})
		return store, err
	}
}
