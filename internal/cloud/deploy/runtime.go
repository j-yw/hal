package deploy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/jywlabs/hal/internal/cloud"
)

var (
	defaultStore cloud.Store
	defaultDB    *sql.DB
	defaultErr   error
	defaultOnce  sync.Once

	// openStoreFn allows tests to stub OpenStore and inspect initialization
	// context behavior without making real DB connections.
	openStoreFn = OpenStore
)

const defaultStoreInitTimeout = 10 * time.Second

// DefaultStoreFactory loads config from environment variables, validates the
// store configuration, and opens the database connection. It uses sync.Once
// to ensure initialization runs exactly once — subsequent calls return the
// cached store or error.
func DefaultStoreFactory() (cloud.Store, error) {
	defaultOnce.Do(func() {
		// Load .env if present so cloud/auth commands can run from .env-only setups.
		if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
			// Keep dotenv parse/load issues non-fatal and fall back to process env.
			fmt.Fprintf(os.Stderr, "Warning: failed to load .env file: %v\n", err)
		}

		cfg := LoadConfigFromEnv()
		if err := cfg.ValidateStore(); err != nil {
			defaultErr = fmt.Errorf("validate store config: %w", err)
			return
		}
		store, db, err := openStoreWithTimeout(cfg)
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
			store, db, openErr = openStoreWithTimeout(cfg)
			if openErr != nil {
				err = fmt.Errorf("open store: %w", openErr)
				return
			}
		})
		return store, err
	}
}

func openStoreWithTimeout(cfg Config) (cloud.Store, *sql.DB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultStoreInitTimeout)
	defer cancel()
	return openStoreFn(ctx, cfg)
}
