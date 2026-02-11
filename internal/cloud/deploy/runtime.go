package deploy

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

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
