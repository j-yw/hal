package deploy

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

func TestNewStoreFactory_SyncOnce(t *testing.T) {
	callCount := 0
	factory := newStoreFactory(func() Config {
		callCount++
		// Return a valid config that will pass validation but fail at OpenStore
		// (no real database running) — this exercises the full init path.
		return Config{
			DBAdapter:      AdapterTurso,
			TursoURL:       "libsql://nonexistent.example.com:1234",
			TursoAuthToken: "fake-token",
		}
	})

	// First call — triggers init.
	store1, err1 := factory()
	if err1 == nil {
		t.Fatal("expected error from OpenStore (no server), got nil")
	}

	// Second call — sync.Once returns cached result.
	store2, err2 := factory()
	if err2 == nil {
		t.Fatal("expected cached error on second call, got nil")
	}

	// Same error instance proves sync.Once caching.
	if err1.Error() != err2.Error() {
		t.Errorf("expected same error on both calls:\n  call 1: %v\n  call 2: %v", err1, err2)
	}
	if store1 != store2 {
		t.Error("expected same store pointer on both calls")
	}

	// Config loader should have been called exactly once.
	if callCount != 1 {
		t.Errorf("expected config loader called once, got %d", callCount)
	}
}

func TestNewStoreFactory_ValidationError(t *testing.T) {
	tests := []struct {
		name    string
		getenv  func(string) string
		wantErr string
	}{
		{
			name:    "turso missing url",
			getenv:  func(string) string { return "" },
			wantErr: "validate store config",
		},
		{
			name: "turso missing token",
			getenv: func(key string) string {
				env := map[string]string{
					EnvDBAdapter: AdapterTurso,
					EnvTursoURL:  "libsql://db.example.com",
				}
				return env[key]
			},
			wantErr: "HAL_CLOUD_TURSO_AUTH_TOKEN is required",
		},
		{
			name: "postgres missing dsn",
			getenv: func(key string) string {
				env := map[string]string{
					EnvDBAdapter: AdapterPostgres,
				}
				return env[key]
			},
			wantErr: "HAL_CLOUD_POSTGRES_DSN is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory := newStoreFactory(func() Config {
				return LoadConfig(tt.getenv)
			})
			store, err := factory()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
			if store != nil {
				t.Error("expected nil store on validation error")
			}
		})
	}
}

func TestNewStoreFactory_ErrorWrapsValidateStore(t *testing.T) {
	factory := newStoreFactory(func() Config {
		return LoadConfig(func(string) string { return "" })
	})
	_, err := factory()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Error should wrap with "validate store config:" prefix.
	if !strings.HasPrefix(err.Error(), "validate store config:") {
		t.Errorf("expected error to start with %q, got %q", "validate store config:", err.Error())
	}
}

func TestDefaultStoreFactory_ResetIsolation(t *testing.T) {
	// Reset before test to clear any state from previous tests.
	ResetDefaultStoreForTest(t)

	// Phase 1: env missing TursoURL → validation error.
	t.Setenv(EnvDBAdapter, AdapterTurso)
	t.Setenv(EnvTursoURL, "")
	t.Setenv(EnvTursoAuthToken, "")

	store1, err1 := DefaultStoreFactory()
	if err1 == nil {
		t.Fatal("phase 1: expected validation error, got nil")
	}
	if !strings.HasPrefix(err1.Error(), "validate store config:") {
		t.Errorf("phase 1: expected 'validate store config:' prefix, got %q", err1.Error())
	}
	if store1 != nil {
		t.Error("phase 1: expected nil store")
	}

	// Phase 2: reset, then provide valid fields → should re-initialize and
	// reach OpenStore (different error proves sync.Once was truly reset).
	ResetDefaultStoreForTest(t)

	t.Setenv(EnvTursoURL, "libsql://nonexistent.example.com:1234")
	t.Setenv(EnvTursoAuthToken, "fake-token")

	store2, err2 := DefaultStoreFactory()
	if err2 == nil {
		t.Fatal("phase 2: expected open store error, got nil")
	}
	if !strings.HasPrefix(err2.Error(), "open store:") {
		t.Errorf("phase 2: expected 'open store:' prefix, got %q", err2.Error())
	}
	if store2 != nil {
		t.Error("phase 2: expected nil store")
	}

	// The two errors must differ — proving DefaultStoreFactory re-ran
	// initialization after reset instead of returning the cached phase-1 error.
	if err1.Error() == err2.Error() {
		t.Errorf("expected different errors after reset, both were: %q", err1.Error())
	}

	// Clean up package-level state for other tests.
	ResetDefaultStoreForTest(t)
}

func TestDefaultStoreFactory_LoadsDotenv(t *testing.T) {
	ResetDefaultStoreForTest(t)
	t.Cleanup(func() {
		ResetDefaultStoreForTest(t)
	})

	dir := t.TempDir()
	envContent := strings.Join([]string{
		EnvDBAdapter + "=" + AdapterPostgres,
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(envContent), 0o644); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})

	unsetEnvForTest(t, EnvDBAdapter, EnvPostgresDSN, EnvTursoURL, EnvTursoAuthToken)

	_, err = DefaultStoreFactory()
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), EnvPostgresDSN) {
		t.Fatalf("expected postgres validation error, got %q", err.Error())
	}
}

func TestNewStoreFactory_ErrorWrapsOpenStore(t *testing.T) {
	factory := newStoreFactory(func() Config {
		return Config{
			DBAdapter:      AdapterTurso,
			TursoURL:       "libsql://nonexistent.example.com:1234",
			TursoAuthToken: "fake-token",
		}
	})
	_, err := factory()
	if err == nil {
		t.Fatal("expected error from OpenStore, got nil")
	}
	// Error should wrap with "open store:" prefix.
	if !strings.HasPrefix(err.Error(), "open store:") {
		t.Errorf("expected error to start with %q, got %q", "open store:", err.Error())
	}
}

func TestNewStoreFactory_OpenStoreUsesDeadline(t *testing.T) {
	prevOpenStoreFn := openStoreFn
	t.Cleanup(func() {
		openStoreFn = prevOpenStoreFn
	})

	var receivedCtx context.Context
	openStoreFn = func(ctx context.Context, _ Config) (cloud.Store, *sql.DB, error) {
		receivedCtx = ctx
		return nil, nil, errors.New("boom")
	}

	factory := newStoreFactory(func() Config {
		return Config{
			DBAdapter:   AdapterPostgres,
			PostgresDSN: "postgres://db.example.com:5432/hal",
		}
	})

	_, err := factory()
	if err == nil {
		t.Fatal("expected error from open store, got nil")
	}
	if receivedCtx == nil {
		t.Fatal("expected open store context to be captured")
	}

	assertInitDeadline(t, receivedCtx)
}

func TestDefaultStoreFactory_OpenStoreUsesDeadline(t *testing.T) {
	ResetDefaultStoreForTest(t)
	t.Cleanup(func() {
		ResetDefaultStoreForTest(t)
	})

	prevOpenStoreFn := openStoreFn
	t.Cleanup(func() {
		openStoreFn = prevOpenStoreFn
	})

	var receivedCtx context.Context
	openStoreFn = func(ctx context.Context, _ Config) (cloud.Store, *sql.DB, error) {
		receivedCtx = ctx
		return nil, nil, errors.New("boom")
	}

	t.Setenv(EnvDBAdapter, AdapterPostgres)
	t.Setenv(EnvPostgresDSN, "postgres://db.example.com:5432/hal")

	_, err := DefaultStoreFactory()
	if err == nil {
		t.Fatal("expected error from open store, got nil")
	}
	if !strings.HasPrefix(err.Error(), "open store:") {
		t.Fatalf("expected open store error prefix, got %q", err.Error())
	}
	if receivedCtx == nil {
		t.Fatal("expected open store context to be captured")
	}

	assertInitDeadline(t, receivedCtx)
}

func unsetEnvForTest(t *testing.T, keys ...string) {
	t.Helper()

	prior := make(map[string]*string, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			saved := value
			prior[key] = &saved
		} else {
			prior[key] = nil
		}
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("unset %s: %v", key, err)
		}
	}

	t.Cleanup(func() {
		for _, key := range keys {
			value := prior[key]
			if value == nil {
				_ = os.Unsetenv(key)
				continue
			}
			_ = os.Setenv(key, *value)
		}
	})
}

func assertInitDeadline(t *testing.T, ctx context.Context) {
	t.Helper()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected initialization context to include a deadline")
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		t.Fatalf("expected positive deadline remaining, got %s", remaining)
	}
	if remaining > defaultStoreInitTimeout {
		t.Fatalf("expected remaining deadline <= %s, got %s", defaultStoreInitTimeout, remaining)
	}
}
