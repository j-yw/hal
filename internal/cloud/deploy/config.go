// Package deploy provides deployment configuration, store factory selection,
// health endpoints, and smoke checks for hal-cloud services.
package deploy

import (
	"fmt"
	"os"
)

// Adapter names for the HAL_CLOUD_DB_ADAPTER environment variable.
const (
	AdapterTurso    = "turso"
	AdapterPostgres = "postgres"
)

// KnownAdapters lists all supported adapter names.
var KnownAdapters = []string{AdapterTurso, AdapterPostgres}

// Environment variable keys used by hal-cloud services.
const (
	EnvDBAdapter          = "HAL_CLOUD_DB_ADAPTER"
	EnvTursoURL           = "HAL_CLOUD_TURSO_URL"
	EnvTursoAuthToken     = "HAL_CLOUD_TURSO_AUTH_TOKEN"
	EnvRunnerURL          = "HAL_CLOUD_RUNNER_URL"
	EnvRunnerServiceToken = "HAL_CLOUD_RUNNER_SERVICE_TOKEN"
	EnvPostgresDSN        = "HAL_CLOUD_POSTGRES_DSN"
)

// Config holds the resolved deployment configuration for hal-cloud services.
type Config struct {
	// DBAdapter is the selected database adapter ("turso" or "postgres").
	DBAdapter string
	// TursoURL is the Turso database URL (required when DBAdapter is "turso").
	TursoURL string
	// TursoAuthToken is the Turso auth token (required when DBAdapter is "turso").
	TursoAuthToken string
	// PostgresDSN is the Postgres connection string (required when DBAdapter is "postgres").
	PostgresDSN string
	// RunnerURL is the Daytona runner service URL.
	RunnerURL string
	// RunnerServiceToken is the service token for runner authentication.
	RunnerServiceToken string
}

// LoadConfig reads deployment configuration from environment variables.
// It uses the provided getenv function for testability (pass os.Getenv in production).
// Default adapter is "turso" when HAL_CLOUD_DB_ADAPTER is unset.
func LoadConfig(getenv func(string) string) Config {
	adapter := getenv(EnvDBAdapter)
	if adapter == "" {
		adapter = AdapterTurso
	}
	return Config{
		DBAdapter:          adapter,
		TursoURL:           getenv(EnvTursoURL),
		TursoAuthToken:     getenv(EnvTursoAuthToken),
		PostgresDSN:        getenv(EnvPostgresDSN),
		RunnerURL:          getenv(EnvRunnerURL),
		RunnerServiceToken: getenv(EnvRunnerServiceToken),
	}
}

// LoadConfigFromEnv is a convenience wrapper that reads from os.Getenv.
func LoadConfigFromEnv() Config {
	return LoadConfig(os.Getenv)
}

// ValidateStore checks that database-related fields are set for the selected adapter.
// Unlike Validate, it does NOT check RunnerURL or RunnerServiceToken.
func (c Config) ValidateStore() error {
	switch c.DBAdapter {
	case AdapterTurso:
		if c.TursoURL == "" {
			return fmt.Errorf("%s is required when %s is %q", EnvTursoURL, EnvDBAdapter, AdapterTurso)
		}
		if c.TursoAuthToken == "" {
			return fmt.Errorf("%s is required when %s is %q", EnvTursoAuthToken, EnvDBAdapter, AdapterTurso)
		}
	case AdapterPostgres:
		if c.PostgresDSN == "" {
			return fmt.Errorf("%s is required when %s is %q", EnvPostgresDSN, EnvDBAdapter, AdapterPostgres)
		}
	default:
		return fmt.Errorf("%s must be %q or %q, got %q", EnvDBAdapter, AdapterTurso, AdapterPostgres, c.DBAdapter)
	}
	return nil
}

// Validate checks that all required fields are set for the selected adapter.
// Returns an error describing the first missing required variable.
func (c Config) Validate() error {
	switch c.DBAdapter {
	case AdapterTurso:
		if c.TursoURL == "" {
			return fmt.Errorf("%s is required when %s is %q", EnvTursoURL, EnvDBAdapter, AdapterTurso)
		}
		if c.TursoAuthToken == "" {
			return fmt.Errorf("%s is required when %s is %q", EnvTursoAuthToken, EnvDBAdapter, AdapterTurso)
		}
	case AdapterPostgres:
		if c.PostgresDSN == "" {
			return fmt.Errorf("%s is required when %s is %q", EnvPostgresDSN, EnvDBAdapter, AdapterPostgres)
		}
	default:
		return fmt.Errorf("%s must be %q or %q, got %q", EnvDBAdapter, AdapterTurso, AdapterPostgres, c.DBAdapter)
	}

	if c.RunnerURL == "" {
		return fmt.Errorf("%s is required", EnvRunnerURL)
	}
	if c.RunnerServiceToken == "" {
		return fmt.Errorf("%s is required", EnvRunnerServiceToken)
	}

	return nil
}
