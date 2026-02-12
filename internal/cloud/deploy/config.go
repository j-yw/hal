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
	EnvDBAdapter      = "HAL_CLOUD_DB_ADAPTER"
	EnvTursoURL       = "HAL_CLOUD_TURSO_URL"
	EnvTursoAuthToken = "HAL_CLOUD_TURSO_AUTH_TOKEN"
	EnvPostgresDSN    = "HAL_CLOUD_POSTGRES_DSN"

	// Daytona SDK environment variables.
	EnvDaytonaAPIKey = "DAYTONA_API_KEY"
	EnvDaytonaAPIURL = "DAYTONA_API_URL"
	EnvDaytonaTarget = "DAYTONA_TARGET"
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

	// DaytonaAPIKey is the Daytona SDK API key (required).
	DaytonaAPIKey string
	// DaytonaAPIURL is the Daytona SDK API URL (optional).
	DaytonaAPIURL string
	// DaytonaTarget is the Daytona SDK target (optional).
	DaytonaTarget string
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
		DBAdapter:      adapter,
		TursoURL:       getenv(EnvTursoURL),
		TursoAuthToken: getenv(EnvTursoAuthToken),
		PostgresDSN:    getenv(EnvPostgresDSN),
		DaytonaAPIKey:  getenv(EnvDaytonaAPIKey),
		DaytonaAPIURL:  getenv(EnvDaytonaAPIURL),
		DaytonaTarget:  getenv(EnvDaytonaTarget),
	}
}

// LoadConfigFromEnv is a convenience wrapper that reads from os.Getenv.
func LoadConfigFromEnv() Config {
	return LoadConfig(os.Getenv)
}

// validateAdapter checks that database-related fields are set for the selected adapter.
func (c Config) validateAdapter() error {
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

// ValidateStore checks that database-related fields are set for the selected adapter.
// Unlike Validate, it does NOT check Daytona SDK fields.
func (c Config) ValidateStore() error {
	return c.validateAdapter()
}

// Validate checks that all required fields are set for the selected adapter
// and that the Daytona API key is present.
// Returns an error describing the first missing required variable.
func (c Config) Validate() error {
	if err := c.validateAdapter(); err != nil {
		return err
	}

	if c.DaytonaAPIKey == "" {
		return fmt.Errorf("%s is required", EnvDaytonaAPIKey)
	}

	return nil
}
