package deploy

import (
	"strings"
	"testing"
)

func TestLoadConfig_DefaultAdapter(t *testing.T) {
	cfg := LoadConfig(func(key string) string { return "" })
	if cfg.DBAdapter != AdapterTurso {
		t.Errorf("expected default adapter %q, got %q", AdapterTurso, cfg.DBAdapter)
	}
}

func TestLoadConfig_ExplicitAdapter(t *testing.T) {
	env := map[string]string{
		EnvDBAdapter: AdapterPostgres,
	}
	cfg := LoadConfig(func(key string) string { return env[key] })
	if cfg.DBAdapter != AdapterPostgres {
		t.Errorf("expected adapter %q, got %q", AdapterPostgres, cfg.DBAdapter)
	}
}

func TestLoadConfig_AllFields(t *testing.T) {
	env := map[string]string{
		EnvDBAdapter:     AdapterTurso,
		EnvTursoURL:      "libsql://db.example.com",
		EnvTursoAuthToken: "token123",
		EnvDaytonaAPIKey: "daytona-key-123",
		EnvDaytonaAPIURL: "https://api.daytona.io",
		EnvDaytonaTarget: "us-east-1",
	}
	cfg := LoadConfig(func(key string) string { return env[key] })
	if cfg.TursoURL != env[EnvTursoURL] {
		t.Errorf("TursoURL = %q, want %q", cfg.TursoURL, env[EnvTursoURL])
	}
	if cfg.TursoAuthToken != env[EnvTursoAuthToken] {
		t.Errorf("TursoAuthToken = %q, want %q", cfg.TursoAuthToken, env[EnvTursoAuthToken])
	}
	if cfg.DaytonaAPIKey != env[EnvDaytonaAPIKey] {
		t.Errorf("DaytonaAPIKey = %q, want %q", cfg.DaytonaAPIKey, env[EnvDaytonaAPIKey])
	}
	if cfg.DaytonaAPIURL != env[EnvDaytonaAPIURL] {
		t.Errorf("DaytonaAPIURL = %q, want %q", cfg.DaytonaAPIURL, env[EnvDaytonaAPIURL])
	}
	if cfg.DaytonaTarget != env[EnvDaytonaTarget] {
		t.Errorf("DaytonaTarget = %q, want %q", cfg.DaytonaTarget, env[EnvDaytonaTarget])
	}
}

func TestLoadConfig_DaytonaAPIURLFallback(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantURL string
	}{
		{
			name: "prefers DAYTONA_API_URL when both set",
			env: map[string]string{
				EnvDaytonaAPIURL:    "https://api.daytona.io",
				EnvDaytonaServerURL: "https://server.daytona.io",
			},
			wantURL: "https://api.daytona.io",
		},
		{
			name: "falls back to DAYTONA_SERVER_URL when DAYTONA_API_URL is unset",
			env: map[string]string{
				EnvDaytonaServerURL: "https://server.daytona.io",
			},
			wantURL: "https://server.daytona.io",
		},
		{
			name:    "empty when neither set",
			env:     map[string]string{},
			wantURL: "",
		},
		{
			name: "DAYTONA_API_URL only",
			env: map[string]string{
				EnvDaytonaAPIURL: "https://api.daytona.io",
			},
			wantURL: "https://api.daytona.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := LoadConfig(func(key string) string { return tt.env[key] })
			if cfg.DaytonaAPIURL != tt.wantURL {
				t.Errorf("DaytonaAPIURL = %q, want %q", cfg.DaytonaAPIURL, tt.wantURL)
			}
		})
	}
}

func TestConfigValidateStore(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "valid turso store config",
			config: Config{
				DBAdapter:      AdapterTurso,
				TursoURL:       "libsql://db.example.com",
				TursoAuthToken: "token123",
			},
			wantErr: "",
		},
		{
			name: "valid postgres store config",
			config: Config{
				DBAdapter:   AdapterPostgres,
				PostgresDSN: "postgres://localhost:5432/hal",
			},
			wantErr: "",
		},
		{
			name: "turso missing url",
			config: Config{
				DBAdapter:      AdapterTurso,
				TursoAuthToken: "token123",
			},
			wantErr: "HAL_CLOUD_TURSO_URL is required",
		},
		{
			name: "turso missing token",
			config: Config{
				DBAdapter: AdapterTurso,
				TursoURL:  "libsql://db.example.com",
			},
			wantErr: "HAL_CLOUD_TURSO_AUTH_TOKEN is required",
		},
		{
			name: "postgres missing dsn",
			config: Config{
				DBAdapter: AdapterPostgres,
			},
			wantErr: "HAL_CLOUD_POSTGRES_DSN is required",
		},
		{
			name: "invalid adapter",
			config: Config{
				DBAdapter: "mysql",
			},
			wantErr: "must be",
		},
		{
			name: "does not check daytona api key",
			config: Config{
				DBAdapter:      AdapterTurso,
				TursoURL:       "libsql://db.example.com",
				TursoAuthToken: "token123",
				DaytonaAPIKey:  "", // empty API key should not cause error
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateStore()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "valid turso config with daytona api key",
			config: Config{
				DBAdapter:      AdapterTurso,
				TursoURL:       "libsql://db.example.com",
				TursoAuthToken: "token123",
				DaytonaAPIKey:  "daytona-key-123",
			},
			wantErr: "",
		},
		{
			name: "valid postgres config with daytona api key",
			config: Config{
				DBAdapter:     AdapterPostgres,
				PostgresDSN:   "postgres://localhost:5432/hal",
				DaytonaAPIKey: "daytona-key-123",
			},
			wantErr: "",
		},
		{
			name: "valid config with all daytona fields",
			config: Config{
				DBAdapter:      AdapterTurso,
				TursoURL:       "libsql://db.example.com",
				TursoAuthToken: "token123",
				DaytonaAPIKey:  "daytona-key-123",
				DaytonaAPIURL:  "https://api.daytona.io",
				DaytonaTarget:  "us-east-1",
			},
			wantErr: "",
		},
		{
			name: "turso missing url",
			config: Config{
				DBAdapter:      AdapterTurso,
				TursoAuthToken: "token123",
				DaytonaAPIKey:  "daytona-key-123",
			},
			wantErr: "HAL_CLOUD_TURSO_URL is required",
		},
		{
			name: "turso missing token",
			config: Config{
				DBAdapter:     AdapterTurso,
				TursoURL:      "libsql://db.example.com",
				DaytonaAPIKey: "daytona-key-123",
			},
			wantErr: "HAL_CLOUD_TURSO_AUTH_TOKEN is required",
		},
		{
			name: "postgres missing dsn",
			config: Config{
				DBAdapter:     AdapterPostgres,
				DaytonaAPIKey: "daytona-key-123",
			},
			wantErr: "HAL_CLOUD_POSTGRES_DSN is required",
		},
		{
			name: "invalid adapter",
			config: Config{
				DBAdapter:     "mysql",
				DaytonaAPIKey: "daytona-key-123",
			},
			wantErr: "must be",
		},
		{
			name: "missing daytona api key",
			config: Config{
				DBAdapter:      AdapterTurso,
				TursoURL:       "libsql://db.example.com",
				TursoAuthToken: "token123",
			},
			wantErr: "DAYTONA_API_KEY is required",
		},
		{
			name: "daytona api url and target are optional",
			config: Config{
				DBAdapter:      AdapterTurso,
				TursoURL:       "libsql://db.example.com",
				TursoAuthToken: "token123",
				DaytonaAPIKey:  "daytona-key-123",
				DaytonaAPIURL:  "", // optional
				DaytonaTarget:  "", // optional
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
