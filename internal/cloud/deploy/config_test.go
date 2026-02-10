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
		EnvDBAdapter:          AdapterTurso,
		EnvTursoURL:           "libsql://db.example.com",
		EnvTursoAuthToken:     "token123",
		EnvRunnerURL:          "http://runner:8090",
		EnvRunnerServiceToken: "svc-token",
	}
	cfg := LoadConfig(func(key string) string { return env[key] })
	if cfg.TursoURL != env[EnvTursoURL] {
		t.Errorf("TursoURL = %q, want %q", cfg.TursoURL, env[EnvTursoURL])
	}
	if cfg.TursoAuthToken != env[EnvTursoAuthToken] {
		t.Errorf("TursoAuthToken = %q, want %q", cfg.TursoAuthToken, env[EnvTursoAuthToken])
	}
	if cfg.RunnerURL != env[EnvRunnerURL] {
		t.Errorf("RunnerURL = %q, want %q", cfg.RunnerURL, env[EnvRunnerURL])
	}
	if cfg.RunnerServiceToken != env[EnvRunnerServiceToken] {
		t.Errorf("RunnerServiceToken = %q, want %q", cfg.RunnerServiceToken, env[EnvRunnerServiceToken])
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "valid turso config",
			config: Config{
				DBAdapter:          AdapterTurso,
				TursoURL:           "libsql://db.example.com",
				TursoAuthToken:     "token123",
				RunnerURL:          "http://runner:8090",
				RunnerServiceToken: "svc-token",
			},
			wantErr: "",
		},
		{
			name: "valid postgres config",
			config: Config{
				DBAdapter:          AdapterPostgres,
				PostgresDSN:        "postgres://localhost:5432/hal",
				RunnerURL:          "http://runner:8090",
				RunnerServiceToken: "svc-token",
			},
			wantErr: "",
		},
		{
			name: "turso missing url",
			config: Config{
				DBAdapter:          AdapterTurso,
				TursoAuthToken:     "token123",
				RunnerURL:          "http://runner:8090",
				RunnerServiceToken: "svc-token",
			},
			wantErr: "HAL_CLOUD_TURSO_URL is required",
		},
		{
			name: "turso missing token",
			config: Config{
				DBAdapter:          AdapterTurso,
				TursoURL:           "libsql://db.example.com",
				RunnerURL:          "http://runner:8090",
				RunnerServiceToken: "svc-token",
			},
			wantErr: "HAL_CLOUD_TURSO_AUTH_TOKEN is required",
		},
		{
			name: "postgres missing dsn",
			config: Config{
				DBAdapter:          AdapterPostgres,
				RunnerURL:          "http://runner:8090",
				RunnerServiceToken: "svc-token",
			},
			wantErr: "HAL_CLOUD_POSTGRES_DSN is required",
		},
		{
			name: "invalid adapter",
			config: Config{
				DBAdapter:          "mysql",
				RunnerURL:          "http://runner:8090",
				RunnerServiceToken: "svc-token",
			},
			wantErr: "must be",
		},
		{
			name: "missing runner url",
			config: Config{
				DBAdapter:          AdapterTurso,
				TursoURL:           "libsql://db.example.com",
				TursoAuthToken:     "token123",
				RunnerServiceToken: "svc-token",
			},
			wantErr: "HAL_CLOUD_RUNNER_URL is required",
		},
		{
			name: "missing runner service token",
			config: Config{
				DBAdapter:      AdapterTurso,
				TursoURL:       "libsql://db.example.com",
				TursoAuthToken: "token123",
				RunnerURL:      "http://runner:8090",
			},
			wantErr: "HAL_CLOUD_RUNNER_SERVICE_TOKEN is required",
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
