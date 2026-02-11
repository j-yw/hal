package deploy

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestOpenStore_UnsupportedAdapter(t *testing.T) {
	cfg := Config{DBAdapter: "mysql"}
	_, _, err := OpenStore(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for unsupported adapter")
	}
	if !strings.Contains(err.Error(), "unsupported adapter") {
		t.Errorf("error %q does not contain %q", err.Error(), "unsupported adapter")
	}
}

func TestOpenStore_TursoFailsWithoutServer(t *testing.T) {
	cfg := Config{
		DBAdapter:      AdapterTurso,
		TursoURL:       "libsql://nonexistent.example.com:1234",
		TursoAuthToken: "fake-token",
	}
	_, _, err := OpenStore(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error connecting to nonexistent Turso server")
	}
}

func TestOpenStore_PostgresFailsWithoutServer(t *testing.T) {
	cfg := Config{
		DBAdapter:   AdapterPostgres,
		PostgresDSN: "postgres://localhost:59999/nonexistent_db_test",
	}
	_, _, err := OpenStore(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error connecting to nonexistent Postgres server")
	}
}

func TestBuildTursoDSN(t *testing.T) {
	tests := []struct {
		name      string
		tursoURL  string
		authToken string
		wantErr   string
		check     func(t *testing.T, dsn string)
	}{
		{
			name:      "no existing query params",
			tursoURL:  "libsql://mydb-myorg.turso.io",
			authToken: "my-secret-token",
			check: func(t *testing.T, dsn string) {
				u, err := url.Parse(dsn)
				if err != nil {
					t.Fatalf("failed to parse DSN: %v", err)
				}
				if got := u.Query().Get("authToken"); got != "my-secret-token" {
					t.Errorf("authToken = %q, want %q", got, "my-secret-token")
				}
				if u.Host != "mydb-myorg.turso.io" {
					t.Errorf("host = %q, want %q", u.Host, "mydb-myorg.turso.io")
				}
			},
		},
		{
			name:      "preserves existing query params",
			tursoURL:  "libsql://mydb-myorg.turso.io?timeout=30s",
			authToken: "my-secret-token",
			check: func(t *testing.T, dsn string) {
				u, err := url.Parse(dsn)
				if err != nil {
					t.Fatalf("failed to parse DSN: %v", err)
				}
				if got := u.Query().Get("authToken"); got != "my-secret-token" {
					t.Errorf("authToken = %q, want %q", got, "my-secret-token")
				}
				if got := u.Query().Get("timeout"); got != "30s" {
					t.Errorf("timeout = %q, want %q", got, "30s")
				}
			},
		},
		{
			name:      "special characters in auth token are escaped",
			tursoURL:  "libsql://mydb-myorg.turso.io",
			authToken: "token+with/special=chars&more",
			check: func(t *testing.T, dsn string) {
				u, err := url.Parse(dsn)
				if err != nil {
					t.Fatalf("failed to parse DSN: %v", err)
				}
				if got := u.Query().Get("authToken"); got != "token+with/special=chars&more" {
					t.Errorf("authToken = %q, want %q", got, "token+with/special=chars&more")
				}
				// Verify the raw query contains the escaped form
				if strings.Contains(u.RawQuery, "token+with/special=chars&more") {
					t.Error("raw query should contain escaped special characters, not literal ones")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dsn, err := buildTursoDSN(tt.tursoURL, tt.authToken)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, dsn)
			}
		})
	}
}
