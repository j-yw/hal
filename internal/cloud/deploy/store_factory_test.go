package deploy

import (
	"context"
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
