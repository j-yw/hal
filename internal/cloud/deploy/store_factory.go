package deploy

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/cloud/postgres"
	"github.com/jywlabs/hal/internal/cloud/turso"
)

// OpenStore opens a database connection and returns a cloud.Store for the
// configured adapter. It also runs schema migration. The caller is responsible
// for closing the returned *sql.DB when done.
func OpenStore(ctx context.Context, cfg Config) (cloud.Store, *sql.DB, error) {
	switch cfg.DBAdapter {
	case AdapterTurso:
		return openTurso(ctx, cfg)
	case AdapterPostgres:
		return openPostgres(ctx, cfg)
	default:
		return nil, nil, fmt.Errorf("unsupported adapter: %s", cfg.DBAdapter)
	}
}

// buildTursoDSN constructs a Turso DSN using net/url to properly escape
// the auth token and preserve any existing query parameters in the URL.
func buildTursoDSN(tursoURL, authToken string) (string, error) {
	u, err := url.Parse(tursoURL)
	if err != nil {
		return "", fmt.Errorf("parse turso URL: %w", err)
	}
	q := u.Query()
	q.Set("authToken", authToken)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func openTurso(ctx context.Context, cfg Config) (cloud.Store, *sql.DB, error) {
	dsn, err := buildTursoDSN(cfg.TursoURL, cfg.TursoAuthToken)
	if err != nil {
		return nil, nil, fmt.Errorf("turso dsn: %w", err)
	}
	db, err := sql.Open("libsql", dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("turso open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("turso ping: %w", err)
	}
	store := turso.New(db)
	if err := store.Migrate(ctx); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("turso migrate: %w", err)
	}
	return store, db, nil
}

func openPostgres(ctx context.Context, cfg Config) (cloud.Store, *sql.DB, error) {
	db, err := sql.Open("pgx", cfg.PostgresDSN)
	if err != nil {
		return nil, nil, fmt.Errorf("postgres open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("postgres ping: %w", err)
	}
	store := postgres.New(db)
	if err := store.Migrate(ctx); err != nil {
		db.Close()
		return nil, nil, fmt.Errorf("postgres migrate: %w", err)
	}
	return store, db, nil
}
