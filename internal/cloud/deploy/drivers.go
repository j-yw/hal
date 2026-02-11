package deploy

// Blank imports register the libsql and pgx database drivers at init time
// so that sql.Open calls in store_factory.go resolve without runtime errors.
import (
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/tursodatabase/libsql-client-go/libsql"
)
