package deploy

import (
	"database/sql"
	"slices"
	"testing"
)

func TestDriversRegistered(t *testing.T) {
	drivers := sql.Drivers()

	for _, want := range []string{"libsql", "pgx"} {
		if !slices.Contains(drivers, want) {
			t.Errorf("expected %q driver to be registered via blank import, got drivers: %v", want, drivers)
		}
	}
}
