// Package turso implements the cloud.Store interface backed by Turso (libSQL/SQLite).
package turso

import "github.com/jywlabs/hal/internal/cloud"

// schemaStatements returns all DDL statements in dependency order.
// Turso uses SQLite-compatible DDL, so we reuse the domain-defined schemas
// from the cloud package directly.
func schemaStatements() []string {
	return []string{
		cloud.RunsSchema,
		cloud.RunsQueueIndex,
		cloud.AttemptsSchema,
		cloud.AttemptsRunIDIndex,
		cloud.AttemptsStatusIndex,
		cloud.AttemptsLeaseIndex,
		cloud.AttemptsOneActiveIndex,
		cloud.EventsSchema,
		cloud.EventsRunIDCreatedAtIndex,
		cloud.EventsPreventUpdate,
		cloud.EventsPreventDelete,
		cloud.IdempotencyKeysSchema,
		cloud.AuthProfilesSchema,
		cloud.AuthProfileLocksSchema,
		cloud.AuthProfileLocksLeaseIndex,
		cloud.AuthProfileLocksOneActiveIndex,
		cloud.RunStateSnapshotsSchema,
		cloud.RunStateSnapshotsRunVersionUniqueIndex,
		cloud.RunStateSnapshotsRunIDCreatedAtIndex,
	}
}
