package sandboxruntime

import "context"

// MinimalLaunchWorkerInput is memory-only input from the original authenticated
// worker entry. Credentials.Identity is unset until actual runtime preparation;
// its remaining fields are original intent, not credential authorization.
// Binding must clone owned command/target/intent data and borrow only the
// original bounded I/O capabilities. This input is never a durable record.
type MinimalLaunchWorkerInput struct {
	Principal   AuthenticatedWorkerPrincipal
	Exec        ExecRequest
	Credentials JobCredentialAdmissionRequest
	RequestKey  string
}

// MinimalLaunchJournal is the staged admission/readback surface of the SAME
// original worker-entry journal. Its implementation validates the original
// reservation, entry and held durable state lock; it cannot be issued from IDs.
// This admission-only surface authorizes no preparation, work, credential,
// persistence, Commit or receipt. Those require the later full typed effect
// contract on the same retained implementation, not another journal.
type MinimalLaunchJournal interface {
	CheckMinimalLaunchReservation(context.Context, *MinimalLaunchReservation) error
}
