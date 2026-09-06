package firecrackerhost

import "context"

// Opaque same-owner callbacks, never a request-supplied boolean or UID. The
// production issuer is the selected Linux runtime's continuously retained store.
type jailerRecoveryAuthority struct {
	current  func(context.Context, string, string) error
	busy     func(context.Context, *strictJailerIdentityLease) error
	terminal func(context.Context, *strictJailerIdentityLease) error
}
