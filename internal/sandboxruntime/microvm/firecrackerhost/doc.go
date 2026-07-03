// Package firecrackerhost provides the host-side adapter boundary for explicit
// Firecracker live boot integrations.
//
// The package is intentionally separate from the firecracker backend contract
// package. Default Hal paths do not construct this adapter; callers must inject
// it through firecracker.BackendOptions when live host behavior is explicitly
// selected.
package firecrackerhost
