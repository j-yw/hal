// Package firecracker owns Firecracker-specific microVM backend code.
//
// Firecracker-specific config mapping, payload rendering, command planning,
// and backend behavior belong in this package. The backend-neutral microvm code
// in internal/sandboxruntime/microvm should keep only reusable microVM
// contracts and must not import this package for default construction.
//
// US-001 established the backend namespace. US-002 adds the pure configuration
// contract, US-003 adds path planning, US-004 adds payload rendering, US-005
// adds operation planning, US-006 adds process-boundary contracts, and US-007
// connects explicit live launch to the injected process boundary after boot
// files render. Later stories may add lifecycle behavior here behind fakeable
// tests and explicit injection.
package firecracker

// BackendID is the stable namespace for the Firecracker microVM backend.
const BackendID = "firecracker"
