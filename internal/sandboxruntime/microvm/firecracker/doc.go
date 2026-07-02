// Package firecracker owns Firecracker-specific microVM backend code.
//
// Firecracker-specific config mapping, payload rendering, command planning,
// and backend behavior belong in this package. The backend-neutral microvm code
// in internal/sandboxruntime/microvm should keep only reusable microVM
// contracts and must not import this package for default construction.
//
// US-001 intentionally exposes only the backend namespace. Later stories may
// add configuration, path, payload, process-boundary, and backend
// implementations here behind fakeable tests and explicit injection.
package firecracker

// BackendID is the stable namespace for the Firecracker microVM backend.
const BackendID = "firecracker"
