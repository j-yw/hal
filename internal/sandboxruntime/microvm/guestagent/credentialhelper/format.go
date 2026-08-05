package credentialhelper

import "fmt"

func opaqueString(name string) string {
	return "<credentialhelper." + name + ">"
}

func writeOpaque(state fmt.State, name string) {
	_, _ = fmt.Fprint(state, opaqueString(name))
}

func (ExtensionRegistration) String() string   { return opaqueString("ExtensionRegistration") }
func (ExtensionRegistration) GoString() string { return opaqueString("ExtensionRegistration") }
func (ExtensionRegistration) Format(state fmt.State, _ rune) {
	writeOpaque(state, "ExtensionRegistration")
}
func (ExtensionRegistration) MarshalJSON() ([]byte, error) { return nil, ErrExtensionSerialization }
func (ExtensionRegistration) MarshalText() ([]byte, error) { return nil, ErrExtensionSerialization }

func (*ExtensionRegistry) String() string                 { return opaqueString("ExtensionRegistry") }
func (*ExtensionRegistry) GoString() string               { return opaqueString("ExtensionRegistry") }
func (*ExtensionRegistry) Format(state fmt.State, _ rune) { writeOpaque(state, "ExtensionRegistry") }
func (*ExtensionRegistry) MarshalJSON() ([]byte, error)   { return nil, ErrExtensionSerialization }
func (*ExtensionRegistry) MarshalText() ([]byte, error)   { return nil, ErrExtensionSerialization }

func (ExtensionOpenRequest) String() string   { return opaqueString("ExtensionOpenRequest") }
func (ExtensionOpenRequest) GoString() string { return opaqueString("ExtensionOpenRequest") }
func (ExtensionOpenRequest) Format(state fmt.State, _ rune) {
	writeOpaque(state, "ExtensionOpenRequest")
}
func (ExtensionOpenRequest) MarshalJSON() ([]byte, error) { return nil, ErrExtensionSerialization }
func (ExtensionOpenRequest) MarshalText() ([]byte, error) { return nil, ErrExtensionSerialization }

func (ExtensionPrepareRequest) String() string   { return opaqueString("ExtensionPrepareRequest") }
func (ExtensionPrepareRequest) GoString() string { return opaqueString("ExtensionPrepareRequest") }
func (ExtensionPrepareRequest) Format(state fmt.State, _ rune) {
	writeOpaque(state, "ExtensionPrepareRequest")
}
func (ExtensionPrepareRequest) MarshalJSON() ([]byte, error) { return nil, ErrExtensionSerialization }
func (ExtensionPrepareRequest) MarshalText() ([]byte, error) { return nil, ErrExtensionSerialization }

func (ExtensionPrepareResult) String() string   { return opaqueString("ExtensionPrepareResult") }
func (ExtensionPrepareResult) GoString() string { return opaqueString("ExtensionPrepareResult") }
func (ExtensionPrepareResult) Format(state fmt.State, _ rune) {
	writeOpaque(state, "ExtensionPrepareResult")
}
func (ExtensionPrepareResult) MarshalJSON() ([]byte, error) { return nil, ErrExtensionSerialization }
func (ExtensionPrepareResult) MarshalText() ([]byte, error) { return nil, ErrExtensionSerialization }

func (ExtensionExecRequest) String() string   { return opaqueString("ExtensionExecRequest") }
func (ExtensionExecRequest) GoString() string { return opaqueString("ExtensionExecRequest") }
func (ExtensionExecRequest) Format(state fmt.State, _ rune) {
	writeOpaque(state, "ExtensionExecRequest")
}
func (ExtensionExecRequest) MarshalJSON() ([]byte, error) { return nil, ErrExtensionSerialization }
func (ExtensionExecRequest) MarshalText() ([]byte, error) { return nil, ErrExtensionSerialization }

func (ExtensionExecResult) String() string                 { return opaqueString("ExtensionExecResult") }
func (ExtensionExecResult) GoString() string               { return opaqueString("ExtensionExecResult") }
func (ExtensionExecResult) Format(state fmt.State, _ rune) { writeOpaque(state, "ExtensionExecResult") }
func (ExtensionExecResult) MarshalJSON() ([]byte, error)   { return nil, ErrExtensionSerialization }
func (ExtensionExecResult) MarshalText() ([]byte, error)   { return nil, ErrExtensionSerialization }

func (ExtensionRenewRequest) String() string   { return opaqueString("ExtensionRenewRequest") }
func (ExtensionRenewRequest) GoString() string { return opaqueString("ExtensionRenewRequest") }
func (ExtensionRenewRequest) Format(state fmt.State, _ rune) {
	writeOpaque(state, "ExtensionRenewRequest")
}
func (ExtensionRenewRequest) MarshalJSON() ([]byte, error) { return nil, ErrExtensionSerialization }
func (ExtensionRenewRequest) MarshalText() ([]byte, error) { return nil, ErrExtensionSerialization }

func (ExtensionRevokeRequest) String() string   { return opaqueString("ExtensionRevokeRequest") }
func (ExtensionRevokeRequest) GoString() string { return opaqueString("ExtensionRevokeRequest") }
func (ExtensionRevokeRequest) Format(state fmt.State, _ rune) {
	writeOpaque(state, "ExtensionRevokeRequest")
}
func (ExtensionRevokeRequest) MarshalJSON() ([]byte, error) { return nil, ErrExtensionSerialization }
func (ExtensionRevokeRequest) MarshalText() ([]byte, error) { return nil, ErrExtensionSerialization }

func (SSHAgentEndpointRequest) String() string   { return opaqueString("SSHAgentEndpointRequest") }
func (SSHAgentEndpointRequest) GoString() string { return opaqueString("SSHAgentEndpointRequest") }
func (SSHAgentEndpointRequest) Format(state fmt.State, _ rune) {
	writeOpaque(state, "SSHAgentEndpointRequest")
}
func (SSHAgentEndpointRequest) MarshalJSON() ([]byte, error) { return nil, ErrExtensionSerialization }
func (SSHAgentEndpointRequest) MarshalText() ([]byte, error) { return nil, ErrExtensionSerialization }

func (SSHAcceptedPublication) String() string   { return opaqueString("SSHAcceptedPublication") }
func (SSHAcceptedPublication) GoString() string { return opaqueString("SSHAcceptedPublication") }
func (SSHAcceptedPublication) Format(state fmt.State, _ rune) {
	writeOpaque(state, "SSHAcceptedPublication")
}
func (SSHAcceptedPublication) MarshalJSON() ([]byte, error) { return nil, ErrExtensionSerialization }
func (SSHAcceptedPublication) MarshalText() ([]byte, error) { return nil, ErrExtensionSerialization }

func (execBindingCapability) String() string   { return opaqueString("ExecBindingCapability") }
func (execBindingCapability) GoString() string { return opaqueString("ExecBindingCapability") }
func (execBindingCapability) Format(state fmt.State, _ rune) {
	writeOpaque(state, "ExecBindingCapability")
}
func (execBindingCapability) MarshalJSON() ([]byte, error) { return nil, ErrExtensionSerialization }
func (execBindingCapability) MarshalText() ([]byte, error) { return nil, ErrExtensionSerialization }

func (ExtensionCleanupResult) String() string   { return opaqueString("ExtensionCleanupResult") }
func (ExtensionCleanupResult) GoString() string { return opaqueString("ExtensionCleanupResult") }
func (ExtensionCleanupResult) Format(state fmt.State, _ rune) {
	writeOpaque(state, "ExtensionCleanupResult")
}
func (ExtensionCleanupResult) MarshalJSON() ([]byte, error) { return nil, ErrExtensionSerialization }
func (ExtensionCleanupResult) MarshalText() ([]byte, error) { return nil, ErrExtensionSerialization }

func (SSHIOResult) String() string                 { return opaqueString("SSHIOResult") }
func (SSHIOResult) GoString() string               { return opaqueString("SSHIOResult") }
func (SSHIOResult) Format(state fmt.State, _ rune) { writeOpaque(state, "SSHIOResult") }
func (SSHIOResult) MarshalJSON() ([]byte, error)   { return nil, ErrExtensionSerialization }
func (SSHIOResult) MarshalText() ([]byte, error)   { return nil, ErrExtensionSerialization }
