package credentialhelper

import "fmt"

func opaqueString(name string) string {
	return "<credentialhelper." + name + ">"
}

func writeOpaque(state fmt.State, name string) {
	_, _ = fmt.Fprint(state, opaqueString(name))
}

// ExtensionRegistration and ExtensionRegistry predate liveValue and remain
// redacted, immutable registry metadata rather than live request authority.
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
