package minimalcontrol

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

const (
	MaximumBootCommandLineBytes = 4096
	prelaunchDomain             = "hal/guest-agent-minimal-v1/prelaunch-binding/v1\x00"
)

// BootConfig holds immutable public pins, not live runtime authority. Its
// unexported state cannot be minted by unmarshalling a descriptor or receipt.
type BootConfig struct {
	identity        session.Identity
	controllerKey   [ed25519.PublicKeySize]byte
	prelaunchDigest [sha256.Size]byte
	valid           bool
}

var bootKeys = []string{
	"profile", "controller_key", "controller_key_generation", "boot_nonce",
	"runtime_id", "runtime_generation", "boot_generation", "image_generation",
	"image_sha256", "prelaunch_binding_sha256",
}

// ParseBootCommandLine never normalizes a selected namespace into acceptance
// or absence. The limit includes the optional terminal /proc/cmdline newline.
func ParseBootCommandLine(line string) (BootConfig, bool, error) {
	if len(line) > MaximumBootCommandLineBytes || strings.ContainsRune(line, '\x00') {
		return BootConfig{}, false, ErrInvalid
	}
	for _, ch := range strings.TrimSuffix(line, "\n") {
		if ch < ' ' && ch != '\t' || ch == 0x7f {
			return BootConfig{}, false, ErrInvalid
		}
	}
	values := make(map[string]string, len(bootKeys))
	for _, token := range strings.Fields(line) {
		key, value, assigned := strings.Cut(token, "=")
		probe := strings.ToLower(strings.Trim(key, "\"'"))
		if probe != "hal_minimal" && !strings.HasPrefix(probe, "hal_minimal_") {
			continue
		}
		if key != probe || !assigned || value == "" || !strings.HasPrefix(key, "hal_minimal_") {
			return BootConfig{}, true, ErrInvalid
		}
		name := strings.TrimPrefix(key, "hal_minimal_")
		if !slices.Contains(bootKeys, name) {
			return BootConfig{}, true, ErrInvalid
		}
		if _, duplicate := values[name]; duplicate {
			return BootConfig{}, true, ErrInvalid
		}
		values[name] = value
	}
	if len(values) == 0 {
		return BootConfig{}, false, nil
	}
	if len(values) != len(bootKeys) || values["profile"] != ProtocolVersion {
		return BootConfig{}, true, ErrInvalid
	}
	boot := BootConfig{identity: session.Identity{
		Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		ControllerKeyGeneration: values["controller_key_generation"], RuntimeID: values["runtime_id"],
		RuntimeGeneration: values["runtime_generation"], BootGeneration: values["boot_generation"], ImageGeneration: values["image_generation"],
	}}
	if !decodeBootBase64(values["controller_key"], &boot.controllerKey) || !decodeBootBase64(values["boot_nonce"], &boot.identity.GuestBootNonce) ||
		!decodeBootHex(values["image_sha256"], &boot.identity.ImageSHA256) || !decodeBootHex(values["prelaunch_binding_sha256"], &boot.prelaunchDigest) ||
		!validPrelaunchIdentity(boot.identity) {
		return BootConfig{}, true, ErrInvalid
	}
	boot.valid = true
	return boot, true, nil
}

func decodeBootBase64(value string, out *[32]byte) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(out) || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return false
	}
	copy(out[:], decoded)
	return *out != ([32]byte{})
}

func decodeBootHex(value string, out *[32]byte) bool {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(out) || hex.EncodeToString(decoded) != value {
		return false
	}
	copy(out[:], decoded)
	return *out != ([32]byte{})
}

func validPrelaunchIdentity(identity session.Identity) bool {
	if identity.Channel != session.ChannelControl || identity.GuestCID != session.GuestCID || identity.GuestPort != session.ControlPort ||
		identity.GuestBootNonce == ([32]byte{}) || identity.ImageSHA256 == ([32]byte{}) ||
		identity.FirecrackerProcessGeneration != "" || identity.VsockGeneration != "" ||
		identity.JobGeneration != "" || identity.ActivationGeneration != "" || identity.RelayGeneration != "" {
		return false
	}
	for _, value := range []string{identity.ControllerKeyGeneration, identity.RuntimeID, identity.RuntimeGeneration, identity.BootGeneration, identity.ImageGeneration} {
		if !safeID(value) {
			return false
		}
	}
	return true
}

// RenderBootCommandLine derives pins from the caller's independently trusted
// prelaunch tuple. It does not establish that tuple's authority or currentness.
// One byte is reserved for Linux's appended /proc/cmdline newline.
func RenderBootCommandLine(base string, identity session.Identity, publicKey ed25519.PublicKey, fields map[string]string) (string, error) {
	if len(fields) != 25 || len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalid
	}
	fields = maps.Clone(fields)
	publicKey = append(ed25519.PublicKey(nil), publicKey...)
	if _, present, err := ParseBootCommandLine(base); err != nil || present || strings.ContainsRune(base, '\n') ||
		!validPrelaunchIdentity(identity) || bytes.Equal(publicKey, make([]byte, ed25519.PublicKeySize)) ||
		validateBindingFields(identity, fields, true) != nil {
		return "", ErrInvalid
	}
	digest := prelaunchBindingDigest(fields)
	values := []string{
		ProtocolVersion, base64.RawURLEncoding.EncodeToString(publicKey), identity.ControllerKeyGeneration,
		base64.RawURLEncoding.EncodeToString(identity.GuestBootNonce[:]), identity.RuntimeID, identity.RuntimeGeneration,
		identity.BootGeneration, identity.ImageGeneration, hex.EncodeToString(identity.ImageSHA256[:]), hex.EncodeToString(digest[:]),
	}
	var rendered strings.Builder
	rendered.WriteString(base)
	for index, key := range bootKeys {
		if rendered.Len() != 0 {
			rendered.WriteByte(' ')
		}
		rendered.WriteString("hal_minimal_" + key + "=" + values[index])
	}
	if rendered.Len()+1 > MaximumBootCommandLineBytes {
		return "", ErrInvalid
	}
	return rendered.String(), nil
}

// Input is already validated; omitting the two late keys yields the same
// digest from either the 25-field prelaunch or 27-field completed tuple.
func prelaunchBindingDigest(fields map[string]string) [32]byte {
	var canonical bytes.Buffer
	canonical.WriteString(prelaunchDomain)
	writeUint16(&canonical, 25)
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		if lateBindingField(key) {
			continue
		}
		for _, value := range []string{key, fields[key]} {
			writeUint16(&canonical, uint16(len(value)))
			canonical.WriteString(value)
		}
	}
	return sha256.Sum256(canonical.Bytes())
}

type bootstrapPrelude struct {
	Binding         map[string]string `json:"binding"`
	Operation       string            `json:"operation"`
	ProtocolVersion string            `json:"protocolVersion"`
}

// BootstrapPrelude is public provisional input, not authenticated readiness.
// The controller must construct this Binding using the actual late identity.
func (binding Binding) BootstrapPrelude() ([]byte, error) {
	if binding.fields == nil {
		return nil, ErrInvalid
	}
	return json.Marshal(bootstrapPrelude{Binding: binding.fields, Operation: "bootstrap", ProtocolVersion: ProtocolVersion})
}

func (boot BootConfig) complete(payload []byte) (session.Identity, Binding, error) {
	var request bootstrapPrelude
	if !boot.valid || !boundedJSON(payload) || json.Unmarshal(payload, &request) != nil {
		return session.Identity{}, Binding{}, ErrInvalid
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(canonical, payload) || request.Operation != "bootstrap" || request.ProtocolVersion != ProtocolVersion {
		return session.Identity{}, Binding{}, ErrInvalid
	}
	identity := boot.identity
	identity.FirecrackerProcessGeneration = request.Binding["processGeneration"]
	identity.VsockGeneration = request.Binding["vsockGeneration"]
	binding, err := NewBinding(identity, request.Binding)
	if err != nil || prelaunchBindingDigest(binding.fields) != boot.prelaunchDigest {
		return session.Identity{}, Binding{}, ErrInvalid
	}
	return identity, binding, nil
}
