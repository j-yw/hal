package firecrackerhost

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"slices"
	"strconv"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
)

const minimalControlSupervisorConfigVersion = "jailer-runtime-owner-minimal-control-config-v1"

// A distinct private wire schema, not optional fields on the seven-role
// schema. Embedded fields reuse their data shapes, not their discriminator,
// validator or seven-config correlation digest.
type minimalControlSupervisorConfig struct {
	jailerRecoverySupervisorConfig
	Control minimalControlPublicConfig `json:"minimalControl"`
}

type minimalControlPublicConfig struct {
	Prelaunch                   map[string]string         `json:"prelaunch"`
	ControllerPublicKey         string                    `json:"controllerPublicKey"`
	ControllerKeyGeneration     string                    `json:"controllerKeyGeneration"`
	BootNonce                   string                    `json:"bootNonce"`
	PreparationDeadlineUnixNano int64                     `json:"preparationDeadlineUnixNano"`
	LaunchGrantID               string                    `json:"launchGrantId"`
	LaunchPolicyRevision        string                    `json:"launchPolicyRevision"`
	NetworkInterface            minimalL7NetworkInterface `json:"networkInterface"`
	StaticNetwork               [6]string                 `json:"staticNetwork"`
	Namespace                   minimalControlNamespaces  `json:"namespace"`
}

type minimalControlNamespaces struct {
	UserDevice    uint64 `json:"userDevice"`
	UserInode     uint64 `json:"userInode"`
	NetworkDevice uint64 `json:"networkDevice"`
	NetworkInode  uint64 `json:"networkInode"`
}

func decodeMinimalControlSupervisorConfig(payload []byte) (minimalControlSupervisorConfig, ed25519.PublicKey, error) {
	var config minimalControlSupervisorConfig
	if !boundedMinimalControlConfigJSON(payload) || json.Unmarshal(payload, &config) != nil {
		return config, nil, errL8RuntimeOwnerInvalid
	}
	canonical, err := json.Marshal(config)
	roles := append(jailerRecoverySupervisorRoles(), "minimal-controller-key")
	if err != nil || !bytes.Equal(canonical, payload) || config.Version != minimalControlSupervisorConfigVersion ||
		config.DaemonUID != 0 || !slices.Equal(config.Roles, roles) || validateJailerRecoveryCommonConfig(config.jailerRecoverySupervisorConfig) != nil {
		return minimalControlSupervisorConfig{}, nil, errL8RuntimeOwnerInvalid
	}
	c, j := config.Control, config.Job
	public, publicOK := minimalControlConfigBase64(c.ControllerPublicKey)
	nonce, nonceOK := minimalControlConfigBase64(c.BootNonce)
	revision, revisionErr := strconv.ParseUint(c.LaunchPolicyRevision, 10, 64)
	ns := c.Namespace
	if !publicOK || !nonceOK || c.PreparationDeadlineUnixNano <= 0 || !validL8RuntimeOwnerSafeID(c.LaunchGrantID) ||
		revisionErr != nil || revision == 0 || strconv.FormatUint(revision, 10) != c.LaunchPolicyRevision ||
		ns.UserDevice == 0 || ns.UserInode == 0 || ns.NetworkDevice == 0 || ns.NetworkInode == 0 ||
		ns.UserDevice == ns.NetworkDevice && ns.UserInode == ns.NetworkInode {
		return minimalControlSupervisorConfig{}, nil, errL8RuntimeOwnerInvalid
	}
	for name, expected := range map[string]string{"sandboxId": j.SandboxID, "executionId": j.ExecutionID, "workerId": j.WorkerID,
		"hostId": j.HostID, "runtimeId": j.RuntimeID, "runtimeGeneration": j.RuntimeGeneration, "imageDigest": "sha256-" + config.Rootfs.SHA256} {
		if c.Prelaunch[name] != expected {
			return minimalControlSupervisorConfig{}, nil, errL8RuntimeOwnerInvalid
		}
	}
	identity := session.Identity{Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		RuntimeID: j.RuntimeID, RuntimeGeneration: j.RuntimeGeneration, BootGeneration: c.Prelaunch["bootGeneration"],
		ImageGeneration: c.Prelaunch["imageGeneration"], ControllerKeyGeneration: c.ControllerKeyGeneration, GuestBootNonce: nonce}
	image, _ := hex.DecodeString(config.Rootfs.SHA256) // common validation checked its canonical digest
	copy(identity.ImageSHA256[:], image)
	// Shared prelaunch validation owns all 25 fields and excludes both late
	// generations. This is not comparison with the actual FC config or L7 owner.
	if !validMinimalControlNetworkShape(c) {
		return minimalControlSupervisorConfig{}, nil, errL8RuntimeOwnerInvalid
	}
	if _, err := minimalcontrol.RenderBootCommandLine(minimalL7BootFragment(c.StaticNetwork), identity, public[:], c.Prelaunch); err != nil {
		return minimalControlSupervisorConfig{}, nil, errL8RuntimeOwnerInvalid
	}
	return config, append(ed25519.PublicKey(nil), public[:]...), nil
}

// Syntax-only sealed projection checks. Actual descriptor/FC/namespace equality
// and retained L7 ownership remain unavailable at this byte-admission boundary.
func validMinimalControlNetworkShape(c minimalControlPublicConfig) bool {
	nic := c.NetworkInterface
	mac, err := net.ParseMAC(nic.GuestMAC)
	if nic.InterfaceID != "net1" || len(nic.HostDeviceName) > 15 || !validL8RuntimeOwnerSafeID(nic.HostDeviceName) ||
		nic.HostDeviceName == "." || nic.HostDeviceName == ".." || err != nil || len(mac) != 6 || mac.String() != nic.GuestMAC ||
		mac[0]&1 != 0 || bytes.Equal(mac, make([]byte, 6)) || c.StaticNetwork[0] != "eth0" {
		return false
	}
	boot, present, err := guestnetwork.ParseBootCommandLine(minimalL7BootFragment(c.StaticNetwork))
	return err == nil && present && ([6]string{boot.InterfaceName(), boot.IPv4Address(), boot.IPv4Gateway(),
		boot.IPv6Address(), boot.IPv6Gateway(), boot.ProxyURL()}) == c.StaticNetwork
}

func minimalControlConfigBase64(value string) ([32]byte, bool) {
	var out [32]byte
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(out) || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return out, false
	}
	copy(out[:], decoded)
	return out, out != ([32]byte{})
}

// The complete selected schema has at most three object/array levels. Count
// only delimiters outside JSON strings before allocating decoded collections.
func boundedMinimalControlConfigJSON(payload []byte) bool {
	if len(payload) == 0 || len(payload) > l8RuntimeOwnerSupervisorConfigLimit {
		return false
	}
	depth, quoted, escaped := 0, false, false
	for _, ch := range payload {
		if quoted {
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == '"' {
				quoted = false
			}
			continue
		}
		switch ch {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			if depth > 3 {
				return false
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return !quoted && depth == 0
}

// This callback-scoped result grants no runtime/store/readiness authority.
// Its signing-key storage must be cleared when the callback returns.
type minimalControlSupervisorAdmission struct {
	config        minimalControlSupervisorConfig
	configDigest  [32]byte
	controllerKey ed25519.PrivateKey
	// DESIGN/RED: the actual admission does not populate either handoff yet.
	borrowed [7]int
	recovery minimalControlRecoveryProjection
}

func unavailableMinimalControlSupervisor(*minimalControlSupervisorAdmission) error {
	// Full eight-config store correlation, sealed L7 projection and owned
	// controller composition have not been implemented. Do not launch.
	return errL8RuntimeOwnerInvalid
}
