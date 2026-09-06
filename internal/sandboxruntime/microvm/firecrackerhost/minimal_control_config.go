package firecrackerhost

import "crypto/ed25519"

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

// This callback-scoped result grants no runtime/store/readiness authority.
// Its signing-key storage must be cleared when the callback returns.
type minimalControlSupervisorAdmission struct {
	config        minimalControlSupervisorConfig
	configDigest  [32]byte
	controllerKey ed25519.PrivateKey
}

func unavailableMinimalControlSupervisor(*minimalControlSupervisorAdmission) error {
	// Full eight-config store correlation, sealed L7 projection and owned
	// controller composition have not been implemented. Do not launch.
	return errL8RuntimeOwnerInvalid
}
