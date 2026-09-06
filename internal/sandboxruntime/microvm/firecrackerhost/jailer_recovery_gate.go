package firecrackerhost

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

const jailerRecoveryGateRole = "jailer-child-gate-v1"
const jailerRecoveryGateConfigLimit = 32 << 10

type jailerRecoveryMountedExecutable struct {
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type jailerRecoveryGateConfig struct {
	Version         string                          `json:"version"`
	ParentPID       uint32                          `json:"parentPid"`
	ParentStartTime uint64                          `json:"parentStartTime"`
	Jailer          jailerRecoveryMountedExecutable `json:"jailer"`
	Firecracker     jailerRecoveryMountedExecutable `json:"firecracker"`
	Args            []string                        `json:"args"`
}

func decodeJailerRecoveryGateConfig(payload []byte) (jailerRecoveryGateConfig, error) {
	var config jailerRecoveryGateConfig
	if len(payload) == 0 || len(payload) > jailerRecoveryGateConfigLimit || json.Unmarshal(payload, &config) != nil {
		return jailerRecoveryGateConfig{}, errL8RuntimeOwnerInvalid
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, payload) || validateJailerRecoveryGateConfig(config) != nil {
		return jailerRecoveryGateConfig{}, errL8RuntimeOwnerInvalid
	}
	return config, nil
}

func validateJailerRecoveryGateConfig(config jailerRecoveryGateConfig) error {
	if config.Version != jailerRecoveryGateRole || config.ParentPID <= 1 || config.ParentStartTime == 0 ||
		config.Jailer.Path == config.Firecracker.Path || config.Jailer.SHA256 == config.Firecracker.SHA256 ||
		config.Jailer.Device == config.Firecracker.Device && config.Jailer.Inode == config.Firecracker.Inode {
		return errL8RuntimeOwnerInvalid
	}
	for _, file := range []jailerRecoveryMountedExecutable{config.Jailer, config.Firecracker} {
		if !filepathIsCleanAbsolute(file.Path) || cleanupFilesystemRoot(file.Path) || file.Device == 0 || file.Inode == 0 ||
			file.Size <= 0 || file.Size > maxStrictJailerExecutableBytes || !validJailerStagingDigest(file.SHA256) {
			return errL8RuntimeOwnerInvalid
		}
	}
	command, err := parseStrictJailerCommand(firecracker.ProcessRunnerStartRequest{Executable: config.Jailer.Path, Args: config.Args})
	if err != nil || command.firecrackerPath != config.Firecracker.Path {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

type jailerRecoveryGateOps struct {
	verifyParent  func() error
	verifyMounted func(jailerRecoveryMountedExecutable) error
	sendArmed     func() error
	awaitRelease  func() error
	closeFiles    func() error
	exec          func(string, []string) error
}

func runJailerRecoveryGate(ctx context.Context, config jailerRecoveryGateConfig, ops jailerRecoveryGateOps) error {
	if ctx == nil || validateJailerRecoveryGateConfig(config) != nil || ops.verifyParent == nil || ops.verifyMounted == nil ||
		ops.sendArmed == nil || ops.awaitRelease == nil || ops.closeFiles == nil || ops.exec == nil {
		return errL8RuntimeOwnerInvalid
	}
	// Recheck the actual parent and mounted bytes after the potentially blocking
	// release barrier. Only the final exec consumes the validated argv. On every
	// earlier failure the outer executable dispatcher closes inherited handles.
	steps := []func() error{
		ops.verifyParent,
		func() error { return ops.verifyMounted(config.Jailer) },
		func() error { return ops.verifyMounted(config.Firecracker) },
		ops.sendArmed, ops.awaitRelease, ops.verifyParent,
		func() error { return ops.verifyMounted(config.Jailer) },
		func() error { return ops.verifyMounted(config.Firecracker) },
		ops.closeFiles,
		func() error {
			return ops.exec(config.Jailer.Path, append([]string{config.Jailer.Path}, config.Args...))
		},
	}
	for _, step := range steps {
		if ctx.Err() != nil || step() != nil {
			return errL8RuntimeOwnerInvalid
		}
	}
	return nil
}
