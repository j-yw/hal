package firecrackerhost

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	l8RuntimeOwnerExecutableSupervise     = "supervise"
	l8RuntimeOwnerExecutableChildGate     = "child-gate"
	l8RuntimeOwnerSupervisorConfigVersion = "firecracker-runtime-owner-supervisor-config-v1"
	l8RuntimeOwnerSupervisorConfigLimit   = 32 << 10
)

type l8RuntimeOwnerDescriptorIdentityV1 struct {
	Kind   string `json:"kind"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Digest string `json:"digest"`
}

type l8RuntimeOwnerSupervisorConfigV1 struct {
	ContractVersion            string                                   `json:"contractVersion"`
	Seed                       sandboxruntime.JobCredentialIdentitySeed `json:"seed"`
	DaemonUID                  uint32                                   `json:"daemonUid"`
	NamespaceWrapperExecutable string                                   `json:"namespaceWrapperExecutable"`
	FirecrackerExecutable      string                                   `json:"firecrackerExecutable"`
	FirecrackerArguments       []string                                 `json:"firecrackerArguments"`
	Kernel                     l8RuntimeOwnerDescriptorIdentityV1       `json:"kernel"`
	Rootfs                     l8RuntimeOwnerDescriptorIdentityV1       `json:"rootfs"`
	InheritedDescriptorCount   uint16                                   `json:"inheritedDescriptorCount"`
}

type l8RuntimeOwnerExecutableOps struct {
	OpenFD        func(uintptr, string) (int, error)
	CloseFD       func(int) error
	RunSupervisor func([6]int) error
	RunChildGate  func([6]int) error
}

type l8RuntimeOwnerChildLaunchOps struct {
	LockOSThread   func()
	UnlockOSThread func()
	Start          func() error
	Wait           func() error
}

type l8RuntimeOwnerFDRemapOps struct {
	DuplicateAtLeast func(int, int) (int, error)
	Dup3             func(int, int, int) error
	Close            func(int) error
	CloseFrom        func(int) error
	Exec             func(string, []string, []string) error
}

type l8RuntimeOwnerChildGateOps struct {
	ArmPdeathsigAndVerifyParent func() error
	SendArmed                   func() error
	AwaitRelease                func() error
	RemapAndExec                func() error
}

type l8RuntimeOwnerKeyIdentity struct {
	Regular bool
	Mode    uint32
	UID     uint32
	Links   uint64
	Size    int64
	Device  uint64
	Inode   uint64
}

type l8RuntimeOwnerKeyFDOps struct {
	Stat  func(int) (l8RuntimeOwnerKeyIdentity, error)
	Pread func(int, []byte, int64) (int, error)
	Close func(int) error
}

func encodeL8RuntimeOwnerSupervisorConfig(config l8RuntimeOwnerSupervisorConfigV1) ([]byte, error) {
	if err := validateL8RuntimeOwnerSupervisorConfig(config); err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	payload, err := json.Marshal(config)
	if err != nil || len(payload) == 0 || len(payload) > l8RuntimeOwnerSupervisorConfigLimit {
		return nil, errL8RuntimeOwnerInvalid
	}
	return payload, nil
}

func decodeL8RuntimeOwnerSupervisorConfig(payload []byte) (l8RuntimeOwnerSupervisorConfigV1, error) {
	if len(payload) == 0 || len(payload) > l8RuntimeOwnerSupervisorConfigLimit || !l8RuntimeOwnerJSONNoDuplicateKeys(payload) ||
		!l8RuntimeOwnerSupervisorConfigJSONExact(payload) {
		return l8RuntimeOwnerSupervisorConfigV1{}, errL8RuntimeOwnerInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var config l8RuntimeOwnerSupervisorConfigV1
	if decoder.Decode(&config) != nil || decoder.Decode(&struct{}{}) != io.EOF || validateL8RuntimeOwnerSupervisorConfig(config) != nil {
		return l8RuntimeOwnerSupervisorConfigV1{}, errL8RuntimeOwnerInvalid
	}
	return config, nil
}

func l8RuntimeOwnerSupervisorConfigJSONExact(payload []byte) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil || len(object) != 9 {
		return false
	}
	stringFields := []string{"contractVersion", "namespaceWrapperExecutable", "firecrackerExecutable"}
	for _, name := range stringFields {
		var value string
		if raw, ok := object[name]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &value) != nil {
			return false
		}
	}
	var daemonUID uint32
	if raw, ok := object["daemonUid"]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &daemonUID) != nil {
		return false
	}
	var inherited uint16
	if raw, ok := object["inheritedDescriptorCount"]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &inherited) != nil {
		return false
	}
	for _, name := range []string{"seed", "kernel", "rootfs"} {
		raw, ok := object[name]
		trimmed := bytes.TrimSpace(raw)
		if !ok || len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
			return false
		}
	}
	raw, ok := object["firecrackerArguments"]
	trimmed := bytes.TrimSpace(raw)
	return ok && len(trimmed) >= 2 && trimmed[0] == '[' && trimmed[len(trimmed)-1] == ']'
}

func runPrivateL8RuntimeOwnerExecutableWithOps(arguments []string, ops l8RuntimeOwnerExecutableOps) int {
	if len(arguments) != 1 || (arguments[0] != l8RuntimeOwnerExecutableSupervise && arguments[0] != l8RuntimeOwnerExecutableChildGate) {
		return 127
	}
	if ops.OpenFD == nil || ops.CloseFD == nil {
		return 127
	}
	roles := []string{"control-socket", "owner-directory", "supervisor-config", "kernel-asset", "rootfs-asset", "owner-root-key"}
	opened := make([]int, 0, 6)
	for index := 0; index < 6; index++ {
		fd, err := ops.OpenFD(uintptr(index+3), roles[index])
		if err != nil {
			for i := len(opened) - 1; i >= 0; i-- {
				_ = ops.CloseFD(opened[i])
			}
			return 127
		}
		opened = append(opened, fd)
	}
	var fds [6]int
	copy(fds[:], opened)
	var runErr error
	if arguments[0] == l8RuntimeOwnerExecutableSupervise {
		if ops.RunSupervisor == nil {
			runErr = errL8RuntimeOwnerInvalid
		} else {
			runErr = ops.RunSupervisor(fds)
		}
	} else {
		if ops.RunChildGate == nil {
			runErr = errL8RuntimeOwnerInvalid
		} else {
			runErr = ops.RunChildGate(fds)
		}
	}
	for i := len(opened) - 1; i >= 0; i-- {
		_ = ops.CloseFD(opened[i])
	}
	if runErr != nil {
		return 127
	}
	return 0
}

func launchL8RuntimeOwnerChildOnRetainedThread(ops l8RuntimeOwnerChildLaunchOps) error {
	if ops.LockOSThread == nil || ops.UnlockOSThread == nil || ops.Start == nil || ops.Wait == nil {
		return errL8RuntimeOwnerInvalid
	}
	ops.LockOSThread()
	defer ops.UnlockOSThread()
	if err := ops.Start(); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	if err := ops.Wait(); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func remapAndExecL8RuntimeOwnerChild(config l8RuntimeOwnerSupervisorConfigV1, sources [4]int, ops l8RuntimeOwnerFDRemapOps) error {
	if ops.DuplicateAtLeast == nil || ops.Dup3 == nil || ops.Close == nil || ops.CloseFrom == nil || ops.Exec == nil {
		return errL8RuntimeOwnerInvalid
	}
	if err := validateL8RuntimeOwnerSupervisorConfig(config); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	temps := [4]int{-1, -1, -1, -1}
	defer func() {
		for _, temporary := range temps {
			if temporary >= 0 {
				_ = ops.Close(temporary)
			}
		}
	}()
	for index, source := range sources {
		temporary, err := ops.DuplicateAtLeast(source, 9)
		if err != nil || temporary < 9 {
			if temporary >= 0 {
				alreadyOwned := false
				for prior := 0; prior < index; prior++ {
					alreadyOwned = alreadyOwned || temps[prior] == temporary
				}
				if !alreadyOwned {
					_ = ops.Close(temporary)
				}
			}
			return errL8RuntimeOwnerInvalid
		}
		for prior := 0; prior < index; prior++ {
			if temps[prior] == temporary {
				return errL8RuntimeOwnerInvalid
			}
		}
		temps[index] = temporary
	}
	for index, temporary := range temps {
		if err := ops.Dup3(temporary, 3+index, 0); err != nil {
			return errL8RuntimeOwnerInvalid
		}
	}
	for index, temporary := range temps {
		temps[index] = -1
		if err := ops.Close(temporary); err != nil {
			return errL8RuntimeOwnerInvalid
		}
	}
	if err := ops.CloseFrom(7); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	argv := []string{
		config.NamespaceWrapperExecutable,
		"--preserve-credentials",
		"--keep-caps",
		"--user=/proc/self/fd/3",
		"--net=/proc/self/fd/4",
		"--",
		config.FirecrackerExecutable,
	}
	argv = append(argv, config.FirecrackerArguments...)
	if err := ops.Exec(config.NamespaceWrapperExecutable, argv, []string{}); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func runL8RuntimeOwnerChildGate(ops l8RuntimeOwnerChildGateOps) error {
	if ops.ArmPdeathsigAndVerifyParent == nil || ops.SendArmed == nil || ops.AwaitRelease == nil || ops.RemapAndExec == nil {
		return errL8RuntimeOwnerInvalid
	}
	if err := ops.ArmPdeathsigAndVerifyParent(); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	if err := ops.SendArmed(); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	if err := ops.AwaitRelease(); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	if err := ops.RemapAndExec(); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func loadL8RuntimeOwnerStableKeyFD(fd int, uid uint32, ops l8RuntimeOwnerKeyFDOps) (key []byte, err error) {
	if ops.Stat == nil || ops.Pread == nil || ops.Close == nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	defer func() {
		if ops.Close(fd) != nil {
			key = nil
			err = errL8RuntimeOwnerInvalid
		}
	}()
	first, statErr := ops.Stat(fd)
	if statErr != nil || !validL8RuntimeOwnerKeyIdentity(first, uid) {
		return nil, errL8RuntimeOwnerInvalid
	}
	buf := make([]byte, 32)
	read, readErr := ops.Pread(fd, buf, 0)
	if readErr != nil || read != 32 {
		return nil, errL8RuntimeOwnerInvalid
	}
	second, statErr := ops.Stat(fd)
	if statErr != nil || second != first {
		return nil, errL8RuntimeOwnerInvalid
	}
	return buf, nil
}

func validL8RuntimeOwnerKeyIdentity(identity l8RuntimeOwnerKeyIdentity, uid uint32) bool {
	return identity.Regular && identity.Mode == 0o600 && identity.UID == uid && identity.Links == 1 && identity.Size == 32
}

func validateL8RuntimeOwnerSupervisorConfig(config l8RuntimeOwnerSupervisorConfigV1) error {
	if config.ContractVersion != l8RuntimeOwnerSupervisorConfigVersion ||
		sandboxruntime.ValidateJobCredentialIdentitySeed(config.Seed) != nil ||
		!l8RuntimeOwnerAbsolutePath(config.NamespaceWrapperExecutable) ||
		!l8RuntimeOwnerAbsolutePath(config.FirecrackerExecutable) ||
		config.InheritedDescriptorCount != 2 {
		return errL8RuntimeOwnerInvalid
	}
	if config.Kernel.Kind != "kernel" || config.Rootfs.Kind != "rootfs" ||
		!validL8RuntimeOwnerAssetDigest(config.Kernel.Digest) || !validL8RuntimeOwnerAssetDigest(config.Rootfs.Digest) ||
		(config.Kernel.Device == config.Rootfs.Device && config.Kernel.Inode == config.Rootfs.Inode) {
		return errL8RuntimeOwnerInvalid
	}
	for _, argument := range config.FirecrackerArguments {
		if argument == "" || strings.ContainsAny(argument, "\x00\r\n") {
			return errL8RuntimeOwnerInvalid
		}
	}
	return nil
}

func l8RuntimeOwnerAbsolutePath(value string) bool {
	return value != "" && filepath.IsAbs(value) && filepath.Clean(value) == value && !strings.ContainsAny(value, "\x00\r\n")
}

func validL8RuntimeOwnerAssetDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

func l8RuntimeOwnerJSONNoDuplicateKeys(payload []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if !l8RuntimeOwnerJSONNoDuplicateValue(decoder) {
		return false
	}
	if _, err := decoder.Token(); err != io.EOF {
		return false
	}
	return true
}

func l8RuntimeOwnerJSONNoDuplicateValue(decoder *json.Decoder) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return token != nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			canonicalName := strings.ToLower(name)
			if err != nil || !ok || seen[canonicalName] {
				return false
			}
			seen[canonicalName] = true
			if !l8RuntimeOwnerJSONNoDuplicateValue(decoder) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for decoder.More() {
			if !l8RuntimeOwnerJSONNoDuplicateValue(decoder) {
				return false
			}
		}
		end, err := decoder.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}

// RunPrivateL8RuntimeOwnerExecutable is the single internal entry point for
// the isolated runtime-owner executable. It is not a default runtime factory.
func RunPrivateL8RuntimeOwnerExecutable(arguments []string, file func(uintptr, string) *os.File) int {
	return runPrivateL8RuntimeOwnerExecutable(arguments, file)
}
