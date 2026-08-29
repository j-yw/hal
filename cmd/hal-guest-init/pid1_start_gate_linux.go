//go:build linux

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/l8composition"
	"golang.org/x/sys/unix"
)

// pid1StartGateExpectedFDNumber is PID1 FD 15. The syscall-policy table lists
// that slot as Closed; this optional D7 channel occupies it when a sealed
// anonymous memfd is inherited.
const pid1StartGateExpectedFDNumber = 15

const pid1StartGateExpectedMaxBytes = 32 << 10

const pid1StartGateRequiredSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE

var errPID1StartGateExpectedInvalid = errors.New("L8 PID1 start-gate expected digest channel is invalid")

// pid1StartGateExpectedFD is the inherited descriptor inspected for sealed
// expected digests. Tests replace it; production keeps FD 15.
var pid1StartGateExpectedFD = pid1StartGateExpectedFDNumber

// pid1StartGateSealedFacts is the JSON subset of
// assetbuild.L8ProcessCompositionFacts copied into PID1StartGateExpected.
type pid1StartGateSealedFacts struct {
	HelperDescriptorSHA256 string `json:"helperDescriptorSha256"`
	ClientDescriptorSHA256 string `json:"clientDescriptorSha256"`
	CompositionSHA256      string `json:"compositionSha256"`
}

// loadPID1StartGateExpected snapshots helper, client, and composition digests
// from a sealed inherited anonymous memfd. Missing or unsigned descriptors
// stay absent. Invalid sealed payloads fail closed.
func loadPID1StartGateExpected() (l8composition.PID1StartGateExpected, bool, error) {
	payload, present, err := readPID1StartGateSealedFD(pid1StartGateExpectedFD)
	if err != nil {
		return l8composition.PID1StartGateExpected{}, false, err
	}
	if !present {
		return l8composition.PID1StartGateExpected{}, false, nil
	}
	expected, err := decodePID1StartGateExpected(payload)
	if err != nil {
		return l8composition.PID1StartGateExpected{}, false, err
	}
	return expected, true, nil
}

// releasePID1AgentStartGate admits helper-then-client descriptors before the
// L7 child start. Missing sealed expected leaves the L7 supervisor path;
// a claimed expected without authenticated descriptors fails closed.
func releasePID1AgentStartGate() int {
	expected, present, err := loadPID1StartGateExpected()
	if err != nil {
		return 127
	}
	if !present {
		return 0
	}
	if _, err := l8composition.NewPID1StartGateState(expected); err != nil {
		return 127
	}
	return 127
}

// admitPID1StartGate is the exact helper-then-client start-gate. Tests inject
// sealed expected plus descriptors; PID1 never constructs helper or client.
func admitPID1StartGate(
	expected l8composition.PID1StartGateExpected,
	helper l8composition.ProcessDescriptor,
	client l8composition.ProcessDescriptor,
) int {
	state, err := l8composition.NewPID1StartGateState(expected)
	if err != nil {
		return 127
	}
	decision, err := state.AcceptHelperDescriptor(helper)
	if err != nil || decision != l8composition.PID1StartGateDecisionContinue {
		return 127
	}
	decision, err = state.AcceptClientDescriptor(client)
	if err != nil || decision != l8composition.PID1StartGateDecisionRelease {
		return 127
	}
	return 0
}

func readPID1StartGateSealedFD(fd int) ([]byte, bool, error) {
	var stat unix.Stat_t
	flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	access, accessErr := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	seals, sealErr := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	if unix.Fstat(fd, &stat) != nil || flagErr != nil || accessErr != nil || sealErr != nil {
		return nil, false, nil
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 0 || flags&unix.FD_CLOEXEC == 0 ||
		access&unix.O_ACCMODE == unix.O_WRONLY || seals != pid1StartGateRequiredSeals || stat.Size < 0 {
		return nil, false, nil
	}
	if stat.Size == 0 {
		return nil, false, nil
	}
	if stat.Size > pid1StartGateExpectedMaxBytes {
		return nil, false, errPID1StartGateExpectedInvalid
	}
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, false, nil
	}
	defer func() { _ = unix.Close(dup) }()
	payload := make([]byte, stat.Size)
	read, err := unix.Pread(dup, payload, 0)
	if err != nil || int64(read) != stat.Size {
		return nil, false, errPID1StartGateExpectedInvalid
	}
	return payload, true, nil
}

func decodePID1StartGateExpected(payload []byte) (l8composition.PID1StartGateExpected, error) {
	var expected l8composition.PID1StartGateExpected
	if len(payload) == 0 || len(payload) > pid1StartGateExpectedMaxBytes {
		return expected, errPID1StartGateExpectedInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var facts pid1StartGateSealedFacts
	if decoder.Decode(&facts) != nil || decoder.More() {
		return expected, errPID1StartGateExpectedInvalid
	}
	helper, err := decodePID1StartGateDigest(facts.HelperDescriptorSHA256)
	if err != nil {
		return expected, err
	}
	client, err := decodePID1StartGateDigest(facts.ClientDescriptorSHA256)
	if err != nil {
		return expected, err
	}
	composition, err := decodePID1StartGateDigest(facts.CompositionSHA256)
	if err != nil {
		return expected, err
	}
	if helper == client {
		return expected, errPID1StartGateExpectedInvalid
	}
	expected.HelperDescriptorSHA256 = helper
	expected.ClientDescriptorSHA256 = client
	expected.CompositionSHA256 = composition
	return expected, nil
}

func decodePID1StartGateDigest(value string) ([32]byte, error) {
	var digest [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) || hex.EncodeToString(decoded) != value {
		return digest, errPID1StartGateExpectedInvalid
	}
	copy(digest[:], decoded)
	if digest == [32]byte{} {
		return digest, errPID1StartGateExpectedInvalid
	}
	return digest, nil
}
