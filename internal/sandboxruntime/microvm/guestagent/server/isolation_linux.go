//go:build linux

package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

const maximumLinuxSelfStatusBytes int64 = 64 << 10

var errLinuxIsolationUnverified = errors.New("guest process isolation is unverified")

type linuxIsolationVerifier struct {
	process LinuxProcessIsolationBoundary
	network NetworkIsolationVerifier
}

type liveLinuxProcessIsolationBoundary struct{}

// NewLinuxIsolationVerifier returns a verifier for the exact current process.
func NewLinuxIsolationVerifier(options LinuxIsolationVerifierOptions) (IsolationVerifier, error) {
	process := options.ProcessBoundary
	if !configuredDependency(process) {
		process = liveLinuxProcessIsolationBoundary{}
	}
	return &linuxIsolationVerifier{process: process, network: options.NetworkVerifier}, nil
}

func (verifier *linuxIsolationVerifier) VerifyIsolation(ctx context.Context, _ guestagent.IsolationProofRequest) (IsolationProofResult, error) {
	if verifier == nil || !configuredDependency(verifier.process) {
		return IsolationProofResult{}, errLinuxIsolationUnverified
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return IsolationProofResult{}, err
	}
	status, err := verifier.process.ReadSelfStatus(ctx, maximumLinuxSelfStatusBytes)
	if err != nil || !linuxSelfStatusIsolated(status, maximumLinuxSelfStatusBytes) {
		return IsolationProofResult{}, errLinuxIsolationUnverified
	}
	if err := ctx.Err(); err != nil {
		return IsolationProofResult{}, err
	}
	groups, err := verifier.process.SupplementaryGroups(ctx)
	if err != nil || len(groups) != 0 {
		return IsolationProofResult{}, errLinuxIsolationUnverified
	}
	if err := ctx.Err(); err != nil {
		return IsolationProofResult{}, err
	}
	rawSocketErr := verifier.process.AttemptRawPacketSocket(ctx)
	if !errors.Is(rawSocketErr, unix.EPERM) && !errors.Is(rawSocketErr, unix.EACCES) {
		return IsolationProofResult{}, errLinuxIsolationUnverified
	}
	result := IsolationProofResult{
		RestrictedIdentity:         true,
		CapabilitiesCleared:        true,
		NoNewPrivileges:            true,
		SupplementaryGroupsCleared: true,
		RawPacketSocketDenied:      true,
		Network: NetworkIsolationProofResult{
			Status: guestagent.IsolationProofStatusUnavailable,
		},
	}
	if !configuredDependency(verifier.network) {
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return IsolationProofResult{}, err
	}
	network, err := verifier.network.VerifyNetworkIsolation(ctx)
	if err != nil {
		return IsolationProofResult{}, errLinuxIsolationUnverified
	}
	if network.Status != guestagent.IsolationProofStatusVerified ||
		!network.SingleInterface || !network.StaticRoutes || !network.ProxyReachable {
		return IsolationProofResult{}, errLinuxIsolationUnverified
	}
	result.Network = network
	return result, nil
}

func (liveLinuxProcessIsolationBoundary) ReadSelfStatus(ctx context.Context, maximum int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := io.LimitReader(file, maximum+1)
	payload, err := io.ReadAll(reader)
	if err != nil || int64(len(payload)) > maximum {
		return nil, errLinuxIsolationUnverified
	}
	return payload, nil
}

func (liveLinuxProcessIsolationBoundary) SupplementaryGroups(ctx context.Context) ([]int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return unix.Getgroups()
}

func (liveLinuxProcessIsolationBoundary) AttemptRawPacketSocket(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(linuxNetworkShort(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	_ = unix.Close(fd)
	return nil
}

func linuxNetworkShort(value uint16) uint16 {
	return value<<8 | value>>8
}

func linuxSelfStatusIsolated(payload []byte, maximum int64) bool {
	if len(payload) == 0 || int64(len(payload)) > maximum || payload[len(payload)-1] != '\n' || bytes.IndexByte(payload, 0) >= 0 {
		return false
	}
	required := map[string]string{
		"Uid":        "identity",
		"Gid":        "identity",
		"CapInh":     "capability",
		"CapPrm":     "capability",
		"CapEff":     "capability",
		"CapBnd":     "capability",
		"CapAmb":     "capability",
		"NoNewPrivs": "one",
	}
	seen := make(map[string]bool, len(required))
	for _, line := range strings.Split(string(payload[:len(payload)-1]), "\n") {
		if strings.ContainsRune(line, '\r') {
			return false
		}
		key, value, found := strings.Cut(line, ":")
		kind, wanted := required[key]
		if !found || !wanted {
			continue
		}
		if seen[key] {
			return false
		}
		seen[key] = true
		value = strings.TrimSpace(value)
		switch kind {
		case "identity":
			fields := strings.Fields(value)
			if len(fields) != 4 || fields[0] != "1000" || fields[1] != "1000" || fields[2] != "1000" || fields[3] != "1000" {
				return false
			}
		case "one":
			if value != "1" {
				return false
			}
		case "capability":
			if len(value) != 16 || strings.Trim(value, "0") != "" {
				return false
			}
		}
	}
	for key := range required {
		if !seen[key] {
			return false
		}
	}
	return true
}
