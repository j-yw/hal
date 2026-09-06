//go:build linux && !l8_production_pid1

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const minimalPID1NetworkLine = "hal_l7_net_if=eth0 hal_l7_ipv4=192.0.2.2/30 hal_l7_ipv4_gateway=192.0.2.1 " +
	"hal_l7_ipv6=fd00:7::2/126 hal_l7_ipv6_gateway=fd00:7::1 hal_l7_proxy=http://198.18.0.1:18080"

func minimalPID1BootLine() string {
	key, nonce, image, binding := [32]byte{41}, [32]byte{1}, [32]byte{2}, [32]byte{3}
	return strings.Join([]string{
		"console=ttyS0",
		"hal_minimal_profile=guest-agent-minimal-v1",
		"hal_minimal_controller_key=" + base64.RawURLEncoding.EncodeToString(key[:]),
		"hal_minimal_controller_key_generation=controller-key-1",
		"hal_minimal_boot_nonce=" + base64.RawURLEncoding.EncodeToString(nonce[:]),
		"hal_minimal_runtime_id=runtime-1",
		"hal_minimal_runtime_generation=runtime-generation-1",
		"hal_minimal_boot_generation=boot-generation-1",
		"hal_minimal_image_generation=image-generation-1",
		"hal_minimal_image_sha256=" + hex.EncodeToString(image[:]),
		"hal_minimal_prelaunch_binding_sha256=" + hex.EncodeToString(binding[:]),
	}, " ")
}

func TestMinimalPID1REDRejectsBeforePrivilegedBoundaries(t *testing.T) {
	valid := minimalPID1BootLine()
	for _, test := range []struct {
		name, boot string
		readError  error
	}{
		{name: "bare", boot: "hal_minimal_profile"},
		{name: "partial", boot: "hal_minimal_profile=guest-agent-minimal-v1"},
		{name: "missing_profile", boot: strings.Replace(valid, "hal_minimal_profile=guest-agent-minimal-v1 ", "", 1)},
		{name: "wrong_profile", boot: strings.Replace(valid, "guest-agent-minimal-v1", "guest-agent-v1", 1)},
		{name: "unknown", boot: valid + " hal_minimal_unknown=value"},
		{name: "duplicate", boot: valid + " hal_minimal_runtime_id=runtime-1"},
		{name: "case_alias", boot: strings.Replace(valid, "hal_minimal_profile", "HAL_MINIMAL_PROFILE", 1)},
		{name: "quoted", boot: strings.Replace(valid, "hal_minimal_runtime_id=runtime-1", "\"hal_minimal_runtime_id=runtime-1\"", 1)},
		{name: "empty", boot: strings.Replace(valid, "hal_minimal_runtime_id=runtime-1", "hal_minimal_runtime_id=", 1)},
		{name: "invalid_key", boot: strings.Replace(valid, "hal_minimal_controller_key=", "hal_minimal_controller_key=bad-", 1)},
		{name: "invalid_nonce", boot: strings.Replace(valid, "hal_minimal_boot_nonce=", "hal_minimal_boot_nonce=bad-", 1)},
		{name: "invalid_digest", boot: strings.Replace(valid, "hal_minimal_image_sha256=", "hal_minimal_image_sha256=bad-", 1)},
		{name: "invalid_binding", boot: strings.Replace(valid, "hal_minimal_prelaunch_binding_sha256=", "hal_minimal_prelaunch_binding_sha256=bad-", 1)},
		{name: "unsafe_identity", boot: strings.Replace(valid, "runtime_id=runtime-1", "runtime_id=/private/runtime", 1)},
		{name: "embedded_newline", boot: valid + "\nconsole=ttyS0"},
		{name: "control", boot: valid + "\r"},
		{name: "nul", boot: valid + "\x00"},
		{name: "too_large", boot: valid + strings.Repeat(" ", 4097)},
		{name: "read_failure", boot: valid, readError: errors.New("synthetic boot read failure")},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls []string
			code := runGuestInitEntry([]string{"/usr/bin/setpriv", "/usr/bin/hal-guest-agent"}, true, guestInitEntryDependencies{
				readBootCommandLine: func(context.Context) (string, error) {
					calls = append(calls, "read")
					return minimalPID1NetworkLine + " " + test.boot, test.readError
				},
				configureNetwork: func(l7NetworkBootConfig) error { calls = append(calls, "network"); return nil },
				releaseAgentGate: func() int { calls = append(calls, "gate"); return 0 },
				superviseChild:   func([]string, []string) int { calls = append(calls, "child"); return 0 },
			})
			if code != 127 || !reflect.DeepEqual(calls, []string{"read"}) {
				t.Fatalf("invalid bootstrap reached privileged boundaries: code=%d calls=%v", code, calls)
			}
		})
	}
}
