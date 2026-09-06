package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// These public pins are deliberately synthetic. Tests exercise the actual
// run() routing helper with counted constructors, not a fake boot parser or a
// real listener. The RED fails before any proposed bootstrap/crypto negatives
// execute; it proves the current entrypoint still chooses the v1 constructor.
func minimalBootstrapREDBootLine() string {
	key := [32]byte{41}
	nonce := [32]byte{1}
	image := [32]byte{2}
	prelaunch := [32]byte{3}
	return "console=ttyS0 " + strings.Join([]string{
		"hal_minimal_profile=guest-agent-minimal-v1",
		"hal_minimal_controller_key=" + base64.RawURLEncoding.EncodeToString(key[:]),
		"hal_minimal_controller_key_generation=controller-key-1",
		"hal_minimal_boot_nonce=" + base64.RawURLEncoding.EncodeToString(nonce[:]),
		"hal_minimal_runtime_id=runtime-1",
		"hal_minimal_runtime_generation=runtime-generation-1",
		"hal_minimal_boot_generation=boot-generation-1",
		"hal_minimal_image_generation=image-generation-1",
		"hal_minimal_image_sha256=" + hex.EncodeToString(image[:]),
		"hal_minimal_prelaunch_binding_sha256=" + hex.EncodeToString(prelaunch[:]),
	}, " ")
}

func TestMinimalBootstrapREDActualEntrySelectsMinimalBeforeLegacy(t *testing.T) {
	boot := minimalBootstrapREDBootLine()
	var reads, legacy, minimal int
	legacyResult := errors.New("legacy constructor reached")
	minimalResult := errors.New("injected minimal server stopped")
	err := runGuestAgentEntry(context.Background(), guestAgentEntryDependencies{
		readBootCommandLine: func(context.Context) (string, error) { reads++; return boot, nil },
		runLegacy:           func() error { legacy++; return legacyResult },
		runMinimal: func(_ context.Context, selected string) error {
			minimal++
			if selected != boot {
				t.Error("immutable boot bytes changed before selected construction")
			}
			return minimalResult
		},
	})
	if reads != 1 || legacy != 0 || minimal != 1 || !errors.Is(err, minimalResult) {
		t.Fatalf("selected public minimal boot reached wrong actual entrypoint: bootReads=%d legacyConstructors=%d minimalConstructors=%d err=%v", reads, legacy, minimal, err)
	}
}

func TestMinimalBootstrapREDRejectsExplicitBadBootBeforeConstructors(t *testing.T) {
	valid := minimalBootstrapREDBootLine()
	for _, scenario := range []string{
		"bare_marker", "profile_only", "missing_profile", "wrong_profile", "unknown_key", "duplicate_key", "case_alias",
		"empty_value", "bad_public_key", "bad_nonce", "bad_image_digest", "bad_prelaunch_digest", "unsafe_identity", "oversized_command_line", "nul", "boot_read_failure",
	} {
		t.Run(scenario, func(t *testing.T) {
			boot := valid
			var sourceError error
			switch scenario {
			case "bare_marker":
				boot = "console=ttyS0 hal_minimal_profile"
			case "profile_only":
				boot = "hal_minimal_profile=guest-agent-minimal-v1"
			case "missing_profile":
				boot = strings.Replace(valid, "hal_minimal_profile=guest-agent-minimal-v1 ", "", 1)
			case "wrong_profile":
				boot = strings.Replace(valid, "guest-agent-minimal-v1", "guest-agent-v1", 1)
			case "unknown_key":
				boot = valid + " hal_minimal_unknown=present"
			case "duplicate_key":
				boot = valid + " hal_minimal_runtime_id=runtime-1"
			case "case_alias":
				boot = strings.Replace(valid, "hal_minimal_profile", "HAL_MINIMAL_PROFILE", 1)
			case "empty_value":
				boot = strings.Replace(valid, "hal_minimal_runtime_id=runtime-1", "hal_minimal_runtime_id=", 1)
			case "bad_public_key":
				boot = strings.Replace(valid, "hal_minimal_controller_key=", "hal_minimal_controller_key=not-base64!", 1)
			case "bad_nonce":
				boot = strings.Replace(valid, "hal_minimal_boot_nonce=", "hal_minimal_boot_nonce=short-", 1)
			case "bad_image_digest":
				boot = strings.Replace(valid, "hal_minimal_image_sha256=", "hal_minimal_image_sha256=not-hex-", 1)
			case "bad_prelaunch_digest":
				boot = strings.Replace(valid, "hal_minimal_prelaunch_binding_sha256=", "hal_minimal_prelaunch_binding_sha256=not-hex-", 1)
			case "unsafe_identity":
				boot = strings.Replace(valid, "hal_minimal_runtime_id=runtime-1", "hal_minimal_runtime_id=../runtime", 1)
			case "oversized_command_line":
				boot = valid + " " + strings.Repeat("x", 4097-len(valid))
			case "nul":
				boot = valid + "\x00"
			case "boot_read_failure":
				sourceError = errors.New("private source failure canary")
			}
			var reads, legacy, minimal int
			err := runGuestAgentEntry(context.Background(), guestAgentEntryDependencies{
				readBootCommandLine: func(context.Context) (string, error) { reads++; return boot, sourceError },
				runLegacy:           func() error { legacy++; return errors.New("legacy constructor reached") },
				runMinimal:          func(context.Context, string) error { minimal++; return errors.New("minimal constructor reached") },
			})
			if err == nil || reads != 1 || legacy != 0 || minimal != 0 {
				t.Fatalf("invalid public boot reached a runtime constructor before validation: bootReads=%d legacyConstructors=%d minimalConstructors=%d err=%v", reads, legacy, minimal, err)
			}
			if strings.Contains(err.Error(), "private source failure canary") {
				t.Fatal("raw boot source error escaped")
			}
		})
	}
}

// Legacy construction remains unchanged by the RED-enabling seam. The GREEN
// will read/validate absence first, but must still select this same constructor
// once, preserve its error identity, and never construct a minimal server.
func TestMinimalBootstrapLegacyAbsenceKeepsCurrentConstructor(t *testing.T) {
	for _, boot := range []string{"", "console=ttyS0 reboot=k panic=1 pci=off", "console=ttyS0 hal_l7_net_if=eth0"} {
		legacy, minimal := 0, 0
		want := errors.New("legacy sentinel")
		err := runGuestAgentEntry(context.Background(), guestAgentEntryDependencies{
			readBootCommandLine: func(context.Context) (string, error) { return boot, nil },
			runLegacy:           func() error { legacy++; return want },
			runMinimal:          func(context.Context, string) error { minimal++; return nil },
		})
		if err != want || legacy != 1 || minimal != 0 {
			t.Fatalf("legacy routing changed: legacy=%d minimal=%d err=%v", legacy, minimal, err)
		}
	}
}
