package firecrackerhost

import (
	"crypto/ed25519"
	"encoding/hex"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// A value-only snapshot of independently admitted public inputs. It is neither
// an L7 launch descriptor nor runtime, namespace, cleanup or readiness authority.
// The later constructor must independently bind its full correlation to the
// admitted owner/store. A nonzero digest here is only data-shape validation.
type minimalControlConfigExpectation struct {
	configCorrelation [32]byte
	job               jailerRecoveryJob
	configSHA256      string
	nic               minimalL7NetworkInterface
	static            [6]string
	boot              minimalcontrol.BootConfig
}

func validateMinimalControlRequestConfig(actual strictJailerConfigFile, expected *minimalControlConfigExpectation, runtimeID, configSHA256 string) error {
	if expected == nil || expected.configCorrelation == ([32]byte{}) || expected.job.RuntimeID != runtimeID ||
		expected.configSHA256 != configSHA256 || validateMinimalL7ConfigProjection(actual, expected.nic, expected.static) != nil {
		return invalidMinimalL7Config()
	}
	boot, present, err := minimalcontrol.ParseBootCommandLine(actual.BootSource.BootArgs)
	if err != nil || !present || boot != expected.boot {
		return invalidMinimalL7Config()
	}
	return nil
}

// Called only after actual sealed FC equality admission. Expected boot pins
// are rendered from the independent public config, never from candidate FC.
// All retained fields are values; no map, key slice or borrowed FD escapes.
func captureMinimalControlConfigExpectation(config minimalControlSupervisorConfig, public ed25519.PublicKey, correlation [32]byte) (minimalControlConfigExpectation, error) {
	c, j := config.Control, config.Job
	nonce, ok := minimalControlConfigBase64(c.BootNonce)
	image, err := hex.DecodeString(config.Rootfs.SHA256)
	if !ok || err != nil || len(image) != 32 || correlation == ([32]byte{}) {
		return minimalControlConfigExpectation{}, errL8RuntimeOwnerInvalid
	}
	identity := session.Identity{Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		RuntimeID: j.RuntimeID, RuntimeGeneration: j.RuntimeGeneration, BootGeneration: c.Prelaunch["bootGeneration"],
		ImageGeneration: c.Prelaunch["imageGeneration"], ControllerKeyGeneration: c.ControllerKeyGeneration, GuestBootNonce: nonce}
	copy(identity.ImageSHA256[:], image)
	line, err := minimalcontrol.RenderBootCommandLine(minimalL7BootFragment(c.StaticNetwork), identity, public, c.Prelaunch)
	if err != nil {
		return minimalControlConfigExpectation{}, errL8RuntimeOwnerInvalid
	}
	boot, present, err := minimalcontrol.ParseBootCommandLine(line)
	if err != nil || !present {
		return minimalControlConfigExpectation{}, errL8RuntimeOwnerInvalid
	}
	return minimalControlConfigExpectation{configCorrelation: correlation, job: j, configSHA256: config.Config.SHA256,
		nic: c.NetworkInterface, static: c.StaticNetwork, boot: boot}, nil
}
