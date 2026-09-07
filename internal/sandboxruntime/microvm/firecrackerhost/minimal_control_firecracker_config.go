package firecrackerhost

import (
	"crypto/ed25519"
	"encoding/hex"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// Admission already validated the sealed public config and its public key.
// Compare that independent input with the separately measured FC bytes; never
// derive expected boot or network fields from the candidate Firecracker config.
// This grants neither namespace equality nor current L7/controller authority.
func validateMinimalControlFirecrackerConfig(actual strictJailerConfigFile, config minimalControlSupervisorConfig, public ed25519.PublicKey) error {
	c, j := config.Control, config.Job
	if validateMinimalL7ConfigProjection(actual, c.NetworkInterface, c.StaticNetwork) != nil {
		return errL8RuntimeOwnerInvalid
	}
	nonce, ok := minimalControlConfigBase64(c.BootNonce)
	image, err := hex.DecodeString(config.Rootfs.SHA256)
	if !ok || err != nil || len(image) != 32 {
		return errL8RuntimeOwnerInvalid
	}
	identity := session.Identity{Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		RuntimeID: j.RuntimeID, RuntimeGeneration: j.RuntimeGeneration, BootGeneration: c.Prelaunch["bootGeneration"],
		ImageGeneration: c.Prelaunch["imageGeneration"], ControllerKeyGeneration: c.ControllerKeyGeneration, GuestBootNonce: nonce}
	copy(identity.ImageSHA256[:], image)
	expectedLine, err := minimalcontrol.RenderBootCommandLine(minimalL7BootFragment(c.StaticNetwork), identity, public, c.Prelaunch)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	expected, expectedPresent, expectedErr := minimalcontrol.ParseBootCommandLine(expectedLine)
	observed, observedPresent, observedErr := minimalcontrol.ParseBootCommandLine(actual.BootSource.BootArgs)
	if expectedErr != nil || !expectedPresent || observedErr != nil || !observedPresent || observed != expected {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}
