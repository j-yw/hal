package firecrackerhost

import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"

// minimalL7ConfigExpectation is a private schema/mapping input, not live
// enforcement authority. The descriptor must come from the retained session
// selected using its full expected identity; its two expected generations must
// come independently from that selection, never from candidate config JSON.
//
// This RED-stage field is deliberately ignored by the existing validator. It
// changes no config acceptance or runtime selection until the bounded mapper
// and validation implementation has been reviewed.
type minimalL7ConfigExpectation struct {
	descriptor         l7network.LaunchDescriptor
	runtimeGeneration  string
	topologyGeneration string
}
