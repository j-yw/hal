//go:build l8_verified_policy_artifact && l8_verified_pinned_callsite_evidence

package localresolver

import assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"

// L8ProcessCompositionFacts keeps the guarded mutation fixture expressed in
// the resolver's vocabulary while preserving the build contract's exact type.
type L8ProcessCompositionFacts = assetbuild.L8ProcessCompositionFacts
