package sshrelay

import (
	"sort"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type livePolicy struct {
	liveValue
	identity PolicyIdentity
	rules    []livePolicyRule
}

type livePolicyRule struct {
	fingerprint credentialprotocol.SSHAgentKeyFingerprint
	algorithm   credentialprotocol.SSHAgentKeyAlgorithm
	flags       credentialprotocol.SSHAgentRSAFlags
}

// NewLivePolicy validates and freezes one nonempty host-admin allowlist.
func NewLivePolicy(identity PolicyIdentity, rules []PolicyRule) (LivePolicy, error) {
	if !validPolicyIdentity(identity) || len(rules) == 0 {
		return nil, ErrPolicyInvalid
	}
	frozen := make([]livePolicyRule, 0, len(rules)*2)
	for _, rule := range rules {
		fingerprint, err := credentialprotocol.ParseSSHAgentKeyFingerprint(rule.Fingerprint)
		if err != nil || credentialprotocol.ValidateSSHAgentKeyAlgorithm(rule.KeyAlgorithm) != nil || len(rule.Flags) == 0 {
			wipeLivePolicyRules(frozen)
			return nil, ErrPolicyInvalid
		}
		flags := append([]credentialprotocol.SSHAgentRSAFlags(nil), rule.Flags...)
		sort.Slice(flags, func(left, right int) bool { return flags[left] < flags[right] })
		for index, flag := range flags {
			if credentialprotocol.ValidateSSHAgentRequestFlags(rule.KeyAlgorithm, flag) != nil ||
				(index > 0 && flags[index-1] == flag) {
				fingerprint.Wipe()
				wipeLivePolicyRules(frozen)
				return nil, ErrPolicyInvalid
			}
			candidate := livePolicyRule{fingerprint: fingerprint, algorithm: rule.KeyAlgorithm, flags: flag}
			for existingIndex := range frozen {
				existing := &frozen[existingIndex]
				if existing.algorithm == candidate.algorithm && existing.flags == candidate.flags && existing.fingerprint.Equal(candidate.fingerprint) {
					fingerprint.Wipe()
					wipeLivePolicyRules(frozen)
					return nil, ErrPolicyInvalid
				}
			}
			frozen = append(frozen, candidate)
		}
		fingerprint.Wipe()
	}
	return &livePolicy{identity: identity, rules: frozen}, nil
}

func (policy *livePolicy) Identity() PolicyIdentity {
	if policy == nil {
		return PolicyIdentity{}
	}
	return policy.identity
}

func (policy *livePolicy) FilterIdentities(identities []credentialprotocol.SSHAgentIdentity) ([]credentialprotocol.SSHAgentIdentity, error) {
	if policy == nil || len(policy.rules) == 0 || len(identities) > credentialprotocol.SSHAgentMaxIdentities {
		return nil, ErrPolicyInvalid
	}
	filtered := make([]credentialprotocol.SSHAgentIdentity, 0, len(identities))
	for index := range identities {
		identity := &identities[index]
		blob := identity.PublicKeyBlob()
		fingerprint, err := credentialprotocol.DeriveSSHAgentKeyFingerprint(blob)
		credentialprotocol.WipeSSHAgentBytes(blob)
		if err != nil {
			credentialprotocol.WipeSSHAgentIdentities(filtered)
			return nil, ErrPolicyInvalid
		}
		allowed := policy.permits(fingerprint, identity.KeyAlgorithm(), 0, false)
		fingerprint.Wipe()
		if !allowed {
			continue
		}
		blob = identity.PublicKeyBlob()
		copyIdentity, err := credentialprotocol.NewSSHAgentIdentity(blob)
		credentialprotocol.WipeSSHAgentBytes(blob)
		if err != nil {
			credentialprotocol.WipeSSHAgentIdentities(filtered)
			return nil, ErrPolicyInvalid
		}
		filtered = append(filtered, copyIdentity)
	}
	return filtered, nil
}

func (policy *livePolicy) AuthorizeSign(request *credentialprotocol.SSHAgentSignRequest) error {
	if policy == nil || request == nil || credentialprotocol.ValidateSSHAgentRequestFlags(request.KeyAlgorithm(), request.Flags()) != nil {
		return ErrRequestRejected
	}
	blob := request.PublicKeyBlob()
	fingerprint, err := credentialprotocol.DeriveSSHAgentKeyFingerprint(blob)
	credentialprotocol.WipeSSHAgentBytes(blob)
	if err != nil {
		return ErrRequestRejected
	}
	allowed := policy.permits(fingerprint, request.KeyAlgorithm(), request.Flags(), true)
	fingerprint.Wipe()
	if !allowed {
		return ErrRequestRejected
	}
	return nil
}

func (policy *livePolicy) permits(fingerprint credentialprotocol.SSHAgentKeyFingerprint, algorithm credentialprotocol.SSHAgentKeyAlgorithm, flags credentialprotocol.SSHAgentRSAFlags, signing bool) bool {
	for index := range policy.rules {
		rule := &policy.rules[index]
		if !rule.fingerprint.Equal(fingerprint) || rule.algorithm != algorithm {
			continue
		}
		if !signing || rule.flags == flags {
			return true
		}
	}
	return false
}

func validateLivePolicy(policy LivePolicy) (PolicyIdentity, error) {
	if !configuredDependency(policy) {
		return PolicyIdentity{}, ErrPolicyInvalid
	}
	concrete, ok := policy.(*livePolicy)
	if !ok || concrete == nil || len(concrete.rules) == 0 {
		return PolicyIdentity{}, ErrPolicyInvalid
	}
	identity, err := safePolicyIdentity(policy)
	if err != nil || !validPolicyIdentity(identity) {
		return PolicyIdentity{}, ErrPolicyInvalid
	}
	return identity, nil
}

func safePolicyIdentity(policy LivePolicy) (identity PolicyIdentity, err error) {
	defer func() {
		if recover() != nil {
			identity = PolicyIdentity{}
			err = ErrPolicyInvalid
		}
	}()
	return policy.Identity(), nil
}

func wipeLivePolicyRules(rules []livePolicyRule) {
	for index := range rules {
		rules[index].fingerprint.Wipe()
		rules[index] = livePolicyRule{}
	}
}

var _ LivePolicy = (*livePolicy)(nil)
