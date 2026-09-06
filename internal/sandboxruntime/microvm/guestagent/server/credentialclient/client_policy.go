package credentialclient

import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"

const clientPolicyLimitSetID credentialprotocol.SafeID = "helper-limits-v1"

// clientPolicy is the stateless, deny-by-default production client policy.
// The private non-pointer value carries no selectable policy authority.
type clientPolicy struct{ liveValue }

// NewClientPolicy returns the sole production client policy. It has no options
// and cannot acquire live transport, extension, or proof authority.
func NewClientPolicy() Policy {
	return clientPolicy{}
}

func (clientPolicy) Descriptor() PolicyDescriptor {
	return newClientPolicyDescriptor()
}

func (clientPolicy) Authorize(request ClientPolicyRequest) (ClientPolicyDecision, error) {
	if request.identityDigest == ([32]byte{}) ||
		request.revision == 0 ||
		request.fixedLimitSetID != clientPolicyLimitSetID ||
		!credentialprotocol.ExtensionDescriptorEqual(request.descriptor, credentialprotocol.SSHRelayV1ExtensionDescriptor()) {
		return rejectClientPolicyRequest()
	}

	switch request.operation {
	case credentialprotocol.PacketTypePrepareBegin, credentialprotocol.PacketTypeExec:
		if request.operation == credentialprotocol.PacketTypePrepareBegin && request.revision != 1 {
			return rejectClientPolicyRequest()
		}
		if !validClientPolicyBindings(request.bindingIDs, request.bindingModes) {
			return rejectClientPolicyRequest()
		}
	case credentialprotocol.PacketTypeRenew, credentialprotocol.PacketTypeRevoke:
		if request.bindingIDs != nil || request.bindingModes != nil {
			return rejectClientPolicyRequest()
		}
	default:
		return rejectClientPolicyRequest()
	}
	return newClientPolicyAllowDecision(), nil
}

func validClientPolicyBindings(ids []credentialprotocol.SafeID, modes []credentialprotocol.DeliveryMode) bool {
	if len(ids) == 0 || len(ids) > credentialprotocol.MaxHelperBindings || len(ids) != len(modes) {
		return false
	}
	seen := make(map[credentialprotocol.SafeID]struct{}, len(ids))
	httpBindings := 0
	for index, id := range ids {
		if credentialprotocol.ValidateSafeID(id) != nil {
			return false
		}
		if _, exists := seen[id]; exists {
			return false
		}
		seen[id] = struct{}{}
		if credentialprotocol.ValidateDeliveryMode(modes[index]) != nil {
			return false
		}
		if modes[index] == credentialprotocol.DeliveryModeHTTPProxy {
			httpBindings++
			if httpBindings > 1 {
				return false
			}
		}
	}
	return true
}

func rejectClientPolicyRequest() (ClientPolicyDecision, error) {
	return newClientPolicyRejectionDecision("malformed_request")
}
