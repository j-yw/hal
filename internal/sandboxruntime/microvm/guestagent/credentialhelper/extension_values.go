package credentialhelper

import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"

func NewExtensionOpenRequest(descriptor credentialprotocol.ExtensionDescriptor, host ExtensionHost) (ExtensionOpenRequest, error) {
	if credentialprotocol.ValidateExtensionDescriptor(descriptor) != nil {
		return ExtensionOpenRequest{}, ErrContractInvalidArgument
	}
	if !configuredDependency(host) {
		return ExtensionOpenRequest{}, ErrContractTypedNil
	}
	return ExtensionOpenRequest{descriptor: credentialprotocol.CloneExtensionDescriptor(descriptor), host: host}, nil
}

func (request ExtensionOpenRequest) Descriptor() credentialprotocol.ExtensionDescriptor {
	return credentialprotocol.CloneExtensionDescriptor(request.descriptor)
}
func (request ExtensionOpenRequest) Host() ExtensionHost { return request.host }

func NewExtensionPrepareRequest(identityDigest [32]byte, revision uint64, expiresUnixNano int64, bindingID credentialprotocol.SafeID, bindingIndex uint16, mode credentialprotocol.DeliveryMode, execBinding ExecBindingCapability) (ExtensionPrepareRequest, error) {
	if identityDigest == ([32]byte{}) || revision == 0 || expiresUnixNano <= 0 || !validSafeID(bindingID) || bindingIndex >= credentialprotocol.MaxHelperBindings || credentialprotocol.ValidateDeliveryMode(mode) != nil {
		return ExtensionPrepareRequest{}, ErrContractInvalidArgument
	}
	if !validExecBindingCapability(execBinding) {
		return ExtensionPrepareRequest{}, ErrContractCapability
	}
	return ExtensionPrepareRequest{identityDigest: identityDigest, revision: revision, expiresUnixNano: expiresUnixNano, bindingID: bindingID, bindingIndex: bindingIndex, mode: mode, execBinding: execBinding}, nil
}

func (request ExtensionPrepareRequest) IdentityDigest() [32]byte { return request.identityDigest }
func (request ExtensionPrepareRequest) Revision() uint64         { return request.revision }
func (request ExtensionPrepareRequest) ExpiresUnixNano() int64   { return request.expiresUnixNano }
func (request ExtensionPrepareRequest) BindingID() credentialprotocol.SafeID {
	return request.bindingID
}
func (request ExtensionPrepareRequest) BindingIndex() uint16 { return request.bindingIndex }
func (request ExtensionPrepareRequest) Mode() credentialprotocol.DeliveryMode {
	return request.mode
}
func (request ExtensionPrepareRequest) ExecBinding() ExecBindingCapability {
	return request.execBinding
}

func NewExtensionPrepareResult(execBinding ExecBindingCapability) (ExtensionPrepareResult, error) {
	if !validExecBindingCapability(execBinding) {
		return ExtensionPrepareResult{}, ErrContractCapability
	}
	return ExtensionPrepareResult{execBinding: execBinding}, nil
}
func (result ExtensionPrepareResult) ExecBinding() ExecBindingCapability { return result.execBinding }

func NewExtensionExecRequest(identityDigest [32]byte, revision uint64, execBindingID credentialprotocol.SafeID, execBinding ExecBindingCapability) (ExtensionExecRequest, error) {
	if identityDigest == ([32]byte{}) || revision == 0 || !validSafeID(execBindingID) {
		return ExtensionExecRequest{}, ErrContractInvalidArgument
	}
	if !validExecBindingCapability(execBinding) {
		return ExtensionExecRequest{}, ErrContractCapability
	}
	return ExtensionExecRequest{identityDigest: identityDigest, revision: revision, execBindingID: execBindingID, execBinding: execBinding}, nil
}
func (request ExtensionExecRequest) IdentityDigest() [32]byte { return request.identityDigest }
func (request ExtensionExecRequest) Revision() uint64         { return request.revision }
func (request ExtensionExecRequest) ExecBindingID() credentialprotocol.SafeID {
	return request.execBindingID
}
func (request ExtensionExecRequest) ExecBinding() ExecBindingCapability { return request.execBinding }

func NewExtensionExecResult(execBinding ExecBindingCapability) (ExtensionExecResult, error) {
	if !validExecBindingCapability(execBinding) {
		return ExtensionExecResult{}, ErrContractCapability
	}
	return ExtensionExecResult{execBinding: execBinding}, nil
}
func (result ExtensionExecResult) ExecBinding() ExecBindingCapability { return result.execBinding }

func NewExtensionRenewRequest(identityDigest [32]byte, revision uint64, expiresUnixNano int64) (ExtensionRenewRequest, error) {
	if identityDigest == ([32]byte{}) || revision == 0 || expiresUnixNano <= 0 {
		return ExtensionRenewRequest{}, ErrContractInvalidArgument
	}
	return ExtensionRenewRequest{identityDigest: identityDigest, revision: revision, expiresUnixNano: expiresUnixNano}, nil
}
func (request ExtensionRenewRequest) IdentityDigest() [32]byte { return request.identityDigest }
func (request ExtensionRenewRequest) Revision() uint64         { return request.revision }
func (request ExtensionRenewRequest) ExpiresUnixNano() int64   { return request.expiresUnixNano }

func NewExtensionRevokeRequest(identityDigest [32]byte, revision uint64, reason credentialprotocol.RevokeReason) (ExtensionRevokeRequest, error) {
	if identityDigest == ([32]byte{}) || revision == 0 || credentialprotocol.ValidateRevokeReason(reason) != nil {
		return ExtensionRevokeRequest{}, ErrContractInvalidArgument
	}
	return ExtensionRevokeRequest{identityDigest: identityDigest, revision: revision, reason: reason}, nil
}
func (request ExtensionRevokeRequest) IdentityDigest() [32]byte { return request.identityDigest }
func (request ExtensionRevokeRequest) Revision() uint64         { return request.revision }
func (request ExtensionRevokeRequest) Reason() credentialprotocol.RevokeReason {
	return request.reason
}

func NewSSHAgentEndpointRequest(identityDigest [32]byte, revision uint64, bindingID credentialprotocol.SafeID, bindingIndex uint16, execBinding ExecBindingCapability) (SSHAgentEndpointRequest, error) {
	if identityDigest == ([32]byte{}) || revision == 0 || !validSafeID(bindingID) || bindingIndex >= credentialprotocol.MaxHelperBindings {
		return SSHAgentEndpointRequest{}, ErrContractInvalidArgument
	}
	if !validExecBindingCapability(execBinding) {
		return SSHAgentEndpointRequest{}, ErrContractCapability
	}
	return SSHAgentEndpointRequest{identityDigest: identityDigest, revision: revision, bindingID: bindingID, bindingIndex: bindingIndex, execBinding: execBinding}, nil
}
func (request SSHAgentEndpointRequest) IdentityDigest() [32]byte { return request.identityDigest }
func (request SSHAgentEndpointRequest) Revision() uint64         { return request.revision }
func (request SSHAgentEndpointRequest) BindingID() credentialprotocol.SafeID {
	return request.bindingID
}
func (request SSHAgentEndpointRequest) BindingIndex() uint16 { return request.bindingIndex }
func (request SSHAgentEndpointRequest) ExecBinding() ExecBindingCapability {
	return request.execBinding
}

func NewSSHAcceptedPublication(identityDigest [32]byte, revision uint64, bindingIndex uint16, ordinal uint8, capabilitySHA256 [32]byte, execBinding ExecBindingCapability) (SSHAcceptedPublication, error) {
	if identityDigest == ([32]byte{}) || revision == 0 || bindingIndex >= credentialprotocol.MaxHelperBindings || ordinal == 0 || ordinal > credentialprotocol.SSHAgentRelayMaxLifetimeConnections || capabilitySHA256 == ([32]byte{}) {
		return SSHAcceptedPublication{}, ErrContractInvalidArgument
	}
	if !validExecBindingCapability(execBinding) {
		return SSHAcceptedPublication{}, ErrContractCapability
	}
	return SSHAcceptedPublication{identityDigest: identityDigest, revision: revision, bindingIndex: bindingIndex, ordinal: ordinal, capabilitySHA256: capabilitySHA256, execBinding: execBinding}, nil
}
func (publication SSHAcceptedPublication) IdentityDigest() [32]byte {
	return publication.identityDigest
}
func (publication SSHAcceptedPublication) Revision() uint64     { return publication.revision }
func (publication SSHAcceptedPublication) BindingIndex() uint16 { return publication.bindingIndex }
func (publication SSHAcceptedPublication) Ordinal() uint8       { return publication.ordinal }
func (publication SSHAcceptedPublication) CapabilitySHA256() [32]byte {
	return publication.capabilitySHA256
}
func (publication SSHAcceptedPublication) ExecBinding() ExecBindingCapability {
	return publication.execBinding
}
