package v2control

func cloneBindingManifests(values []BindingManifest) []BindingManifest {
	return append([]BindingManifest(nil), values...)
}

func cloneBindingProofs(values []BindingProof) []BindingProof {
	return append([]BindingProof(nil), values...)
}

func (manifest BindingManifest) BindingID() string  { return manifest.state.bindingID }
func (manifest BindingManifest) Mode() DeliveryMode { return manifest.state.mode }
func (manifest BindingManifest) ServiceID() (string, bool) {
	return manifest.state.serviceID, manifest.state.mode == DeliveryMode("http_proxy")
}
func (manifest BindingManifest) TargetPath() (string, bool) {
	return manifest.state.targetPath, manifest.state.mode == DeliveryMode("file_tmpfs")
}
func (manifest BindingManifest) DeclaredFileBytes() (uint32, bool) {
	return manifest.state.declaredFileBytes, manifest.state.mode == DeliveryMode("file_tmpfs")
}
func (manifest BindingManifest) FileSHA256() (string, bool) {
	return manifest.state.fileSHA256, manifest.state.mode == DeliveryMode("file_tmpfs")
}
func (manifest BindingManifest) SSHPolicyID() (string, bool) {
	return manifest.state.sshPolicyID, manifest.state.mode == DeliveryMode("ssh_agent")
}
func (manifest BindingManifest) SSHPolicyRevision() (uint64, bool) {
	return manifest.state.sshPolicyRevision, manifest.state.mode == DeliveryMode("ssh_agent")
}
func (proof BindingProof) BindingID() string  { return proof.state.bindingID }
func (proof BindingProof) Mode() DeliveryMode { return proof.state.mode }
func (proof BindingProof) ProofID() string    { return proof.state.proofID }

func (request CredentialPrepareRequest) RequestID() RequestID {
	if request.state == nil {
		return RequestID{}
	}
	return request.state.requestID
}
func (request CredentialPrepareRequest) IdentityDigest() IdentityDigest {
	if request.state == nil {
		return IdentityDigest{}
	}
	return request.state.identityDigest
}
func (request CredentialPrepareRequest) Identity() JobIdentity {
	if request.state == nil {
		return JobIdentity{}
	}
	return request.state.identity.JobIdentity()
}
func (request CredentialPrepareRequest) Revision() uint64 {
	if request.state == nil {
		return 0
	}
	return request.state.revision
}
func (request CredentialPrepareRequest) ExpiresAtUnixNano() int64 {
	if request.state == nil {
		return 0
	}
	return request.state.expiresAtUnixNano
}
func (request CredentialPrepareRequest) Bindings() []BindingManifest {
	if request.state == nil {
		return nil
	}
	return cloneBindingManifests(request.state.bindings)
}
func (request CredentialPrepareRequest) PrivateRecordCount() uint32 {
	if request.state == nil {
		return 0
	}
	return request.state.privateRecordCount
}
func (request CredentialPrepareRequest) PrivateAggregateBytes() uint64 {
	if request.state == nil {
		return 0
	}
	return request.state.privateAggregateBytes
}

func (response CredentialPrepareSuccessResponse) RequestID() RequestID {
	if response.state == nil {
		return RequestID{}
	}
	return response.state.requestID
}
func (response CredentialPrepareSuccessResponse) IdentityDigest() IdentityDigest {
	if response.state == nil {
		return IdentityDigest{}
	}
	return response.state.identityDigest
}
func (response CredentialPrepareSuccessResponse) Revision() uint64 {
	if response.state == nil {
		return 0
	}
	return response.state.revision
}
func (response CredentialPrepareSuccessResponse) ExpiresAtUnixNano() int64 {
	if response.state == nil {
		return 0
	}
	return response.state.expiresAtUnixNano
}
func (response CredentialPrepareSuccessResponse) ActiveProofID() string {
	if response.state == nil {
		return ""
	}
	return response.state.activeProofID
}
func (response CredentialPrepareSuccessResponse) ExecBindingID() string {
	if response.state == nil {
		return ""
	}
	return response.state.execBindingID
}
func (response CredentialPrepareSuccessResponse) BindingProofs() []BindingProof {
	if response.state == nil {
		return nil
	}
	return cloneBindingProofs(response.state.bindingProofs)
}
