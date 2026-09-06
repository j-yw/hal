package credentialclient

import (
	"encoding/hex"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

// helperActiveLedger is the exact in-memory helper job after a correlated
// metadata-only prepare-commit response. ManifestSHA256 is the projected
// helper-record digest; this type does not hash v2 JSON or claim digest
// authority for the full v2 manifest.
type helperActiveLedger struct {
	identityDigest   v2control.IdentityDigest
	requestID        [16]byte
	helperGeneration credentialprotocol.SafeID
	manifestSHA256   [32]byte
	revision         uint64
	expiryUnixNano   int64
	proofIDs         []string
	records          []credentialprotocol.HelperBindingManifestRecord
	bindings         []v2control.BindingManifest
	activeProofID    string
	execBindingID    string
}

func projectV2ManifestToHelperRecords(bindings []v2control.BindingManifest) ([]credentialprotocol.HelperBindingManifestRecord, [32]byte, error) {
	records := make([]credentialprotocol.HelperBindingManifestRecord, 0, len(bindings))
	for _, binding := range bindings {
		record, err := helperBindingRecordFromManifest(binding)
		if err != nil {
			return nil, [32]byte{}, err
		}
		if credentialprotocol.ValidateHelperBindingManifestRecord(record) != nil {
			return nil, [32]byte{}, errInvalidHelperSendPacket
		}
		records = append(records, record)
	}
	digest, err := credentialprotocol.ComputeHelperManifestSHA256(records)
	if err != nil || digest == ([32]byte{}) {
		return nil, [32]byte{}, errInvalidHelperSendPacket
	}
	return records, digest, nil
}

func helperProofsMatchProjectedRecords(proofs []credentialprotocol.HelperBindingProof, records []credentialprotocol.HelperBindingManifestRecord) bool {
	if len(proofs) == 0 || len(proofs) != len(records) {
		return false
	}
	for index, proof := range proofs {
		if proof.BindingID != records[index].BindingID || proof.Mode != records[index].Mode {
			return false
		}
		if credentialprotocol.ValidateBodyToken(proof.ProofID) != nil {
			return false
		}
	}
	return true
}

func newHelperActiveLedger(
	identityDigest v2control.IdentityDigest,
	requestID [16]byte,
	helperGeneration credentialprotocol.SafeID,
	manifestSHA256 [32]byte,
	revision uint64,
	expiryUnixNano int64,
	proofs []credentialprotocol.HelperBindingProof,
	records []credentialprotocol.HelperBindingManifestRecord,
	bindings []v2control.BindingManifest,
	activeProofID, execBindingID string,
) (*helperActiveLedger, error) {
	if identityDigest == (v2control.IdentityDigest{}) || requestID == ([16]byte{}) ||
		credentialprotocol.ValidateSafeID(helperGeneration) != nil || manifestSHA256 == ([32]byte{}) ||
		revision == 0 || expiryUnixNano <= 0 || !helperProofsMatchProjectedRecords(proofs, records) ||
		len(bindings) != len(records) || credentialprotocol.ValidateBodyToken(activeProofID) != nil ||
		credentialprotocol.ValidateBodyToken(execBindingID) != nil {
		return nil, errInvalidHelperPacket
	}
	proofIDs := make([]string, len(proofs))
	for index, proof := range proofs {
		proofIDs[index] = proof.ProofID
	}
	return &helperActiveLedger{
		identityDigest:   identityDigest,
		requestID:        requestID,
		helperGeneration: helperGeneration,
		manifestSHA256:   manifestSHA256,
		revision:         revision,
		expiryUnixNano:   expiryUnixNano,
		proofIDs:         proofIDs,
		records:          cloneValues(records),
		bindings:         cloneValues(bindings),
		activeProofID:    activeProofID,
		execBindingID:    execBindingID,
	}, nil
}

func helperModeToV2(mode credentialprotocol.DeliveryMode) (v2control.DeliveryMode, error) {
	switch mode {
	case credentialprotocol.DeliveryModeHTTPProxy:
		return v2control.DeliveryMode("http_proxy"), nil
	case credentialprotocol.DeliveryModeFileTmpfs:
		return v2control.DeliveryMode("file_tmpfs"), nil
	case credentialprotocol.DeliveryModeSSHAgent:
		return v2control.DeliveryMode("ssh_agent"), nil
	default:
		return "", errInvalidHelperPacket
	}
}

func helperResponseHeaderMatches(header credentialprotocol.HelperPacketHeader, requestID [16]byte, identity [32]byte, revision uint64, requestType credentialprotocol.PacketType) bool {
	if header.Type != credentialprotocol.PacketTypeResponse || header.RequestID != requestID ||
		header.GuestCredentialIdentityDigest != identity || revision == 0 {
		return false
	}
	return credentialprotocol.ValidateHelperPacketHeaderSemantics(header) == nil && requestType != 0
}

func mapHelperPrepareSuccessToV2(request v2control.CredentialPrepareRequest, header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperResponseBody) (v2control.CredentialPrepareSuccessResponse, error) {
	if v2control.ValidateCredentialPrepareRequest(request) != nil ||
		credentialprotocol.ValidateHelperResponseBody(body) != nil ||
		body.RequestType != credentialprotocol.PacketTypePrepareCommit ||
		body.Disposition != credentialprotocol.ResponseDispositionAccepted ||
		body.Prepare == nil ||
		!helperResponseHeaderMatches(header, request.RequestID().Bytes(), request.IdentityDigest().Bytes(), body.Revision, body.RequestType) ||
		body.Revision != request.Revision() || body.Prepare.ExpiresAtUnixNano != request.ExpiresAtUnixNano() {
		return v2control.CredentialPrepareSuccessResponse{}, errInvalidHelperPacket
	}
	bindings := request.Bindings()
	if !helperProofsMatchProjectedRecords(body.Prepare.BindingProofs, mustProjectPrepareRecords(bindings)) {
		return v2control.CredentialPrepareSuccessResponse{}, errInvalidHelperPacket
	}
	if len(body.Prepare.BindingProofs) != len(bindings) {
		return v2control.CredentialPrepareSuccessResponse{}, errInvalidHelperPacket
	}
	proofs := make([]v2control.BindingProof, 0, len(body.Prepare.BindingProofs))
	for index, helperProof := range body.Prepare.BindingProofs {
		mode, err := helperModeToV2(helperProof.Mode)
		if err != nil || helperProof.BindingID != bindings[index].BindingID() || mode != bindings[index].Mode() {
			return v2control.CredentialPrepareSuccessResponse{}, errInvalidHelperPacket
		}
		proof, err := v2control.NewBindingProof(helperProof.BindingID, mode, helperProof.ProofID)
		if err != nil {
			return v2control.CredentialPrepareSuccessResponse{}, errInvalidHelperPacket
		}
		proofs = append(proofs, proof)
	}
	response, err := v2control.NewCredentialPrepareSuccessResponse(
		request, body.Revision, body.Prepare.ExpiresAtUnixNano,
		body.Prepare.ActiveProofID, body.Prepare.ExecBindingID, proofs,
	)
	if err != nil {
		return v2control.CredentialPrepareSuccessResponse{}, errInvalidHelperPacket
	}
	return response, nil
}

func mustProjectPrepareRecords(bindings []v2control.BindingManifest) []credentialprotocol.HelperBindingManifestRecord {
	records, _, err := projectV2ManifestToHelperRecords(bindings)
	if err != nil {
		return nil
	}
	return records
}

func mapHelperRenewSuccessToV2(request v2control.CredentialRenewRequest, header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperResponseBody) (v2control.CredentialRenewSuccessResponse, error) {
	if v2control.ValidateCredentialRenewRequest(request) != nil ||
		credentialprotocol.ValidateHelperResponseBody(body) != nil ||
		body.RequestType != credentialprotocol.PacketTypeRenew ||
		body.Disposition != credentialprotocol.ResponseDispositionAccepted ||
		body.Renew == nil ||
		!helperResponseHeaderMatches(header, request.RequestID().Bytes(), request.IdentityDigest().Bytes(), body.Revision, body.RequestType) ||
		body.Revision != request.Revision() || body.Renew.ExpiresAtUnixNano != request.ExpiresAtUnixNano() {
		return v2control.CredentialRenewSuccessResponse{}, errInvalidHelperPacket
	}
	response, err := v2control.NewCredentialRenewSuccessResponse(request, body.Renew.ReplacementActiveProofID)
	if err != nil {
		return v2control.CredentialRenewSuccessResponse{}, errInvalidHelperPacket
	}
	return response, nil
}

func mapHelperRevokeSuccessToV2(request v2control.CredentialRevokeRequest, header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperResponseBody) (v2control.CredentialRevokeSuccessResponse, error) {
	if v2control.ValidateCredentialRevokeRequest(request) != nil ||
		credentialprotocol.ValidateHelperResponseBody(body) != nil ||
		body.RequestType != credentialprotocol.PacketTypeRevoke ||
		body.Disposition != credentialprotocol.ResponseDispositionCleanupComplete ||
		body.Revoke == nil || !body.Revoke.AuthorityAbsent || !body.Revoke.ResourcesAbsent ||
		!helperResponseHeaderMatches(header, request.RequestID().Bytes(), request.IdentityDigest().Bytes(), body.Revision, body.RequestType) ||
		body.Revision != request.Revision() {
		return v2control.CredentialRevokeSuccessResponse{}, errInvalidHelperPacket
	}
	response, err := v2control.NewCredentialRevokeSuccessResponse(request, body.Revoke.CleanupProofID)
	if err != nil {
		return v2control.CredentialRevokeSuccessResponse{}, errInvalidHelperPacket
	}
	return response, nil
}

func mapHelperExecSuccessToV2(request v2control.CredentialExecRequest, header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperResponseBody) (v2control.CredentialExecSuccessResponse, error) {
	if v2control.ValidateCredentialExecRequest(request) != nil ||
		credentialprotocol.ValidateHelperResponseBody(body) != nil ||
		body.RequestType != credentialprotocol.PacketTypeExec ||
		body.Disposition != credentialprotocol.ResponseDispositionAccepted ||
		body.Exec == nil ||
		!helperResponseHeaderMatches(header, request.RequestID().Bytes(), request.IdentityDigest().Bytes(), body.Revision, body.RequestType) ||
		body.Revision != request.Revision() {
		return v2control.CredentialExecSuccessResponse{}, errInvalidHelperPacket
	}
	result := body.Exec
	response, err := v2control.NewCredentialExecSuccessResponse(
		request,
		result.ExitCode,
		result.StdinBytes, hex.EncodeToString(result.StdinSHA256[:]),
		result.StdoutBytes, hex.EncodeToString(result.StdoutSHA256[:]), result.StdoutTruncated,
		result.StderrBytes, hex.EncodeToString(result.StderrSHA256[:]), result.StderrTruncated,
		hex.EncodeToString(result.ExecTransactionSHA256[:]),
	)
	if err != nil {
		return v2control.CredentialExecSuccessResponse{}, errInvalidHelperPacket
	}
	return response, nil
}

func (client *Client) authorizeHelperSend(operation credentialprotocol.PacketType, digest v2control.IdentityDigest, revision uint64, bindings []v2control.BindingManifest) error {
	if client == nil || !configuredDependency(client.policy) {
		return clientError(ClientContractPolicy, ClientFieldPolicy)
	}
	var ids []credentialprotocol.SafeID
	var modes []credentialprotocol.DeliveryMode
	switch operation {
	case credentialprotocol.PacketTypePrepareBegin, credentialprotocol.PacketTypeExec:
		records, _, err := projectV2ManifestToHelperRecords(bindings)
		if err != nil {
			return clientError(ClientContractPolicy, ClientFieldPolicy)
		}
		ids = make([]credentialprotocol.SafeID, len(records))
		modes = make([]credentialprotocol.DeliveryMode, len(records))
		for index, record := range records {
			ids[index] = credentialprotocol.SafeID(record.BindingID)
			modes[index] = record.Mode
		}
	case credentialprotocol.PacketTypeRenew, credentialprotocol.PacketTypeRevoke:
		if bindings != nil {
			return clientError(ClientContractPolicy, ClientFieldPolicy)
		}
	default:
		return clientError(ClientContractPolicy, ClientFieldPolicy)
	}
	request := newClientPolicyRequest(
		operation,
		digest.Bytes(),
		revision,
		ids,
		modes,
		credentialprotocol.SSHRelayV1ExtensionDescriptor(),
		clientPolicyLimitSetID,
	)
	decision, err, panicked := authorizeClientPolicy(client.policy, request)
	if panicked {
		return clientError(ClientContractPanic, ClientFieldPolicy)
	}
	if err != nil || !decision.allow {
		return clientError(ClientContractPolicy, ClientFieldPolicy)
	}
	return nil
}

func authorizeClientPolicy(policy Policy, request ClientPolicyRequest) (decision ClientPolicyDecision, err error, panicked bool) {
	defer func() {
		if recover() != nil {
			decision = ClientPolicyDecision{}
			err = nil
			panicked = true
		}
	}()
	decision, err = policy.Authorize(request)
	return decision, err, false
}
