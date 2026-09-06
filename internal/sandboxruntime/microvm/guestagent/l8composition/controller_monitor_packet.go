package l8composition

import (
	"bytes"
	"encoding/binary"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type ControllerMonitorPacket struct {
	header   ControllerMonitorHeader
	ready    ControllerMonitorReadyBody
	begin    credentialprotocol.HelperPrepareBeginBody
	commit   credentialprotocol.HelperPrepareCommitBody
	ssh      ControllerMonitorCreateSSHEndpointBody
	revoke   credentialprotocol.HelperRevokeBody
	response ControllerMonitorResponseBody
	event    ControllerMonitorEventBody
	close    ControllerMonitorCloseNotifyBody
}

func EncodeControllerMonitorHeader(header ControllerMonitorHeader) ([ControllerMonitorHeaderBytes]byte, error) {
	var encoded [ControllerMonitorHeaderBytes]byte
	if err := validateControllerMonitorHeader(header); err != nil {
		return encoded, err
	}
	copy(encoded[:4], ControllerMonitorMagic)
	encoded[4] = ControllerMonitorVersion
	encoded[5] = byte(header.Type)
	binary.BigEndian.PutUint16(encoded[6:8], ControllerMonitorFlags)
	binary.BigEndian.PutUint64(encoded[8:16], header.Sequence)
	copy(encoded[16:32], header.RequestID[:])
	copy(encoded[32:64], header.JobIdentityDigest[:])
	binary.BigEndian.PutUint32(encoded[64:68], header.BodyLength)
	return encoded, nil
}

func DecodeControllerMonitorHeader(encoded []byte) (ControllerMonitorHeader, error) {
	if len(encoded) != ControllerMonitorHeaderBytes {
		return ControllerMonitorHeader{}, ErrControllerMonitorHeaderLength
	}
	if !bytes.Equal(encoded[:4], []byte(ControllerMonitorMagic)) {
		return ControllerMonitorHeader{}, ErrControllerMonitorMagic
	}
	if encoded[4] != ControllerMonitorVersion {
		return ControllerMonitorHeader{}, ErrControllerMonitorVersion
	}
	if binary.BigEndian.Uint16(encoded[6:8]) != ControllerMonitorFlags {
		return ControllerMonitorHeader{}, ErrControllerMonitorFlags
	}
	header := ControllerMonitorHeader{Type: ControllerMonitorPacketType(encoded[5]), Sequence: binary.BigEndian.Uint64(encoded[8:16]), BodyLength: binary.BigEndian.Uint32(encoded[64:68])}
	copy(header.RequestID[:], encoded[16:32])
	copy(header.JobIdentityDigest[:], encoded[32:64])
	if err := validateControllerMonitorHeader(header); err != nil {
		return ControllerMonitorHeader{}, err
	}
	return header, nil
}

func validateControllerMonitorHeader(header ControllerMonitorHeader) error {
	if err := ValidateControllerMonitorPacketType(header.Type); err != nil {
		return err
	}
	if header.Sequence >= MaxControllerMonitorPacketsPerDirection {
		return ErrControllerMonitorBody
	}
	if header.BodyLength > MaxControllerMonitorBodyBytes {
		return ErrControllerMonitorBodyLength
	}
	if controllerMonitorZero32(header.JobIdentityDigest) {
		return ErrControllerMonitorJobIdentity
	}
	zeroRequest := controllerMonitorZero16(header.RequestID)
	if header.Type == ControllerMonitorPacketTypeMonitorReady || header.Type == ControllerMonitorPacketTypeCloseNotify {
		if !zeroRequest {
			return ErrControllerMonitorRequestIdentity
		}
	} else if zeroRequest {
		return ErrControllerMonitorRequestIdentity
	}
	return nil
}

func EncodeControllerMonitorReadyPacket(sequence uint64, job [32]byte, body ControllerMonitorReadyBody) ([]byte, error) {
	encoded, err := EncodeControllerMonitorReadyBody(body)
	return encodeControllerMonitorTypedPacket(ControllerMonitorPacketTypeMonitorReady, sequence, [16]byte{}, job, encoded, err)
}
func EncodeControllerMonitorPrepareBeginPacket(sequence uint64, request [16]byte, job [32]byte, body credentialprotocol.HelperPrepareBeginBody) ([]byte, error) {
	if err := validateControllerMonitorPrepareBindings(body.Bindings); err != nil {
		return nil, err
	}
	encoded, err := credentialprotocol.EncodeHelperPrepareBeginBody(body)
	if err == nil && (len(encoded) < controllerMonitorPrepareBeginMinBytes || len(encoded) > controllerMonitorPrepareBeginMaxBytes) {
		err = ErrControllerMonitorBodyLength
	}
	return encodeControllerMonitorTypedPacket(ControllerMonitorPacketTypePrepareBegin, sequence, request, job, encoded, err)
}

func EncodeControllerMonitorPrepareCommitPacket(sequence uint64, request [16]byte, job [32]byte, body credentialprotocol.HelperPrepareCommitBody) ([]byte, error) {
	encoded, err := credentialprotocol.EncodeHelperPrepareCommitBody(body)
	return encodeControllerMonitorTypedPacket(ControllerMonitorPacketTypePrepareCommit, sequence, request, job, encoded, err)
}
func EncodeControllerMonitorCreateSSHEndpointPacket(sequence uint64, request [16]byte, job [32]byte, body ControllerMonitorCreateSSHEndpointBody) ([]byte, error) {
	encoded, err := EncodeControllerMonitorCreateSSHEndpointBody(body)
	return encodeControllerMonitorTypedPacket(ControllerMonitorPacketTypeCreateSSHEndpoint, sequence, request, job, encoded, err)
}
func EncodeControllerMonitorRevokePacket(sequence uint64, request [16]byte, job [32]byte, body credentialprotocol.HelperRevokeBody) ([]byte, error) {
	encoded, err := credentialprotocol.EncodeHelperRevokeBody(body)
	return encodeControllerMonitorTypedPacket(ControllerMonitorPacketTypeRevoke, sequence, request, job, encoded, err)
}
func EncodeControllerMonitorResponsePacket(sequence uint64, request [16]byte, job [32]byte, body ControllerMonitorResponseBody) ([]byte, error) {
	encoded, err := EncodeControllerMonitorResponseBody(body)
	return encodeControllerMonitorTypedPacket(ControllerMonitorPacketTypeResponse, sequence, request, job, encoded, err)
}
func EncodeControllerMonitorEventPacket(sequence uint64, request [16]byte, job [32]byte, body ControllerMonitorEventBody) ([]byte, error) {
	if body.EventID != controllerMonitorEventID(request) {
		return nil, ErrControllerMonitorEvent
	}
	encoded, err := EncodeControllerMonitorEventBody(body)
	return encodeControllerMonitorTypedPacket(ControllerMonitorPacketTypeMonitorEvent, sequence, request, job, encoded, err)
}
func EncodeControllerMonitorCloseNotifyPacket(sequence uint64, job [32]byte, body ControllerMonitorCloseNotifyBody) ([]byte, error) {
	encoded, err := EncodeControllerMonitorCloseNotifyBody(body)
	return encodeControllerMonitorTypedPacket(ControllerMonitorPacketTypeCloseNotify, sequence, [16]byte{}, job, encoded, err)
}

func encodeControllerMonitorTypedPacket(packetType ControllerMonitorPacketType, sequence uint64, request [16]byte, job [32]byte, body []byte, bodyErr error) ([]byte, error) {
	if packetType == ControllerMonitorPacketTypePrepareFile {
		return nil, ErrControllerMonitorPrepareFileSlotRequired
	}
	if bodyErr != nil {
		return nil, bodyErr
	}
	header, err := EncodeControllerMonitorHeader(ControllerMonitorHeader{Type: packetType, Sequence: sequence, RequestID: request, JobIdentityDigest: job, BodyLength: uint32(len(body))})
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, len(header)+len(body))
	encoded = append(encoded, header[:]...)
	encoded = append(encoded, body...)
	return encoded, nil
}

func DecodeControllerMonitorPacket(encoded []byte) (ControllerMonitorPacket, error) {
	if len(encoded) < ControllerMonitorHeaderBytes {
		return ControllerMonitorPacket{}, ErrControllerMonitorHeaderLength
	}
	header, err := DecodeControllerMonitorHeader(encoded[:ControllerMonitorHeaderBytes])
	if err != nil {
		return ControllerMonitorPacket{}, err
	}
	expected := ControllerMonitorHeaderBytes + int(header.BodyLength)
	if len(encoded) < expected {
		return ControllerMonitorPacket{}, ErrControllerMonitorDatagramLength
	}
	if len(encoded) > expected {
		return ControllerMonitorPacket{}, ErrControllerMonitorDatagramTrailingData
	}
	if err := validateControllerMonitorTypeBodyLength(header.Type, int(header.BodyLength)); err != nil {
		return ControllerMonitorPacket{}, err
	}
	body := encoded[ControllerMonitorHeaderBytes:]
	packet := ControllerMonitorPacket{header: header}
	switch header.Type {
	case ControllerMonitorPacketTypeMonitorReady:
		packet.ready, err = DecodeControllerMonitorReadyBody(body)
	case ControllerMonitorPacketTypePrepareBegin:
		packet.begin, err = credentialprotocol.DecodeHelperPrepareBeginBody(body)
		if err == nil {
			err = validateControllerMonitorPrepareBindings(packet.begin.Bindings)
		}
	case ControllerMonitorPacketTypePrepareFile:
		err = ErrControllerMonitorPrepareFileSlotRequired
	case ControllerMonitorPacketTypePrepareCommit:
		packet.commit, err = credentialprotocol.DecodeHelperPrepareCommitBody(body)
	case ControllerMonitorPacketTypeCreateSSHEndpoint:
		packet.ssh, err = DecodeControllerMonitorCreateSSHEndpointBody(body)
	case ControllerMonitorPacketTypeRevoke:
		packet.revoke, err = credentialprotocol.DecodeHelperRevokeBody(body)
	case ControllerMonitorPacketTypeResponse:
		packet.response, err = DecodeControllerMonitorResponseBody(body)
	case ControllerMonitorPacketTypeMonitorEvent:
		packet.event, err = DecodeControllerMonitorEventBody(body)
		if err == nil && packet.event.EventID != controllerMonitorEventID(header.RequestID) {
			err = ErrControllerMonitorEvent
		}
	case ControllerMonitorPacketTypeCloseNotify:
		packet.close, err = DecodeControllerMonitorCloseNotifyBody(body)
	default:
		err = ErrControllerMonitorPacketType
	}
	if err != nil {
		return ControllerMonitorPacket{}, err
	}
	return packet, nil
}

func validateControllerMonitorPrepareBindings(bindings []credentialprotocol.HelperBindingManifestRecord) error {
	sshCount := 0
	for _, binding := range bindings {
		if binding.Mode == credentialprotocol.DeliveryModeSSHAgent {
			sshCount++
			if sshCount > 1 {
				return ErrControllerMonitorBody
			}
		}
	}
	return nil
}

func validateControllerMonitorTypeBodyLength(packetType ControllerMonitorPacketType, length int) error {
	valid := false
	switch packetType {
	case ControllerMonitorPacketTypeMonitorReady:
		valid = length >= controllerMonitorReadyMinBytes && length <= controllerMonitorReadyMaxBytes
	case ControllerMonitorPacketTypePrepareBegin:
		valid = length >= controllerMonitorPrepareBeginMinBytes && length <= controllerMonitorPrepareBeginMaxBytes
	case ControllerMonitorPacketTypePrepareFile:
		valid = length >= controllerMonitorPrepareFileMinBytes && length <= controllerMonitorPrepareFileMaxBytes
	case ControllerMonitorPacketTypePrepareCommit:
		valid = length == controllerMonitorPrepareCommitBytes
	case ControllerMonitorPacketTypeCreateSSHEndpoint:
		valid = length >= controllerMonitorSSHCreateMinBytes && length <= controllerMonitorSSHCreateMaxBytes
	case ControllerMonitorPacketTypeRevoke:
		valid = length == controllerMonitorRevokeBytes
	case ControllerMonitorPacketTypeResponse:
		valid = length >= 11 && length <= 305
	case ControllerMonitorPacketTypeMonitorEvent:
		valid = length >= controllerMonitorEventMinBytes && length <= controllerMonitorEventMaxBytes
	case ControllerMonitorPacketTypeCloseNotify:
		valid = length == controllerMonitorCloseBytes
	}
	if !valid {
		return ErrControllerMonitorBodyLength
	}
	return nil
}

func EncodeControllerMonitorPacket(packet ControllerMonitorPacket) ([]byte, error) {
	if err := validateControllerMonitorPacketUnion(packet); err != nil {
		return nil, err
	}
	var body []byte
	var err error
	switch packet.header.Type {
	case ControllerMonitorPacketTypeMonitorReady:
		body, err = EncodeControllerMonitorReadyBody(packet.ready)
	case ControllerMonitorPacketTypePrepareBegin:
		body, err = credentialprotocol.EncodeHelperPrepareBeginBody(packet.begin)
	case ControllerMonitorPacketTypePrepareFile:
		return nil, ErrControllerMonitorPrepareFileSlotRequired
	case ControllerMonitorPacketTypePrepareCommit:
		body, err = credentialprotocol.EncodeHelperPrepareCommitBody(packet.commit)
	case ControllerMonitorPacketTypeCreateSSHEndpoint:
		body, err = EncodeControllerMonitorCreateSSHEndpointBody(packet.ssh)
	case ControllerMonitorPacketTypeRevoke:
		body, err = credentialprotocol.EncodeHelperRevokeBody(packet.revoke)
	case ControllerMonitorPacketTypeResponse:
		body, err = EncodeControllerMonitorResponseBody(packet.response)
	case ControllerMonitorPacketTypeMonitorEvent:
		if packet.event.EventID != controllerMonitorEventID(packet.header.RequestID) {
			return nil, ErrControllerMonitorEvent
		}
		body, err = EncodeControllerMonitorEventBody(packet.event)
	case ControllerMonitorPacketTypeCloseNotify:
		body, err = EncodeControllerMonitorCloseNotifyBody(packet.close)
	default:
		return nil, ErrControllerMonitorBody
	}
	if err != nil {
		return nil, err
	}
	encoded, err := encodeControllerMonitorTypedPacket(packet.header.Type, packet.header.Sequence, packet.header.RequestID, packet.header.JobIdentityDigest, body, nil)
	if err != nil {
		return nil, err
	}
	rebuilt, err := DecodeControllerMonitorHeader(encoded[:ControllerMonitorHeaderBytes])
	if err != nil || rebuilt != packet.header {
		return nil, ErrControllerMonitorBody
	}
	return encoded, nil
}

func validateControllerMonitorPacketUnion(packet ControllerMonitorPacket) error {
	emptyBegin := packet.begin.Revision == 0 && packet.begin.ExpiryUnixNano == 0 && packet.begin.Bindings == nil
	emptyReady := packet.ready == (ControllerMonitorReadyBody{})
	emptyCommit := packet.commit == (credentialprotocol.HelperPrepareCommitBody{})
	emptySSH := packet.ssh == (ControllerMonitorCreateSSHEndpointBody{})
	emptyRevoke := packet.revoke == (credentialprotocol.HelperRevokeBody{})
	emptyResponse := packet.response == (ControllerMonitorResponseBody{})
	emptyEvent := packet.event == (ControllerMonitorEventBody{})
	emptyClose := packet.close == (ControllerMonitorCloseNotifyBody{})
	inactiveEmpty := (packet.header.Type == ControllerMonitorPacketTypeMonitorReady || emptyReady) &&
		(packet.header.Type == ControllerMonitorPacketTypePrepareBegin || emptyBegin) &&
		(packet.header.Type == ControllerMonitorPacketTypePrepareCommit || emptyCommit) &&
		(packet.header.Type == ControllerMonitorPacketTypeCreateSSHEndpoint || emptySSH) &&
		(packet.header.Type == ControllerMonitorPacketTypeRevoke || emptyRevoke) &&
		(packet.header.Type == ControllerMonitorPacketTypeResponse || emptyResponse) &&
		(packet.header.Type == ControllerMonitorPacketTypeMonitorEvent || emptyEvent) &&
		(packet.header.Type == ControllerMonitorPacketTypeCloseNotify || emptyClose)
	if ValidateControllerMonitorPacketType(packet.header.Type) != nil || !inactiveEmpty {
		return ErrControllerMonitorBody
	}
	return nil
}

func (packet ControllerMonitorPacket) Header() ControllerMonitorHeader { return packet.header }
func (packet ControllerMonitorPacket) MonitorReady() (ControllerMonitorReadyBody, bool) {
	return packet.ready, packet.header.Type == ControllerMonitorPacketTypeMonitorReady
}
func (packet ControllerMonitorPacket) PrepareBegin() (credentialprotocol.HelperPrepareBeginBody, bool) {
	if packet.header.Type != ControllerMonitorPacketTypePrepareBegin {
		return credentialprotocol.HelperPrepareBeginBody{}, false
	}
	body := packet.begin
	body.Bindings = append([]credentialprotocol.HelperBindingManifestRecord(nil), body.Bindings...)
	return body, true
}
func (packet ControllerMonitorPacket) PrepareCommit() (credentialprotocol.HelperPrepareCommitBody, bool) {
	return packet.commit, packet.header.Type == ControllerMonitorPacketTypePrepareCommit
}
func (packet ControllerMonitorPacket) CreateSSHEndpoint() (ControllerMonitorCreateSSHEndpointBody, bool) {
	return packet.ssh, packet.header.Type == ControllerMonitorPacketTypeCreateSSHEndpoint
}
func (packet ControllerMonitorPacket) Revoke() (credentialprotocol.HelperRevokeBody, bool) {
	return packet.revoke, packet.header.Type == ControllerMonitorPacketTypeRevoke
}
func (packet ControllerMonitorPacket) Response() (ControllerMonitorResponseBody, bool) {
	return packet.response, packet.header.Type == ControllerMonitorPacketTypeResponse
}
func (packet ControllerMonitorPacket) Event() (ControllerMonitorEventBody, bool) {
	return packet.event, packet.header.Type == ControllerMonitorPacketTypeMonitorEvent
}
func (packet ControllerMonitorPacket) CloseNotify() (ControllerMonitorCloseNotifyBody, bool) {
	return packet.close, packet.header.Type == ControllerMonitorPacketTypeCloseNotify
}

func ValidateControllerMonitorPacketMetadata(packetType ControllerMonitorPacketType, direction ControllerMonitorDirection, rightsCount uint32, response *ControllerMonitorResponseBody) error {
	if err := ValidateControllerMonitorPacketType(packetType); err != nil {
		return err
	}
	if err := ValidateControllerMonitorDirection(direction); err != nil {
		return err
	}
	wantRights := uint32(0)
	switch packetType {
	case ControllerMonitorPacketTypeMonitorReady:
		if direction != ControllerMonitorDirectionMonitorToPID1 {
			return ErrControllerMonitorPacketDirection
		}
		wantRights = 2
	case ControllerMonitorPacketTypePrepareBegin, ControllerMonitorPacketTypePrepareFile, ControllerMonitorPacketTypePrepareCommit, ControllerMonitorPacketTypeCreateSSHEndpoint, ControllerMonitorPacketTypeRevoke:
		if direction != ControllerMonitorDirectionControllerToMonitor {
			return ErrControllerMonitorPacketDirection
		}
	case ControllerMonitorPacketTypeResponse:
		if direction != ControllerMonitorDirectionMonitorToController || response == nil {
			return ErrControllerMonitorPacketDirection
		}
		if response.disposition == credentialprotocol.ResponseDispositionAccepted && response.requestType == ControllerMonitorPacketTypeCreateSSHEndpoint {
			wantRights = 1
		}
	case ControllerMonitorPacketTypeMonitorEvent:
		if direction != ControllerMonitorDirectionMonitorToController {
			return ErrControllerMonitorPacketDirection
		}
	case ControllerMonitorPacketTypeCloseNotify:
		if direction != ControllerMonitorDirectionControllerToMonitor && direction != ControllerMonitorDirectionMonitorToController {
			return ErrControllerMonitorPacketDirection
		}
	}
	if rightsCount != wantRights {
		return ErrControllerMonitorRights
	}
	return nil
}

func ValidateControllerMonitorReceiveMetadata(packet ControllerMonitorPacket, metadata ControllerMonitorReceiveMetadata, monitor, controller ControllerMonitorKernelCredential, agentPID uint32) error {
	if metadata.RightsCount > uint32(len(metadata.Rights)) {
		return ErrControllerMonitorRights
	}
	if metadata.MessageTruncated || metadata.ControlTruncated {
		return ErrControllerMonitorTruncated
	}
	if metadata.CredentialCount != 1 {
		return ErrControllerMonitorCredentialCount
	}
	if !validControllerMonitorRootCredential(monitor) || !validControllerMonitorRootCredential(controller) || !validControllerMonitorPID(agentPID) {
		return ErrControllerMonitorKernelCredential
	}
	if monitor.PID == controller.PID || monitor.PID == agentPID || controller.PID == agentPID {
		return ErrControllerMonitorRoleIdentityAlias
	}
	wantCredential := monitor
	if metadata.Direction == ControllerMonitorDirectionControllerToMonitor {
		wantCredential = controller
	}
	if metadata.Credential != wantCredential {
		return ErrControllerMonitorKernelCredential
	}
	var response *ControllerMonitorResponseBody
	if packet.header.Type == ControllerMonitorPacketTypeResponse {
		response = &packet.response
	}
	if err := ValidateControllerMonitorPacketMetadata(packet.header.Type, metadata.Direction, metadata.RightsCount, response); err != nil {
		return err
	}
	for index := uint32(0); index < metadata.RightsCount; index++ {
		if metadata.Rights[index].Index != index || !validControllerMonitorSafeID(metadata.Rights[index].Generation) || controllerMonitorZero32(metadata.Rights[index].CorrelationSHA256) {
			return ErrControllerMonitorRights
		}
		if ValidateControllerMonitorRightKind(metadata.Rights[index].Kind) != nil || ValidateControllerMonitorRightAccess(metadata.Rights[index].Access) != nil {
			return ErrControllerMonitorRights
		}
	}
	for index := metadata.RightsCount; index < uint32(len(metadata.Rights)); index++ {
		if metadata.Rights[index] != (ControllerMonitorRightMetadata{}) {
			return ErrControllerMonitorRights
		}
	}
	if metadata.RightsCount == 2 {
		if metadata.Rights[0] != (ControllerMonitorRightMetadata{Index: 0, Kind: ControllerMonitorRightControllerEndpoint, Access: ControllerMonitorRightDuplexSeqpacket, Generation: packet.ready.MonitorGeneration, CorrelationSHA256: packet.ready.MonitorReadySHA256}) || metadata.Rights[1] != (ControllerMonitorRightMetadata{Index: 1, Kind: ControllerMonitorRightMountNamespace, Access: ControllerMonitorRightNamespaceEnter, Generation: packet.ready.MountGeneration, CorrelationSHA256: packet.ready.MonitorReadySHA256}) {
			return ErrControllerMonitorRights
		}
	}
	if metadata.RightsCount == 1 {
		result, ok := packet.response.SSHEndpointResult()
		if !ok || metadata.Rights[0] != (ControllerMonitorRightMetadata{Index: 0, Kind: ControllerMonitorRightSSHListener, Access: ControllerMonitorRightListenStream, Generation: result.EndpointGeneration, CorrelationSHA256: result.EndpointSHA256}) {
			return ErrControllerMonitorRights
		}
	}
	return nil
}
