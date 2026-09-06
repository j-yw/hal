package l8composition

import (
	"bytes"
	"encoding/binary"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type ControllerSupervisorPacket struct {
	header      ControllerSupervisorHeader
	ready       ControllerSupervisorSupervisorReadyBody
	create      ControllerSupervisorCreateJobBody
	created     ControllerSupervisorJobCreatedBody
	launch      ControllerSupervisorLaunchShimBody
	started     ControllerSupervisorShimStartedBody
	terminate   ControllerSupervisorTerminateJobBody
	destroy     ControllerSupervisorDestroyJobBody
	event       ControllerSupervisorEventBody
	attestation ControllerSupervisorControllerAttestationBody
	accepted    ControllerSupervisorCompositionAcceptedBody
	closeBody   ControllerSupervisorCloseNotifyBody
}

func EncodeControllerSupervisorHeader(header ControllerSupervisorHeader) ([ControllerSupervisorHeaderBytes]byte, error) {
	var encoded [ControllerSupervisorHeaderBytes]byte
	if err := validateControllerSupervisorHeader(header); err != nil {
		return encoded, err
	}
	copy(encoded[:4], ControllerSupervisorMagic)
	encoded[4] = ControllerSupervisorVersion
	encoded[5] = byte(header.Type)
	binary.BigEndian.PutUint16(encoded[6:8], ControllerSupervisorFlags)
	binary.BigEndian.PutUint64(encoded[8:16], header.Sequence)
	copy(encoded[16:32], header.RequestID[:])
	copy(encoded[32:64], header.JobIdentityDigest[:])
	binary.BigEndian.PutUint32(encoded[64:68], header.BodyLength)
	return encoded, nil
}

func DecodeControllerSupervisorHeader(encoded []byte) (ControllerSupervisorHeader, error) {
	if len(encoded) != ControllerSupervisorHeaderBytes {
		return ControllerSupervisorHeader{}, ErrControllerSupervisorHeaderLength
	}
	if !bytes.Equal(encoded[:4], []byte(ControllerSupervisorMagic)) {
		return ControllerSupervisorHeader{}, ErrControllerSupervisorMagic
	}
	if encoded[4] != ControllerSupervisorVersion {
		return ControllerSupervisorHeader{}, ErrControllerSupervisorVersion
	}
	if binary.BigEndian.Uint16(encoded[6:8]) != ControllerSupervisorFlags {
		return ControllerSupervisorHeader{}, ErrControllerSupervisorFlags
	}
	header := ControllerSupervisorHeader{Type: ControllerSupervisorPacketType(encoded[5]), Sequence: binary.BigEndian.Uint64(encoded[8:16]), BodyLength: binary.BigEndian.Uint32(encoded[64:68])}
	copy(header.RequestID[:], encoded[16:32])
	copy(header.JobIdentityDigest[:], encoded[32:64])
	if err := validateControllerSupervisorHeader(header); err != nil {
		return ControllerSupervisorHeader{}, err
	}
	return header, nil
}

func validateControllerSupervisorHeader(header ControllerSupervisorHeader) error {
	if err := ValidateControllerSupervisorPacketType(header.Type); err != nil {
		return err
	}
	if header.Sequence >= MaxControllerSupervisorPacketsPerDirection {
		return ErrControllerSupervisorSequence
	}
	if header.BodyLength > MaxControllerSupervisorBodyBytes {
		return ErrControllerSupervisorBodyLength
	}
	boot := header.Type == ControllerSupervisorPacketTypeSupervisorReady || header.Type == ControllerSupervisorPacketTypeControllerAttestation || header.Type == ControllerSupervisorPacketTypeCompositionAccepted || header.Type == ControllerSupervisorPacketTypeCloseNotify
	if boot {
		if !controllerSupervisorZero16(header.RequestID) {
			return ErrControllerSupervisorRequestID
		}
		if !controllerSupervisorZero32(header.JobIdentityDigest) {
			return ErrControllerSupervisorJobIdentity
		}
	} else {
		if controllerSupervisorZero16(header.RequestID) {
			return ErrControllerSupervisorRequestID
		}
		if controllerSupervisorZero32(header.JobIdentityDigest) {
			return ErrControllerSupervisorJobIdentity
		}
	}
	return nil
}

func encodeControllerSupervisorTypedPacket(packetType ControllerSupervisorPacketType, sequence uint64, requestID [16]byte, jobIdentity [32]byte, body []byte) ([]byte, error) {
	if len(body) > MaxControllerSupervisorBodyBytes {
		return nil, ErrControllerSupervisorBodyLength
	}
	header, err := EncodeControllerSupervisorHeader(ControllerSupervisorHeader{Type: packetType, Sequence: sequence, RequestID: requestID, JobIdentityDigest: jobIdentity, BodyLength: uint32(len(body))})
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, len(header)+len(body))
	encoded = append(encoded, header[:]...)
	return append(encoded, body...), nil
}

func EncodeControllerSupervisorSupervisorReadyPacket(sequence uint64, body ControllerSupervisorSupervisorReadyBody) ([]byte, error) {
	encoded, err := EncodeControllerSupervisorSupervisorReadyBody(body)
	if err != nil {
		return nil, err
	}
	return encodeControllerSupervisorTypedPacket(ControllerSupervisorPacketTypeSupervisorReady, sequence, [16]byte{}, [32]byte{}, encoded)
}
func EncodeControllerSupervisorCreateJobPacket(sequence uint64, requestID [16]byte, jobIdentity [32]byte, body ControllerSupervisorCreateJobBody) ([]byte, error) {
	encoded, err := EncodeControllerSupervisorCreateJobBody(body)
	if err != nil {
		return nil, err
	}
	return encodeControllerSupervisorTypedPacket(ControllerSupervisorPacketTypeCreateJob, sequence, requestID, jobIdentity, encoded)
}
func EncodeControllerSupervisorJobCreatedPacket(sequence uint64, requestID [16]byte, jobIdentity [32]byte, body ControllerSupervisorJobCreatedBody) ([]byte, error) {
	encoded, err := EncodeControllerSupervisorJobCreatedBody(body)
	if err != nil {
		return nil, err
	}
	return encodeControllerSupervisorTypedPacket(ControllerSupervisorPacketTypeJobCreated, sequence, requestID, jobIdentity, encoded)
}
func EncodeControllerSupervisorLaunchShimPacket(sequence uint64, requestID [16]byte, jobIdentity [32]byte, body ControllerSupervisorLaunchShimBody) ([]byte, error) {
	if err := ValidateControllerSupervisorLaunchID(requestID, body.LaunchID); err != nil {
		return nil, err
	}
	encoded, err := EncodeControllerSupervisorLaunchShimBody(body)
	if err != nil {
		return nil, err
	}
	return encodeControllerSupervisorTypedPacket(ControllerSupervisorPacketTypeLaunchShim, sequence, requestID, jobIdentity, encoded)
}
func EncodeControllerSupervisorShimStartedPacket(sequence uint64, requestID [16]byte, jobIdentity [32]byte, body ControllerSupervisorShimStartedBody) ([]byte, error) {
	if err := ValidateControllerSupervisorLaunchID(requestID, body.LaunchID); err != nil {
		return nil, err
	}
	encoded, err := EncodeControllerSupervisorShimStartedBody(body)
	if err != nil {
		return nil, err
	}
	return encodeControllerSupervisorTypedPacket(ControllerSupervisorPacketTypeShimStarted, sequence, requestID, jobIdentity, encoded)
}
func EncodeControllerSupervisorTerminateJobPacket(sequence uint64, requestID [16]byte, jobIdentity [32]byte, body ControllerSupervisorTerminateJobBody) ([]byte, error) {
	encoded, err := EncodeControllerSupervisorTerminateJobBody(body)
	if err != nil {
		return nil, err
	}
	return encodeControllerSupervisorTypedPacket(ControllerSupervisorPacketTypeTerminateJob, sequence, requestID, jobIdentity, encoded)
}
func EncodeControllerSupervisorDestroyJobPacket(sequence uint64, requestID [16]byte, jobIdentity [32]byte, body ControllerSupervisorDestroyJobBody) ([]byte, error) {
	encoded, err := EncodeControllerSupervisorDestroyJobBody(body)
	if err != nil {
		return nil, err
	}
	return encodeControllerSupervisorTypedPacket(ControllerSupervisorPacketTypeDestroyJob, sequence, requestID, jobIdentity, encoded)
}
func EncodeControllerSupervisorEventPacket(sequence uint64, requestID [16]byte, jobIdentity [32]byte, body ControllerSupervisorEventBody) ([]byte, error) {
	if body.LaunchID != "" && body.RequestType == ControllerSupervisorPacketTypeLaunchShim {
		if err := ValidateControllerSupervisorLaunchID(requestID, body.LaunchID); err != nil {
			return nil, err
		}
	}
	encoded, err := EncodeControllerSupervisorEventBody(body)
	if err != nil {
		return nil, err
	}
	return encodeControllerSupervisorTypedPacket(ControllerSupervisorPacketTypeSupervisorEvent, sequence, requestID, jobIdentity, encoded)
}
func EncodeControllerSupervisorControllerAttestationPacket(sequence uint64, body ControllerSupervisorControllerAttestationBody) ([]byte, error) {
	encoded, err := EncodeControllerSupervisorControllerAttestationBody(body)
	if err != nil {
		return nil, err
	}
	return encodeControllerSupervisorTypedPacket(ControllerSupervisorPacketTypeControllerAttestation, sequence, [16]byte{}, [32]byte{}, encoded)
}
func EncodeControllerSupervisorCompositionAcceptedPacket(sequence uint64, body ControllerSupervisorCompositionAcceptedBody) ([]byte, error) {
	encoded, err := EncodeControllerSupervisorCompositionAcceptedBody(body)
	if err != nil {
		return nil, err
	}
	return encodeControllerSupervisorTypedPacket(ControllerSupervisorPacketTypeCompositionAccepted, sequence, [16]byte{}, [32]byte{}, encoded)
}
func EncodeControllerSupervisorCloseNotifyPacket(sequence uint64, body ControllerSupervisorCloseNotifyBody) ([]byte, error) {
	encoded, err := EncodeControllerSupervisorCloseNotifyBody(body)
	if err != nil {
		return nil, err
	}
	return encodeControllerSupervisorTypedPacket(ControllerSupervisorPacketTypeCloseNotify, sequence, [16]byte{}, [32]byte{}, encoded)
}

func DecodeControllerSupervisorPacket(encoded []byte) (ControllerSupervisorPacket, error) {
	if len(encoded) < ControllerSupervisorHeaderBytes {
		return ControllerSupervisorPacket{}, ErrControllerSupervisorHeaderLength
	}
	header, err := DecodeControllerSupervisorHeader(encoded[:ControllerSupervisorHeaderBytes])
	if err != nil {
		return ControllerSupervisorPacket{}, err
	}
	expected := ControllerSupervisorHeaderBytes + int(header.BodyLength)
	if len(encoded) < expected {
		return ControllerSupervisorPacket{}, ErrControllerSupervisorDatagramLength
	}
	if len(encoded) > expected {
		return ControllerSupervisorPacket{}, ErrControllerSupervisorDatagramTrailingData
	}
	packet := ControllerSupervisorPacket{header: header}
	body := encoded[ControllerSupervisorHeaderBytes:]
	switch header.Type {
	case ControllerSupervisorPacketTypeSupervisorReady:
		packet.ready, err = DecodeControllerSupervisorSupervisorReadyBody(body)
	case ControllerSupervisorPacketTypeCreateJob:
		packet.create, err = DecodeControllerSupervisorCreateJobBody(body)
	case ControllerSupervisorPacketTypeJobCreated:
		packet.created, err = DecodeControllerSupervisorJobCreatedBody(body)
	case ControllerSupervisorPacketTypeLaunchShim:
		packet.launch, err = DecodeControllerSupervisorLaunchShimBody(body)
		if err == nil {
			err = ValidateControllerSupervisorLaunchID(header.RequestID, packet.launch.LaunchID)
		}
	case ControllerSupervisorPacketTypeShimStarted:
		packet.started, err = DecodeControllerSupervisorShimStartedBody(body)
		if err == nil {
			err = ValidateControllerSupervisorLaunchID(header.RequestID, packet.started.LaunchID)
		}
	case ControllerSupervisorPacketTypeTerminateJob:
		packet.terminate, err = DecodeControllerSupervisorTerminateJobBody(body)
	case ControllerSupervisorPacketTypeDestroyJob:
		packet.destroy, err = DecodeControllerSupervisorDestroyJobBody(body)
	case ControllerSupervisorPacketTypeSupervisorEvent:
		packet.event, err = DecodeControllerSupervisorEventBody(body)
		if err == nil && packet.event.LaunchID != "" {
			err = ValidateControllerSupervisorLaunchID(header.RequestID, packet.event.LaunchID)
		}
	case ControllerSupervisorPacketTypeControllerAttestation:
		packet.attestation, err = DecodeControllerSupervisorControllerAttestationBody(body)
	case ControllerSupervisorPacketTypeCompositionAccepted:
		packet.accepted, err = DecodeControllerSupervisorCompositionAcceptedBody(body)
	case ControllerSupervisorPacketTypeCloseNotify:
		packet.closeBody, err = DecodeControllerSupervisorCloseNotifyBody(body)
	default:
		err = ErrControllerSupervisorPacketType
	}
	if err != nil {
		return ControllerSupervisorPacket{}, err
	}
	return packet, nil
}

func EncodeControllerSupervisorPacket(packet ControllerSupervisorPacket) ([]byte, error) {
	if err := validateControllerSupervisorPacketUnion(packet); err != nil {
		return nil, err
	}
	var encoded []byte
	var err error
	switch packet.header.Type {
	case ControllerSupervisorPacketTypeSupervisorReady:
		encoded, err = EncodeControllerSupervisorSupervisorReadyPacket(packet.header.Sequence, packet.ready)
	case ControllerSupervisorPacketTypeCreateJob:
		encoded, err = EncodeControllerSupervisorCreateJobPacket(packet.header.Sequence, packet.header.RequestID, packet.header.JobIdentityDigest, packet.create)
	case ControllerSupervisorPacketTypeJobCreated:
		encoded, err = EncodeControllerSupervisorJobCreatedPacket(packet.header.Sequence, packet.header.RequestID, packet.header.JobIdentityDigest, packet.created)
	case ControllerSupervisorPacketTypeLaunchShim:
		encoded, err = EncodeControllerSupervisorLaunchShimPacket(packet.header.Sequence, packet.header.RequestID, packet.header.JobIdentityDigest, packet.launch)
	case ControllerSupervisorPacketTypeShimStarted:
		encoded, err = EncodeControllerSupervisorShimStartedPacket(packet.header.Sequence, packet.header.RequestID, packet.header.JobIdentityDigest, packet.started)
	case ControllerSupervisorPacketTypeTerminateJob:
		encoded, err = EncodeControllerSupervisorTerminateJobPacket(packet.header.Sequence, packet.header.RequestID, packet.header.JobIdentityDigest, packet.terminate)
	case ControllerSupervisorPacketTypeDestroyJob:
		encoded, err = EncodeControllerSupervisorDestroyJobPacket(packet.header.Sequence, packet.header.RequestID, packet.header.JobIdentityDigest, packet.destroy)
	case ControllerSupervisorPacketTypeSupervisorEvent:
		encoded, err = EncodeControllerSupervisorEventPacket(packet.header.Sequence, packet.header.RequestID, packet.header.JobIdentityDigest, packet.event)
	case ControllerSupervisorPacketTypeControllerAttestation:
		encoded, err = EncodeControllerSupervisorControllerAttestationPacket(packet.header.Sequence, packet.attestation)
	case ControllerSupervisorPacketTypeCompositionAccepted:
		encoded, err = EncodeControllerSupervisorCompositionAcceptedPacket(packet.header.Sequence, packet.accepted)
	case ControllerSupervisorPacketTypeCloseNotify:
		encoded, err = EncodeControllerSupervisorCloseNotifyPacket(packet.header.Sequence, packet.closeBody)
	default:
		return nil, ErrControllerSupervisorBody
	}
	if err != nil {
		return nil, err
	}
	rebuilt, err := DecodeControllerSupervisorHeader(encoded[:ControllerSupervisorHeaderBytes])
	if err != nil || rebuilt != packet.header {
		return nil, ErrControllerSupervisorBody
	}
	return encoded, nil
}

func validateControllerSupervisorPacketUnion(packet ControllerSupervisorPacket) error {
	emptyDescriptor := func(value ProcessDescriptor) bool {
		return value.ContractVersion == "" && value.Role == 0 && len(value.Extensions) == 0 && value.PolicySHA256 == [32]byte{}
	}
	emptyReady := packet.ready == (ControllerSupervisorSupervisorReadyBody{})
	emptyCreate := packet.create == (ControllerSupervisorCreateJobBody{})
	emptyCreated := packet.created == (ControllerSupervisorJobCreatedBody{})
	emptyLaunch := packet.launch == (ControllerSupervisorLaunchShimBody{})
	emptyStarted := packet.started == (ControllerSupervisorShimStartedBody{})
	emptyTerminate := packet.terminate == (ControllerSupervisorTerminateJobBody{})
	emptyDestroy := packet.destroy == (ControllerSupervisorDestroyJobBody{})
	emptyEvent := packet.event == (ControllerSupervisorEventBody{})
	emptyAttestation := emptyDescriptor(packet.attestation.Descriptor)
	emptyAccepted := packet.accepted == (ControllerSupervisorCompositionAcceptedBody{})
	emptyClose := packet.closeBody == (ControllerSupervisorCloseNotifyBody{})

	inactiveEmpty := func(active ControllerSupervisorPacketType) bool {
		return (active == ControllerSupervisorPacketTypeSupervisorReady || emptyReady) &&
			(active == ControllerSupervisorPacketTypeCreateJob || emptyCreate) &&
			(active == ControllerSupervisorPacketTypeJobCreated || emptyCreated) &&
			(active == ControllerSupervisorPacketTypeLaunchShim || emptyLaunch) &&
			(active == ControllerSupervisorPacketTypeShimStarted || emptyStarted) &&
			(active == ControllerSupervisorPacketTypeTerminateJob || emptyTerminate) &&
			(active == ControllerSupervisorPacketTypeDestroyJob || emptyDestroy) &&
			(active == ControllerSupervisorPacketTypeSupervisorEvent || emptyEvent) &&
			(active == ControllerSupervisorPacketTypeControllerAttestation || emptyAttestation) &&
			(active == ControllerSupervisorPacketTypeCompositionAccepted || emptyAccepted) &&
			(active == ControllerSupervisorPacketTypeCloseNotify || emptyClose)
	}
	if err := ValidateControllerSupervisorPacketType(packet.header.Type); err != nil || !inactiveEmpty(packet.header.Type) {
		return ErrControllerSupervisorBody
	}
	return nil
}

func (p ControllerSupervisorPacket) Header() ControllerSupervisorHeader { return p.header }
func (p ControllerSupervisorPacket) SupervisorReady() (ControllerSupervisorSupervisorReadyBody, bool) {
	return p.ready, p.header.Type == ControllerSupervisorPacketTypeSupervisorReady
}
func (p ControllerSupervisorPacket) CreateJob() (ControllerSupervisorCreateJobBody, bool) {
	return p.create, p.header.Type == ControllerSupervisorPacketTypeCreateJob
}
func (p ControllerSupervisorPacket) JobCreated() (ControllerSupervisorJobCreatedBody, bool) {
	return p.created, p.header.Type == ControllerSupervisorPacketTypeJobCreated
}
func (p ControllerSupervisorPacket) LaunchShim() (ControllerSupervisorLaunchShimBody, bool) {
	return p.launch, p.header.Type == ControllerSupervisorPacketTypeLaunchShim
}
func (p ControllerSupervisorPacket) ShimStarted() (ControllerSupervisorShimStartedBody, bool) {
	return p.started, p.header.Type == ControllerSupervisorPacketTypeShimStarted
}
func (p ControllerSupervisorPacket) TerminateJob() (ControllerSupervisorTerminateJobBody, bool) {
	return p.terminate, p.header.Type == ControllerSupervisorPacketTypeTerminateJob
}
func (p ControllerSupervisorPacket) DestroyJob() (ControllerSupervisorDestroyJobBody, bool) {
	return p.destroy, p.header.Type == ControllerSupervisorPacketTypeDestroyJob
}
func (p ControllerSupervisorPacket) SupervisorEvent() (ControllerSupervisorEventBody, bool) {
	return p.event, p.header.Type == ControllerSupervisorPacketTypeSupervisorEvent
}
func (p ControllerSupervisorPacket) ControllerAttestation() (ControllerSupervisorControllerAttestationBody, bool) {
	if p.header.Type != ControllerSupervisorPacketTypeControllerAttestation {
		return ControllerSupervisorControllerAttestationBody{}, false
	}
	return ControllerSupervisorControllerAttestationBody{Descriptor: cloneAgentSupervisorDescriptor(p.attestation.Descriptor)}, true
}
func (p ControllerSupervisorPacket) CompositionAccepted() (ControllerSupervisorCompositionAcceptedBody, bool) {
	return p.accepted, p.header.Type == ControllerSupervisorPacketTypeCompositionAccepted
}
func (p ControllerSupervisorPacket) CloseNotify() (ControllerSupervisorCloseNotifyBody, bool) {
	return p.closeBody, p.header.Type == ControllerSupervisorPacketTypeCloseNotify
}

func ValidateControllerSupervisorReceiveMetadata(packet ControllerSupervisorPacket, metadata ControllerSupervisorReceiveMetadata, pid1, controller ControllerSupervisorKernelCredential, agentPID uint32) error {
	if metadata.MessageTruncated || metadata.ControlTruncated {
		return ErrControllerSupervisorTruncated
	}
	if err := ValidateControllerSupervisorDirection(metadata.Direction); err != nil {
		return err
	}
	if metadata.CredentialCount != 1 {
		return ErrControllerSupervisorCredentialCount
	}
	if !validControllerSupervisorPID1(pid1) || !validControllerSupervisorController(controller) || !validControllerSupervisorPID(agentPID) {
		return ErrControllerSupervisorKernelCredential
	}
	if pid1.PID == controller.PID || pid1.PID == agentPID || controller.PID == agentPID {
		return ErrControllerSupervisorRoleIdentityAlias
	}
	wantCredential := pid1
	if metadata.Direction == ControllerSupervisorDirectionControllerToPID1 {
		wantCredential = controller
	}
	if metadata.Credential != wantCredential {
		return ErrControllerSupervisorKernelCredential
	}
	if err := ValidateControllerSupervisorPacketMetadata(packet.header.Type, metadata.Direction, metadata.RightsCount); err != nil {
		return err
	}
	if metadata.RightsCount > MaxControllerSupervisorRights {
		return ErrControllerSupervisorRights
	}
	for i := uint32(0); i < metadata.RightsCount; i++ {
		if err := validateControllerSupervisorRightMetadata(metadata.Rights[i]); err != nil {
			return err
		}
	}
	for i := metadata.RightsCount; i < MaxControllerSupervisorRights; i++ {
		if metadata.Rights[i] != (ControllerSupervisorRightMetadata{}) {
			return ErrControllerSupervisorRights
		}
	}
	return validateControllerSupervisorRightRoles(packet, metadata)
}

func ValidateControllerSupervisorPacketMetadata(packetType ControllerSupervisorPacketType, direction ControllerSupervisorDirection, rightsCount uint32) error {
	if err := ValidateControllerSupervisorPacketType(packetType); err != nil {
		return err
	}
	if err := ValidateControllerSupervisorDirection(direction); err != nil {
		return err
	}
	pid1Send := packetType == ControllerSupervisorPacketTypeSupervisorReady || packetType == ControllerSupervisorPacketTypeJobCreated || packetType == ControllerSupervisorPacketTypeShimStarted || packetType == ControllerSupervisorPacketTypeSupervisorEvent || packetType == ControllerSupervisorPacketTypeCompositionAccepted
	if packetType != ControllerSupervisorPacketTypeCloseNotify && pid1Send != (direction == ControllerSupervisorDirectionPID1ToController) {
		return ErrControllerSupervisorPacketDirection
	}
	want := uint32(0)
	if packetType == ControllerSupervisorPacketTypeJobCreated {
		want = 2
	} else if packetType == ControllerSupervisorPacketTypeLaunchShim {
		want = 8
	}
	if rightsCount != want {
		return ErrControllerSupervisorRights
	}
	return nil
}

func validateControllerSupervisorRightMetadata(value ControllerSupervisorRightMetadata) error {
	if err := ValidateControllerSupervisorRightKind(value.Kind); err != nil {
		return err
	}
	if err := ValidateControllerSupervisorRightAccess(value.Access); err != nil {
		return err
	}
	if err := credentialprotocol.ValidateSafeID(value.Generation); err != nil {
		return err
	}
	if controllerSupervisorZero32(value.SHA256) {
		return ErrControllerSupervisorDigestZero
	}
	return nil
}
func validateControllerSupervisorRightRoles(packet ControllerSupervisorPacket, metadata ControllerSupervisorReceiveMetadata) error {
	var expected [MaxControllerSupervisorRights]ControllerSupervisorRightMetadata
	switch packet.header.Type {
	case ControllerSupervisorPacketTypeJobCreated:
		body := packet.created
		expected[0] = ControllerSupervisorRightMetadata{ControllerSupervisorRightMonitorEndpoint, ControllerSupervisorAccessDuplexSeqpacket, body.MonitorGeneration, body.MonitorReadySHA256}
		expected[1] = ControllerSupervisorRightMetadata{ControllerSupervisorRightMonitorNamespace, ControllerSupervisorAccessNamespaceEnter, body.MountGeneration, body.MonitorReadySHA256}
	case ControllerSupervisorPacketTypeLaunchShim:
		body := packet.launch
		launchDigest, err := ControllerSupervisorLaunchShimSHA256(packet.header.JobIdentityDigest, body)
		if err != nil {
			return err
		}
		expected[0] = ControllerSupervisorRightMetadata{ControllerSupervisorRightMonitorNamespace, ControllerSupervisorAccessNamespaceEnter, body.MountGeneration, launchDigest}
		expected[1] = ControllerSupervisorRightMetadata{ControllerSupervisorRightWorkdir, ControllerSupervisorAccessDirectoryChdir, body.MountGeneration, launchDigest}
		expected[2] = ControllerSupervisorRightMetadata{ControllerSupervisorRightExecutable, ControllerSupervisorAccessExecutableRead, body.JobGeneration, body.ExecutableSHA256}
		expected[3] = ControllerSupervisorRightMetadata{ControllerSupervisorRightStdinRead, ControllerSupervisorAccessPipeRead, body.LaunchID, launchDigest}
		expected[4] = ControllerSupervisorRightMetadata{ControllerSupervisorRightStdoutWrite, ControllerSupervisorAccessPipeWrite, body.LaunchID, launchDigest}
		expected[5] = ControllerSupervisorRightMetadata{ControllerSupervisorRightStderrWrite, ControllerSupervisorAccessPipeWrite, body.LaunchID, launchDigest}
		expected[6] = ControllerSupervisorRightMetadata{ControllerSupervisorRightStartGateRead, ControllerSupervisorAccessPipeRead, body.LaunchID, launchDigest}
		expected[7] = ControllerSupervisorRightMetadata{ControllerSupervisorRightLaunchBlockRead, ControllerSupervisorAccessSealedPipeRead, body.LaunchID, body.LaunchBlockSHA256}
	}
	for i := uint32(0); i < metadata.RightsCount; i++ {
		if metadata.Rights[i] != expected[i] {
			return ErrControllerSupervisorRightMetadata
		}
	}
	return nil
}

func validControllerSupervisorPID(value uint32) bool { return value >= 2 && value <= 1<<31-1 }
func validControllerSupervisorPID1(value ControllerSupervisorKernelCredential) bool {
	return value.PID == 1 && value.UID == 0 && value.GID == 0
}
func validControllerSupervisorController(value ControllerSupervisorKernelCredential) bool {
	return validControllerSupervisorPID(value.PID) && value.UID == 0 && value.GID == 0
}
