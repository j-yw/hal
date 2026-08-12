package l8composition

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

type ControllerSupervisorSupervisorReadyBody struct {
	BootGeneration        credentialprotocol.SafeID
	HelperGeneration      credentialprotocol.SafeID
	SupervisorGeneration  credentialprotocol.SafeID
	LimitSetID            credentialprotocol.SafeID
	SupervisorReadySHA256 [sha256.Size]byte
}

type ControllerSupervisorCreateJobBody struct {
	Revision            uint64
	JobGeneration       credentialprotocol.SafeID
	MonitorGeneration   credentialprotocol.SafeID
	MountGeneration     credentialprotocol.SafeID
	CgroupGeneration    credentialprotocol.SafeID
	LimitSetID          credentialprotocol.SafeID
	MonitorConfigSHA256 [sha256.Size]byte
	CgroupConfigSHA256  [sha256.Size]byte
}

type ControllerSupervisorJobCreatedBody struct {
	Revision           uint64
	JobGeneration      credentialprotocol.SafeID
	MonitorGeneration  credentialprotocol.SafeID
	MountGeneration    credentialprotocol.SafeID
	CgroupGeneration   credentialprotocol.SafeID
	LimitSetID         credentialprotocol.SafeID
	CreateJobSHA256    [sha256.Size]byte
	MonitorReadySHA256 [sha256.Size]byte
}

type ControllerSupervisorLaunchShimBody struct {
	Revision          uint64
	JobGeneration     credentialprotocol.SafeID
	MonitorGeneration credentialprotocol.SafeID
	MountGeneration   credentialprotocol.SafeID
	CgroupGeneration  credentialprotocol.SafeID
	LaunchID          credentialprotocol.SafeID
	LimitSetID        credentialprotocol.SafeID
	ExecutableSHA256  [sha256.Size]byte
	LaunchBlockSHA256 [sha256.Size]byte
}

type ControllerSupervisorShimStartedBody struct {
	Revision          uint64
	JobGeneration     credentialprotocol.SafeID
	MonitorGeneration credentialprotocol.SafeID
	MountGeneration   credentialprotocol.SafeID
	CgroupGeneration  credentialprotocol.SafeID
	LaunchID          credentialprotocol.SafeID
	LaunchShimSHA256  [sha256.Size]byte
}

type ControllerSupervisorTerminateJobBody struct {
	Revision          uint64
	JobGeneration     credentialprotocol.SafeID
	MonitorGeneration credentialprotocol.SafeID
	MountGeneration   credentialprotocol.SafeID
	CgroupGeneration  credentialprotocol.SafeID
	Reason            ControllerSupervisorReason
}

type ControllerSupervisorDestroyJobBody ControllerSupervisorTerminateJobBody

type ControllerSupervisorEventBody struct {
	EventCode         ControllerSupervisorEventCode
	RequestType       ControllerSupervisorPacketType
	FailureCode       ControllerSupervisorFailureCode
	Revision          uint64
	JobGeneration     credentialprotocol.SafeID
	MonitorGeneration credentialprotocol.SafeID
	MountGeneration   credentialprotocol.SafeID
	CgroupGeneration  credentialprotocol.SafeID
	LaunchID          credentialprotocol.SafeID
	ExitCategory      ControllerSupervisorExitCategory
	ExitCode          int32
	ZeroPopulation    bool
	MonitorState      ControllerSupervisorMonitorState
	CleanupCategory   ControllerSupervisorCleanupCategory
}

type ControllerSupervisorControllerAttestationBody struct {
	Descriptor ProcessDescriptor
}

type ControllerSupervisorCompositionAcceptedBody struct {
	CompositionSHA256 [sha256.Size]byte
}

type ControllerSupervisorCloseNotifyBody struct {
	Reason credentialprotocol.CloseReason
}

func encodeControllerSupervisorSafeID(value credentialprotocol.SafeID) ([]byte, error) {
	if err := credentialprotocol.ValidateSafeID(value); err != nil {
		return nil, err
	}
	return credentialprotocol.EncodeBodyToken(string(value))
}

func decodeControllerSupervisorSafeID(encoded []byte) (credentialprotocol.SafeID, int, error) {
	value, consumed, err := credentialprotocol.DecodeBodyTokenPrefix(encoded)
	if err != nil {
		return "", 0, err
	}
	id := credentialprotocol.SafeID(value)
	if err := credentialprotocol.ValidateSafeID(id); err != nil {
		return "", 0, err
	}
	return id, consumed, nil
}

func appendControllerSupervisorSafeID(dst []byte, value credentialprotocol.SafeID) ([]byte, error) {
	encoded, err := encodeControllerSupervisorSafeID(value)
	if err != nil {
		return nil, err
	}
	return append(dst, encoded...), nil
}

func decodeControllerSupervisorIDs(encoded []byte, offset int, targets ...*credentialprotocol.SafeID) (int, error) {
	for _, target := range targets {
		if offset > len(encoded) {
			return 0, ErrControllerSupervisorBodyTruncated
		}
		value, consumed, err := decodeControllerSupervisorSafeID(encoded[offset:])
		if err != nil {
			return 0, err
		}
		*target = value
		offset += consumed
	}
	return offset, nil
}

func validateControllerSupervisorRevision(value uint64) error {
	if value == 0 {
		return ErrControllerSupervisorRevision
	}
	return nil
}

func validateControllerSupervisorLimitSet(value credentialprotocol.SafeID) error {
	if value != ControllerSupervisorLimitSetID {
		return ErrControllerSupervisorLimitSet
	}
	return credentialprotocol.ValidateSafeID(value)
}

func validateControllerSupervisorDigest(values ...[sha256.Size]byte) error {
	for _, value := range values {
		if controllerSupervisorZero32(value) {
			return ErrControllerSupervisorDigestZero
		}
	}
	return nil
}

func EncodeControllerSupervisorSupervisorReadyBody(body ControllerSupervisorSupervisorReadyBody) ([]byte, error) {
	if err := validateControllerSupervisorReadyBody(body); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, 4*(2+credentialprotocol.MaxSafeIDBytes)+sha256.Size)
	var err error
	for _, value := range []credentialprotocol.SafeID{body.BootGeneration, body.HelperGeneration, body.SupervisorGeneration, body.LimitSetID} {
		encoded, err = appendControllerSupervisorSafeID(encoded, value)
		if err != nil {
			return nil, err
		}
	}
	return append(encoded, body.SupervisorReadySHA256[:]...), nil
}

func DecodeControllerSupervisorSupervisorReadyBody(encoded []byte) (ControllerSupervisorSupervisorReadyBody, error) {
	var body ControllerSupervisorSupervisorReadyBody
	offset, err := decodeControllerSupervisorIDs(encoded, 0, &body.BootGeneration, &body.HelperGeneration, &body.SupervisorGeneration, &body.LimitSetID)
	if err != nil {
		return ControllerSupervisorSupervisorReadyBody{}, err
	}
	if len(encoded)-offset < sha256.Size {
		return ControllerSupervisorSupervisorReadyBody{}, ErrControllerSupervisorBodyTruncated
	}
	if len(encoded)-offset > sha256.Size {
		return ControllerSupervisorSupervisorReadyBody{}, ErrControllerSupervisorBodyTrailingData
	}
	copy(body.SupervisorReadySHA256[:], encoded[offset:])
	if err := validateControllerSupervisorReadyBody(body); err != nil {
		return ControllerSupervisorSupervisorReadyBody{}, err
	}
	return body, nil
}

func validateControllerSupervisorReadyBody(body ControllerSupervisorSupervisorReadyBody) error {
	for _, value := range []credentialprotocol.SafeID{body.BootGeneration, body.HelperGeneration, body.SupervisorGeneration} {
		if err := credentialprotocol.ValidateSafeID(value); err != nil {
			return err
		}
	}
	if err := validateControllerSupervisorLimitSet(body.LimitSetID); err != nil {
		return err
	}
	return validateControllerSupervisorDigest(body.SupervisorReadySHA256)
}

func encodeControllerSupervisorCreateFields(revision uint64, job, monitor, mount, cgroup, limit credentialprotocol.SafeID, first, second [32]byte) ([]byte, error) {
	if err := validateControllerSupervisorRevision(revision); err != nil {
		return nil, err
	}
	if err := validateControllerSupervisorLimitSet(limit); err != nil {
		return nil, err
	}
	if err := validateControllerSupervisorDigest(first, second); err != nil {
		return nil, err
	}
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, revision)
	var err error
	for _, value := range []credentialprotocol.SafeID{job, monitor, mount, cgroup, limit} {
		encoded, err = appendControllerSupervisorSafeID(encoded, value)
		if err != nil {
			return nil, err
		}
	}
	encoded = append(encoded, first[:]...)
	return append(encoded, second[:]...), nil
}

func decodeControllerSupervisorCreateFields(encoded []byte) (uint64, credentialprotocol.SafeID, credentialprotocol.SafeID, credentialprotocol.SafeID, credentialprotocol.SafeID, credentialprotocol.SafeID, [32]byte, [32]byte, error) {
	var job, monitor, mount, cgroup, limit credentialprotocol.SafeID
	var first, second [32]byte
	if len(encoded) < 8 {
		return 0, job, monitor, mount, cgroup, limit, first, second, ErrControllerSupervisorBodyTruncated
	}
	revision := binary.BigEndian.Uint64(encoded[:8])
	offset, err := decodeControllerSupervisorIDs(encoded, 8, &job, &monitor, &mount, &cgroup, &limit)
	if err != nil {
		return 0, job, monitor, mount, cgroup, limit, first, second, err
	}
	if len(encoded)-offset < 64 {
		return 0, job, monitor, mount, cgroup, limit, first, second, ErrControllerSupervisorBodyTruncated
	}
	if len(encoded)-offset > 64 {
		return 0, job, monitor, mount, cgroup, limit, first, second, ErrControllerSupervisorBodyTrailingData
	}
	copy(first[:], encoded[offset:offset+32])
	copy(second[:], encoded[offset+32:])
	if err := validateControllerSupervisorRevision(revision); err != nil {
		return 0, job, monitor, mount, cgroup, limit, first, second, err
	}
	if err := validateControllerSupervisorLimitSet(limit); err != nil {
		return 0, job, monitor, mount, cgroup, limit, first, second, err
	}
	if err := validateControllerSupervisorDigest(first, second); err != nil {
		return 0, job, monitor, mount, cgroup, limit, first, second, err
	}
	return revision, job, monitor, mount, cgroup, limit, first, second, nil
}

func EncodeControllerSupervisorCreateJobBody(body ControllerSupervisorCreateJobBody) ([]byte, error) {
	return encodeControllerSupervisorCreateFields(body.Revision, body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration, body.LimitSetID, body.MonitorConfigSHA256, body.CgroupConfigSHA256)
}
func DecodeControllerSupervisorCreateJobBody(encoded []byte) (ControllerSupervisorCreateJobBody, error) {
	r, j, m, mt, c, l, a, b, err := decodeControllerSupervisorCreateFields(encoded)
	if err != nil {
		return ControllerSupervisorCreateJobBody{}, err
	}
	return ControllerSupervisorCreateJobBody{r, j, m, mt, c, l, a, b}, nil
}
func EncodeControllerSupervisorJobCreatedBody(body ControllerSupervisorJobCreatedBody) ([]byte, error) {
	return encodeControllerSupervisorCreateFields(body.Revision, body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration, body.LimitSetID, body.CreateJobSHA256, body.MonitorReadySHA256)
}
func DecodeControllerSupervisorJobCreatedBody(encoded []byte) (ControllerSupervisorJobCreatedBody, error) {
	r, j, m, mt, c, l, a, b, err := decodeControllerSupervisorCreateFields(encoded)
	if err != nil {
		return ControllerSupervisorJobCreatedBody{}, err
	}
	return ControllerSupervisorJobCreatedBody{r, j, m, mt, c, l, a, b}, nil
}

func EncodeControllerSupervisorLaunchShimBody(body ControllerSupervisorLaunchShimBody) ([]byte, error) {
	if err := validateControllerSupervisorRevision(body.Revision); err != nil {
		return nil, err
	}
	if err := validateControllerSupervisorLimitSet(body.LimitSetID); err != nil {
		return nil, err
	}
	if err := validateControllerSupervisorDigest(body.ExecutableSHA256, body.LaunchBlockSHA256); err != nil {
		return nil, err
	}
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, body.Revision)
	var err error
	for _, value := range []credentialprotocol.SafeID{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration, body.LaunchID, body.LimitSetID} {
		encoded, err = appendControllerSupervisorSafeID(encoded, value)
		if err != nil {
			return nil, err
		}
	}
	encoded = append(encoded, body.ExecutableSHA256[:]...)
	return append(encoded, body.LaunchBlockSHA256[:]...), nil
}
func DecodeControllerSupervisorLaunchShimBody(encoded []byte) (ControllerSupervisorLaunchShimBody, error) {
	var body ControllerSupervisorLaunchShimBody
	if len(encoded) < 8 {
		return body, ErrControllerSupervisorBodyTruncated
	}
	body.Revision = binary.BigEndian.Uint64(encoded[:8])
	offset, err := decodeControllerSupervisorIDs(encoded, 8, &body.JobGeneration, &body.MonitorGeneration, &body.MountGeneration, &body.CgroupGeneration, &body.LaunchID, &body.LimitSetID)
	if err != nil {
		return ControllerSupervisorLaunchShimBody{}, err
	}
	if len(encoded)-offset < 64 {
		return ControllerSupervisorLaunchShimBody{}, ErrControllerSupervisorBodyTruncated
	}
	if len(encoded)-offset > 64 {
		return ControllerSupervisorLaunchShimBody{}, ErrControllerSupervisorBodyTrailingData
	}
	copy(body.ExecutableSHA256[:], encoded[offset:offset+32])
	copy(body.LaunchBlockSHA256[:], encoded[offset+32:])
	if _, err := EncodeControllerSupervisorLaunchShimBody(body); err != nil {
		return ControllerSupervisorLaunchShimBody{}, err
	}
	return body, nil
}

func EncodeControllerSupervisorShimStartedBody(body ControllerSupervisorShimStartedBody) ([]byte, error) {
	if err := validateControllerSupervisorRevision(body.Revision); err != nil {
		return nil, err
	}
	if err := validateControllerSupervisorDigest(body.LaunchShimSHA256); err != nil {
		return nil, err
	}
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, body.Revision)
	var err error
	for _, value := range []credentialprotocol.SafeID{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration, body.LaunchID} {
		encoded, err = appendControllerSupervisorSafeID(encoded, value)
		if err != nil {
			return nil, err
		}
	}
	return append(encoded, body.LaunchShimSHA256[:]...), nil
}
func DecodeControllerSupervisorShimStartedBody(encoded []byte) (ControllerSupervisorShimStartedBody, error) {
	var body ControllerSupervisorShimStartedBody
	if len(encoded) < 8 {
		return body, ErrControllerSupervisorBodyTruncated
	}
	body.Revision = binary.BigEndian.Uint64(encoded[:8])
	offset, err := decodeControllerSupervisorIDs(encoded, 8, &body.JobGeneration, &body.MonitorGeneration, &body.MountGeneration, &body.CgroupGeneration, &body.LaunchID)
	if err != nil {
		return ControllerSupervisorShimStartedBody{}, err
	}
	if len(encoded)-offset < 32 {
		return ControllerSupervisorShimStartedBody{}, ErrControllerSupervisorBodyTruncated
	}
	if len(encoded)-offset > 32 {
		return ControllerSupervisorShimStartedBody{}, ErrControllerSupervisorBodyTrailingData
	}
	copy(body.LaunchShimSHA256[:], encoded[offset:])
	if _, err := EncodeControllerSupervisorShimStartedBody(body); err != nil {
		return ControllerSupervisorShimStartedBody{}, err
	}
	return body, nil
}

func validateControllerSupervisorReason(value ControllerSupervisorReason, destroy bool) error {
	if err := ValidateControllerSupervisorReason(value); err != nil {
		return err
	}
	if destroy && value > ControllerSupervisorReasonDaemonShutdown {
		return ErrControllerSupervisorReason
	}
	return nil
}

func encodeControllerSupervisorEndJobBody(body ControllerSupervisorTerminateJobBody, destroy bool) ([]byte, error) {
	if err := validateControllerSupervisorRevision(body.Revision); err != nil {
		return nil, err
	}
	if err := validateControllerSupervisorReason(body.Reason, destroy); err != nil {
		return nil, err
	}
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, body.Revision)
	var err error
	for _, value := range []credentialprotocol.SafeID{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration} {
		encoded, err = appendControllerSupervisorSafeID(encoded, value)
		if err != nil {
			return nil, err
		}
	}
	return append(encoded, byte(body.Reason)), nil
}
func decodeControllerSupervisorEndJobBody(encoded []byte, destroy bool) (ControllerSupervisorTerminateJobBody, error) {
	var body ControllerSupervisorTerminateJobBody
	if len(encoded) < 8 {
		return body, ErrControllerSupervisorBodyTruncated
	}
	body.Revision = binary.BigEndian.Uint64(encoded[:8])
	offset, err := decodeControllerSupervisorIDs(encoded, 8, &body.JobGeneration, &body.MonitorGeneration, &body.MountGeneration, &body.CgroupGeneration)
	if err != nil {
		return ControllerSupervisorTerminateJobBody{}, err
	}
	if len(encoded)-offset < 1 {
		return body, ErrControllerSupervisorBodyTruncated
	}
	if len(encoded)-offset > 1 {
		return body, ErrControllerSupervisorBodyTrailingData
	}
	body.Reason = ControllerSupervisorReason(encoded[offset])
	if _, err := encodeControllerSupervisorEndJobBody(body, destroy); err != nil {
		return ControllerSupervisorTerminateJobBody{}, err
	}
	return body, nil
}
func EncodeControllerSupervisorTerminateJobBody(body ControllerSupervisorTerminateJobBody) ([]byte, error) {
	return encodeControllerSupervisorEndJobBody(body, false)
}
func DecodeControllerSupervisorTerminateJobBody(encoded []byte) (ControllerSupervisorTerminateJobBody, error) {
	return decodeControllerSupervisorEndJobBody(encoded, false)
}
func EncodeControllerSupervisorDestroyJobBody(body ControllerSupervisorDestroyJobBody) ([]byte, error) {
	return encodeControllerSupervisorEndJobBody(ControllerSupervisorTerminateJobBody(body), true)
}
func DecodeControllerSupervisorDestroyJobBody(encoded []byte) (ControllerSupervisorDestroyJobBody, error) {
	body, err := decodeControllerSupervisorEndJobBody(encoded, true)
	return ControllerSupervisorDestroyJobBody(body), err
}

func encodeControllerSupervisorOptionalID(value credentialprotocol.SafeID) ([]byte, error) {
	if value == "" {
		return []byte{0, 0}, nil
	}
	return encodeControllerSupervisorSafeID(value)
}
func decodeControllerSupervisorOptionalID(encoded []byte) (credentialprotocol.SafeID, int, error) {
	if len(encoded) < 2 {
		return "", 0, ErrControllerSupervisorBodyTruncated
	}
	if binary.BigEndian.Uint16(encoded[:2]) == 0 {
		return "", 2, nil
	}
	return decodeControllerSupervisorSafeID(encoded)
}

func ValidateControllerSupervisorEventBody(body ControllerSupervisorEventBody) error {
	if err := ValidateControllerSupervisorEventCode(body.EventCode); err != nil {
		return err
	}
	if body.RequestType != ControllerSupervisorPacketTypeCreateJob && body.RequestType != ControllerSupervisorPacketTypeLaunchShim && body.RequestType != ControllerSupervisorPacketTypeTerminateJob && body.RequestType != ControllerSupervisorPacketTypeDestroyJob {
		return ErrControllerSupervisorFailureCorrelation
	}
	if err := ValidateControllerSupervisorFailureCode(body.FailureCode); err != nil {
		return err
	}
	if err := validateControllerSupervisorRevision(body.Revision); err != nil {
		return err
	}
	for _, value := range []credentialprotocol.SafeID{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration} {
		if err := credentialprotocol.ValidateSafeID(value); err != nil {
			return err
		}
	}
	if body.LaunchID != "" {
		if err := credentialprotocol.ValidateSafeID(body.LaunchID); err != nil {
			return err
		}
	}
	if err := ValidateControllerSupervisorExitCategory(body.ExitCategory); err != nil {
		return err
	}
	if err := ValidateControllerSupervisorMonitorState(body.MonitorState); err != nil {
		return err
	}
	if err := ValidateControllerSupervisorCleanupCategory(body.CleanupCategory); err != nil {
		return err
	}
	validExit := false
	switch body.ExitCategory {
	case ControllerSupervisorExitNotApplicable, ControllerSupervisorExitUnknown:
		validExit = body.ExitCode == 0
	case ControllerSupervisorExitExited:
		validExit = body.ExitCode >= 0 && body.ExitCode <= 255
	case ControllerSupervisorExitSignaled:
		validExit = body.ExitCode >= 1 && body.ExitCode <= 64
	case ControllerSupervisorExitLaunchTransitionFailed:
		validExit = body.ExitCode == 1
	}
	if !validExit {
		return ErrControllerSupervisorExitCode
	}
	launchPresent := body.LaunchID != ""
	switch body.EventCode {
	case ControllerSupervisorEventShimExited:
		if body.RequestType != ControllerSupervisorPacketTypeLaunchShim || body.FailureCode != 0 || !launchPresent || (body.ExitCategory != ControllerSupervisorExitExited && body.ExitCategory != ControllerSupervisorExitSignaled && body.ExitCategory != ControllerSupervisorExitLaunchTransitionFailed) || (body.MonitorState != ControllerSupervisorMonitorReady && body.MonitorState != ControllerSupervisorMonitorCleanupPending) || body.CleanupCategory != ControllerSupervisorCleanupNotApplicable {
			return ErrControllerSupervisorEventUnion
		}
	case ControllerSupervisorEventOperationFailed:
		if body.FailureCode == 0 || launchPresent != (body.RequestType == ControllerSupervisorPacketTypeLaunchShim) || body.ExitCategory != ControllerSupervisorExitNotApplicable || body.ExitCode != 0 {
			return ErrControllerSupervisorEventUnion
		}
		if !controllerSupervisorFailureAllowed(body.RequestType, body.FailureCode) {
			return ErrControllerSupervisorFailureCorrelation
		}
		if body.FailureCode == ControllerSupervisorFailureResourceLimit {
			if body.CleanupCategory != ControllerSupervisorCleanupNotApplicable {
				return ErrControllerSupervisorEventUnion
			}
		} else if body.CleanupCategory == ControllerSupervisorCleanupNotApplicable {
			return ErrControllerSupervisorEventUnion
		}
	case ControllerSupervisorEventJobTerminated:
		if body.RequestType != ControllerSupervisorPacketTypeTerminateJob || body.FailureCode != 0 || launchPresent || body.ExitCategory != ControllerSupervisorExitNotApplicable || body.ExitCode != 0 || !body.ZeroPopulation || (body.MonitorState != ControllerSupervisorMonitorReady && body.MonitorState != ControllerSupervisorMonitorCleanupPending) || body.CleanupCategory != ControllerSupervisorCleanupNotApplicable {
			return ErrControllerSupervisorEventUnion
		}
	case ControllerSupervisorEventJobDestroyed:
		if body.RequestType != ControllerSupervisorPacketTypeDestroyJob || body.FailureCode != 0 || launchPresent || body.ExitCategory != ControllerSupervisorExitNotApplicable || body.ExitCode != 0 || !body.ZeroPopulation || body.MonitorState != ControllerSupervisorMonitorAbsent || body.CleanupCategory != ControllerSupervisorCleanupComplete {
			return ErrControllerSupervisorEventUnion
		}
	case ControllerSupervisorEventCleanupObserved:
		if body.FailureCode != ControllerSupervisorFailureCleanupIncomplete || launchPresent != (body.RequestType == ControllerSupervisorPacketTypeLaunchShim) || body.ExitCategory != ControllerSupervisorExitNotApplicable || body.ExitCode != 0 || (body.CleanupCategory != ControllerSupervisorCleanupRetryRequired && body.CleanupCategory != ControllerSupervisorCleanupStopVMRequired) {
			return ErrControllerSupervisorEventUnion
		}
	}
	return nil
}

func controllerSupervisorFailureAllowed(request ControllerSupervisorPacketType, failure ControllerSupervisorFailureCode) bool {
	switch request {
	case ControllerSupervisorPacketTypeCreateJob:
		return failure == 1 || failure == 2 || failure == 6 || failure == 7 || failure == 8
	case ControllerSupervisorPacketTypeLaunchShim:
		return failure == 1 || failure == 3 || failure == 6 || failure == 7 || failure == 8 || failure == 9
	case ControllerSupervisorPacketTypeTerminateJob:
		return failure == 4 || failure == 6 || failure == 7 || failure == 8 || failure == 9
	case ControllerSupervisorPacketTypeDestroyJob:
		return failure == 5 || failure == 6 || failure == 7 || failure == 8
	default:
		return false
	}
}

func EncodeControllerSupervisorEventBody(body ControllerSupervisorEventBody) ([]byte, error) {
	if err := ValidateControllerSupervisorEventBody(body); err != nil {
		return nil, err
	}
	encoded := []byte{byte(body.EventCode), byte(body.RequestType), byte(body.FailureCode), 0}
	encoded = binary.BigEndian.AppendUint64(encoded, body.Revision)
	var err error
	for _, value := range []credentialprotocol.SafeID{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration} {
		encoded, err = appendControllerSupervisorSafeID(encoded, value)
		if err != nil {
			return nil, err
		}
	}
	optional, err := encodeControllerSupervisorOptionalID(body.LaunchID)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, optional...)
	encoded = append(encoded, byte(body.ExitCategory))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(body.ExitCode))
	zero := byte(0)
	if body.ZeroPopulation {
		zero = 1
	}
	return append(encoded, zero, byte(body.MonitorState), byte(body.CleanupCategory)), nil
}
func DecodeControllerSupervisorEventBody(encoded []byte) (ControllerSupervisorEventBody, error) {
	var body ControllerSupervisorEventBody
	if len(encoded) < 12 {
		return body, ErrControllerSupervisorBodyTruncated
	}
	if encoded[3] != 0 {
		return body, ErrControllerSupervisorReserved
	}
	body.EventCode = ControllerSupervisorEventCode(encoded[0])
	body.RequestType = ControllerSupervisorPacketType(encoded[1])
	body.FailureCode = ControllerSupervisorFailureCode(encoded[2])
	body.Revision = binary.BigEndian.Uint64(encoded[4:12])
	offset, err := decodeControllerSupervisorIDs(encoded, 12, &body.JobGeneration, &body.MonitorGeneration, &body.MountGeneration, &body.CgroupGeneration)
	if err != nil {
		return ControllerSupervisorEventBody{}, err
	}
	launchID, offsetAdd, err := decodeControllerSupervisorOptionalID(encoded[offset:])
	if err != nil {
		return ControllerSupervisorEventBody{}, err
	}
	body.LaunchID = launchID
	offset += offsetAdd
	if len(encoded)-offset < 8 {
		return ControllerSupervisorEventBody{}, ErrControllerSupervisorBodyTruncated
	}
	if len(encoded)-offset > 8 {
		return ControllerSupervisorEventBody{}, ErrControllerSupervisorBodyTrailingData
	}
	body.ExitCategory = ControllerSupervisorExitCategory(encoded[offset])
	body.ExitCode = int32(binary.BigEndian.Uint32(encoded[offset+1 : offset+5]))
	if encoded[offset+5] > 1 {
		return ControllerSupervisorEventBody{}, ErrControllerSupervisorEventUnion
	}
	body.ZeroPopulation = encoded[offset+5] == 1
	body.MonitorState = ControllerSupervisorMonitorState(encoded[offset+6])
	body.CleanupCategory = ControllerSupervisorCleanupCategory(encoded[offset+7])
	if err := ValidateControllerSupervisorEventBody(body); err != nil {
		return ControllerSupervisorEventBody{}, err
	}
	return body, nil
}

func EncodeControllerSupervisorControllerAttestationBody(body ControllerSupervisorControllerAttestationBody) ([]byte, error) {
	if body.Descriptor.Role != ProcessRoleHelper {
		return nil, ErrControllerSupervisorDescriptorRole
	}
	descriptor, err := EncodeProcessDescriptor(body.Descriptor)
	if err != nil {
		return nil, err
	}
	if len(descriptor) < 1 || len(descriptor) > MaxProcessDescriptorBytes {
		return nil, ErrControllerSupervisorDescriptorLength
	}
	encoded := make([]byte, 2, 2+len(descriptor))
	binary.BigEndian.PutUint16(encoded, uint16(len(descriptor)))
	return append(encoded, descriptor...), nil
}
func DecodeControllerSupervisorControllerAttestationBody(encoded []byte) (ControllerSupervisorControllerAttestationBody, error) {
	if len(encoded) < 2 {
		return ControllerSupervisorControllerAttestationBody{}, ErrControllerSupervisorDescriptorLength
	}
	length := int(binary.BigEndian.Uint16(encoded[:2]))
	if length < 1 || length > MaxProcessDescriptorBytes || len(encoded)-2 < length {
		return ControllerSupervisorControllerAttestationBody{}, ErrControllerSupervisorDescriptorLength
	}
	if len(encoded)-2 > length {
		return ControllerSupervisorControllerAttestationBody{}, ErrControllerSupervisorBodyTrailingData
	}
	descriptor, err := DecodeProcessDescriptor(encoded[2:])
	if err != nil {
		return ControllerSupervisorControllerAttestationBody{}, err
	}
	if descriptor.Role != ProcessRoleHelper {
		return ControllerSupervisorControllerAttestationBody{}, ErrControllerSupervisorDescriptorRole
	}
	canonical, err := EncodeProcessDescriptor(descriptor)
	if err != nil || len(canonical) != length || !bytes.Equal(canonical, encoded[2:]) {
		return ControllerSupervisorControllerAttestationBody{}, ErrControllerSupervisorDescriptorLength
	}
	return ControllerSupervisorControllerAttestationBody{Descriptor: descriptor}, nil
}
func EncodeControllerSupervisorCompositionAcceptedBody(body ControllerSupervisorCompositionAcceptedBody) ([]byte, error) {
	if err := validateControllerSupervisorDigest(body.CompositionSHA256); err != nil {
		return nil, err
	}
	return append([]byte(nil), body.CompositionSHA256[:]...), nil
}
func DecodeControllerSupervisorCompositionAcceptedBody(encoded []byte) (ControllerSupervisorCompositionAcceptedBody, error) {
	if len(encoded) < 32 {
		return ControllerSupervisorCompositionAcceptedBody{}, ErrControllerSupervisorBodyTruncated
	}
	if len(encoded) > 32 {
		return ControllerSupervisorCompositionAcceptedBody{}, ErrControllerSupervisorBodyTrailingData
	}
	var body ControllerSupervisorCompositionAcceptedBody
	copy(body.CompositionSHA256[:], encoded)
	if err := validateControllerSupervisorDigest(body.CompositionSHA256); err != nil {
		return ControllerSupervisorCompositionAcceptedBody{}, err
	}
	return body, nil
}
func EncodeControllerSupervisorCloseNotifyBody(body ControllerSupervisorCloseNotifyBody) ([]byte, error) {
	if err := credentialprotocol.ValidateCloseReason(body.Reason); err != nil {
		return nil, err
	}
	return []byte{byte(body.Reason)}, nil
}
func DecodeControllerSupervisorCloseNotifyBody(encoded []byte) (ControllerSupervisorCloseNotifyBody, error) {
	if len(encoded) < 1 {
		return ControllerSupervisorCloseNotifyBody{}, ErrControllerSupervisorBodyTruncated
	}
	if len(encoded) > 1 {
		return ControllerSupervisorCloseNotifyBody{}, ErrControllerSupervisorBodyTrailingData
	}
	body := ControllerSupervisorCloseNotifyBody{Reason: credentialprotocol.CloseReason(encoded[0])}
	if err := credentialprotocol.ValidateCloseReason(body.Reason); err != nil {
		return ControllerSupervisorCloseNotifyBody{}, err
	}
	return body, nil
}

func ControllerSupervisorLaunchID(requestID [16]byte) (credentialprotocol.SafeID, error) {
	if controllerSupervisorZero16(requestID) {
		return "", ErrControllerSupervisorLaunchID
	}
	value := credentialprotocol.SafeID(base64.RawURLEncoding.EncodeToString(requestID[:]))
	if len(value) != 22 || credentialprotocol.ValidateSafeID(value) != nil {
		return "", ErrControllerSupervisorLaunchID
	}
	return value, nil
}
func ValidateControllerSupervisorLaunchID(requestID [16]byte, launchID credentialprotocol.SafeID) error {
	expected, err := ControllerSupervisorLaunchID(requestID)
	if err != nil || launchID != expected {
		return ErrControllerSupervisorLaunchID
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(launchID))
	if err != nil || len(decoded) != 16 {
		return ErrControllerSupervisorLaunchID
	}
	var actual [16]byte
	copy(actual[:], decoded)
	if actual != requestID {
		return ErrControllerSupervisorLaunchID
	}
	return nil
}
