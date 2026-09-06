package l8composition

import (
	"crypto/sha256"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	controllerMonitorReadyDomain          = "hal/l8/controller-monitor/monitor-ready/v1"
	controllerMonitorPrepareDomain        = "hal/l8/controller-monitor/prepare-postinspection/v1"
	controllerMonitorEndpointConfigDomain = "hal/l8/controller-monitor/ssh-endpoint-config/v1"
	controllerMonitorEndpointDomain       = "hal/l8/controller-monitor/ssh-endpoint/v1"
	controllerMonitorEventDomain          = "hal/l8/controller-monitor/event-postinspection/v1"
	controllerMonitorCleanupDomain        = "hal/l8/controller-monitor/cleanup/v1"
)

func ControllerMonitorReadySHA256(job [32]byte, body ControllerMonitorReadyBody) ([32]byte, error) {
	if controllerMonitorZero32(job) || body.Revision != 1 || controllerMonitorZero32(body.CreateJobSHA256) {
		return [32]byte{}, ErrControllerMonitorDigest
	}
	for _, value := range []string{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration, body.LimitSetID} {
		if !validControllerMonitorSafeID(value) {
			return [32]byte{}, ErrControllerMonitorGeneration
		}
	}
	if body.LimitSetID != ControllerMonitorLimitSetID {
		return [32]byte{}, ErrControllerMonitorLimitSet
	}
	input := opaque16(controllerMonitorReadyDomain)
	input = append(input, job[:]...)
	input = appendUint64CM(input, body.Revision)
	var err error
	for _, value := range []string{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration, body.LimitSetID} {
		input, err = appendControllerMonitorToken(input, value)
		if err != nil {
			return [32]byte{}, err
		}
	}
	input = append(input, body.CreateJobSHA256[:]...)
	return sha256.Sum256(input), nil
}

func ControllerMonitorPreparePostinspectionSHA256(job [32]byte, revision uint64, monitorGeneration, mountGeneration string, manifest, transaction [32]byte, fileCount uint16, aggregate uint64) ([32]byte, error) {
	if controllerMonitorZero32(job) || revision != 1 || !validControllerMonitorSafeID(monitorGeneration) || !validControllerMonitorSafeID(mountGeneration) || controllerMonitorZero32(manifest) || controllerMonitorZero32(transaction) || fileCount > credentialprotocol.MaxHelperBindings || aggregate > credentialprotocol.MaxHelperFileAggregateBytes {
		return [32]byte{}, ErrControllerMonitorDigest
	}
	input := opaque16(controllerMonitorPrepareDomain)
	input = append(input, job[:]...)
	input = appendUint64CM(input, revision)
	input, _ = appendControllerMonitorToken(input, monitorGeneration)
	input, _ = appendControllerMonitorToken(input, mountGeneration)
	input = append(input, manifest[:]...)
	input = append(input, transaction[:]...)
	input = appendUint16CM(input, fileCount)
	input = appendUint64CM(input, aggregate)
	return sha256.Sum256(input), nil
}

func ControllerMonitorEndpointConfigSHA256(job [32]byte, revision uint64, bindingIndex uint16, bindingID, endpointGeneration, mountGeneration string, manifest [32]byte) ([32]byte, error) {
	if controllerMonitorZero32(job) || revision != 1 || bindingIndex >= credentialprotocol.MaxHelperBindings || !validControllerMonitorSafeID(bindingID) || !validControllerMonitorSafeID(endpointGeneration) || !validControllerMonitorSafeID(mountGeneration) || controllerMonitorZero32(manifest) {
		return [32]byte{}, ErrControllerMonitorDigest
	}
	input := opaque16(controllerMonitorEndpointConfigDomain)
	input = append(input, job[:]...)
	input = appendUint64CM(input, revision)
	input = appendUint16CM(input, bindingIndex)
	input, _ = appendControllerMonitorToken(input, bindingID)
	input, _ = appendControllerMonitorToken(input, endpointGeneration)
	input, _ = appendControllerMonitorToken(input, mountGeneration)
	input = append(input, manifest[:]...)
	return sha256.Sum256(input), nil
}

func ControllerMonitorEndpointSHA256(job, endpointConfig [32]byte, endpointGeneration, monitorGeneration, mountGeneration string) ([32]byte, error) {
	if controllerMonitorZero32(job) || controllerMonitorZero32(endpointConfig) || !validControllerMonitorSafeID(endpointGeneration) || !validControllerMonitorSafeID(monitorGeneration) || !validControllerMonitorSafeID(mountGeneration) {
		return [32]byte{}, ErrControllerMonitorDigest
	}
	input := opaque16(controllerMonitorEndpointDomain)
	input = append(input, job[:]...)
	input = append(input, endpointConfig[:]...)
	input, _ = appendControllerMonitorToken(input, endpointGeneration)
	input, _ = appendControllerMonitorToken(input, monitorGeneration)
	input, _ = appendControllerMonitorToken(input, mountGeneration)
	return sha256.Sum256(input), nil
}

func ControllerMonitorEventPostinspectionSHA256(job [32]byte, event ControllerMonitorEventCode, failure ControllerMonitorFailureCode, cleanup ControllerMonitorCleanupCategory, revision uint64, eventRequestID [16]byte, monitorGeneration, mountGeneration string) ([32]byte, error) {
	if controllerMonitorZero32(job) || controllerMonitorZero16(eventRequestID) || revision != 1 || ValidateControllerMonitorEventCode(event) != nil || ValidateControllerMonitorFailureCode(failure) != nil || ValidateControllerMonitorCleanupCategory(cleanup) != nil || !validControllerMonitorSafeID(monitorGeneration) || !validControllerMonitorSafeID(mountGeneration) {
		return [32]byte{}, ErrControllerMonitorDigest
	}
	eventID := controllerMonitorEventID(eventRequestID)
	probe := ControllerMonitorEventBody{EventCode: event, FailureCode: failure, CleanupCategory: cleanup, Revision: revision, EventID: eventID, MountGeneration: mountGeneration, PostinspectionSHA256: [32]byte{1}}
	if ValidateControllerMonitorEventBody(probe) != nil {
		return [32]byte{}, ErrControllerMonitorEvent
	}
	input := opaque16(controllerMonitorEventDomain)
	input = append(input, job[:]...)
	input = append(input, byte(event), byte(failure), byte(cleanup))
	input = appendUint64CM(input, revision)
	input, _ = appendControllerMonitorToken(input, eventID)
	input, _ = appendControllerMonitorToken(input, monitorGeneration)
	input, _ = appendControllerMonitorToken(input, mountGeneration)
	return sha256.Sum256(input), nil
}

func ControllerMonitorCleanupSHA256(job [32]byte, revision uint64, reason credentialprotocol.RevokeReason, monitorGeneration, mountGeneration, endpointGeneration string, entriesAbsent, socketAbsent, mountAbsent bool) ([32]byte, error) {
	if controllerMonitorZero32(job) || revision != 1 || credentialprotocol.ValidateRevokeReason(reason) != nil || !validControllerMonitorSafeID(monitorGeneration) || !validControllerMonitorSafeID(mountGeneration) || endpointGeneration != "" && !validControllerMonitorSafeID(endpointGeneration) {
		return [32]byte{}, ErrControllerMonitorDigest
	}
	input := opaque16(controllerMonitorCleanupDomain)
	input = append(input, job[:]...)
	input = appendUint64CM(input, revision)
	input = append(input, byte(reason))
	input, _ = appendControllerMonitorToken(input, monitorGeneration)
	input, _ = appendControllerMonitorToken(input, mountGeneration)
	input = appendControllerMonitorOptionalToken(input, endpointGeneration)
	input = append(input, boolByteCM(entriesAbsent), boolByteCM(socketAbsent), boolByteCM(mountAbsent))
	return sha256.Sum256(input), nil
}

func appendControllerMonitorToken(encoded []byte, value string) ([]byte, error) {
	token, err := credentialprotocol.EncodeBodyToken(value)
	if err != nil {
		return nil, err
	}
	return append(encoded, token...), nil
}
func appendControllerMonitorOptionalToken(encoded []byte, value string) []byte {
	if value == "" {
		return append(encoded, 0, 0)
	}
	token, _ := credentialprotocol.EncodeBodyToken(value)
	return append(encoded, token...)
}
