package l8composition

import "fmt"

func controllerMonitorFormat(state fmt.State, name string) { _, _ = state.Write([]byte(name)) }
func controllerMonitorMarshalDenied() ([]byte, error)      { return nil, ErrControllerMonitorSerialization }
func controllerMonitorUnmarshalDenied([]byte) error        { return ErrControllerMonitorSerialization }

func (ControllerMonitorPacketType) String() string   { return "ControllerMonitorPacketType" }
func (ControllerMonitorPacketType) GoString() string { return "ControllerMonitorPacketType" }
func (ControllerMonitorPacketType) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorPacketType")
}
func (ControllerMonitorPacketType) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPacketType) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPacketType) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorPacketType) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorPacketType) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorPacketType) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorDirection) String() string   { return "ControllerMonitorDirection" }
func (ControllerMonitorDirection) GoString() string { return "ControllerMonitorDirection" }
func (ControllerMonitorDirection) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorDirection")
}
func (ControllerMonitorDirection) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorDirection) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorDirection) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorDirection) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorDirection) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorDirection) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorRightKind) String() string   { return "ControllerMonitorRightKind" }
func (ControllerMonitorRightKind) GoString() string { return "ControllerMonitorRightKind" }
func (ControllerMonitorRightKind) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorRightKind")
}
func (ControllerMonitorRightKind) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorRightKind) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorRightKind) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorRightKind) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorRightKind) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorRightKind) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorRightAccess) String() string   { return "ControllerMonitorRightAccess" }
func (ControllerMonitorRightAccess) GoString() string { return "ControllerMonitorRightAccess" }
func (ControllerMonitorRightAccess) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorRightAccess")
}
func (ControllerMonitorRightAccess) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorRightAccess) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorRightAccess) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorRightAccess) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorRightAccess) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorRightAccess) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorFailureCode) String() string   { return "ControllerMonitorFailureCode" }
func (ControllerMonitorFailureCode) GoString() string { return "ControllerMonitorFailureCode" }
func (ControllerMonitorFailureCode) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorFailureCode")
}
func (ControllerMonitorFailureCode) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorFailureCode) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorFailureCode) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorFailureCode) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorFailureCode) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorFailureCode) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorEventCode) String() string   { return "ControllerMonitorEventCode" }
func (ControllerMonitorEventCode) GoString() string { return "ControllerMonitorEventCode" }
func (ControllerMonitorEventCode) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorEventCode")
}
func (ControllerMonitorEventCode) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorEventCode) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorEventCode) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorEventCode) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorEventCode) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorEventCode) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorCleanupCategory) String() string   { return "ControllerMonitorCleanupCategory" }
func (ControllerMonitorCleanupCategory) GoString() string { return "ControllerMonitorCleanupCategory" }
func (ControllerMonitorCleanupCategory) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorCleanupCategory")
}
func (ControllerMonitorCleanupCategory) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorCleanupCategory) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorCleanupCategory) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorCleanupCategory) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorCleanupCategory) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorCleanupCategory) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorHeader) String() string   { return "ControllerMonitorHeader" }
func (ControllerMonitorHeader) GoString() string { return "ControllerMonitorHeader" }
func (ControllerMonitorHeader) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorHeader")
}
func (ControllerMonitorHeader) MarshalJSON() ([]byte, error) { return controllerMonitorMarshalDenied() }
func (ControllerMonitorHeader) MarshalText() ([]byte, error) { return controllerMonitorMarshalDenied() }
func (ControllerMonitorHeader) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorHeader) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorHeader) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorHeader) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorKernelCredential) String() string { return "ControllerMonitorKernelCredential" }
func (ControllerMonitorKernelCredential) GoString() string {
	return "ControllerMonitorKernelCredential"
}
func (ControllerMonitorKernelCredential) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorKernelCredential")
}
func (ControllerMonitorKernelCredential) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorKernelCredential) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorKernelCredential) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorKernelCredential) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorKernelCredential) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorKernelCredential) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorRightMetadata) String() string   { return "ControllerMonitorRightMetadata" }
func (ControllerMonitorRightMetadata) GoString() string { return "ControllerMonitorRightMetadata" }
func (ControllerMonitorRightMetadata) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorRightMetadata")
}
func (ControllerMonitorRightMetadata) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorRightMetadata) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorRightMetadata) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorRightMetadata) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorRightMetadata) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorRightMetadata) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorReceiveMetadata) String() string   { return "ControllerMonitorReceiveMetadata" }
func (ControllerMonitorReceiveMetadata) GoString() string { return "ControllerMonitorReceiveMetadata" }
func (ControllerMonitorReceiveMetadata) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorReceiveMetadata")
}
func (ControllerMonitorReceiveMetadata) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorReceiveMetadata) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorReceiveMetadata) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorReceiveMetadata) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorReceiveMetadata) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorReceiveMetadata) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorReadyBody) String() string   { return "ControllerMonitorReadyBody" }
func (ControllerMonitorReadyBody) GoString() string { return "ControllerMonitorReadyBody" }
func (ControllerMonitorReadyBody) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorReadyBody")
}
func (ControllerMonitorReadyBody) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorReadyBody) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorReadyBody) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorReadyBody) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorReadyBody) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorReadyBody) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorCreateSSHEndpointBody) String() string {
	return "ControllerMonitorCreateSSHEndpointBody"
}
func (ControllerMonitorCreateSSHEndpointBody) GoString() string {
	return "ControllerMonitorCreateSSHEndpointBody"
}
func (ControllerMonitorCreateSSHEndpointBody) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorCreateSSHEndpointBody")
}
func (ControllerMonitorCreateSSHEndpointBody) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorCreateSSHEndpointBody) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorCreateSSHEndpointBody) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorCreateSSHEndpointBody) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorCreateSSHEndpointBody) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorCreateSSHEndpointBody) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorPrepareResult) String() string   { return "ControllerMonitorPrepareResult" }
func (ControllerMonitorPrepareResult) GoString() string { return "ControllerMonitorPrepareResult" }
func (ControllerMonitorPrepareResult) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorPrepareResult")
}
func (ControllerMonitorPrepareResult) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPrepareResult) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPrepareResult) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorPrepareResult) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorPrepareResult) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorPrepareResult) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorSSHEndpointResult) String() string {
	return "ControllerMonitorSSHEndpointResult"
}
func (ControllerMonitorSSHEndpointResult) GoString() string {
	return "ControllerMonitorSSHEndpointResult"
}
func (ControllerMonitorSSHEndpointResult) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorSSHEndpointResult")
}
func (ControllerMonitorSSHEndpointResult) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorSSHEndpointResult) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorSSHEndpointResult) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorSSHEndpointResult) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorSSHEndpointResult) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorSSHEndpointResult) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorRevokeResult) String() string   { return "ControllerMonitorRevokeResult" }
func (ControllerMonitorRevokeResult) GoString() string { return "ControllerMonitorRevokeResult" }
func (ControllerMonitorRevokeResult) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorRevokeResult")
}
func (ControllerMonitorRevokeResult) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorRevokeResult) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorRevokeResult) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorRevokeResult) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorRevokeResult) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorRevokeResult) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorResponseBody) String() string   { return "ControllerMonitorResponseBody" }
func (ControllerMonitorResponseBody) GoString() string { return "ControllerMonitorResponseBody" }
func (ControllerMonitorResponseBody) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorResponseBody")
}
func (ControllerMonitorResponseBody) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorResponseBody) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorResponseBody) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorResponseBody) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorResponseBody) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorResponseBody) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorEventBody) String() string   { return "ControllerMonitorEventBody" }
func (ControllerMonitorEventBody) GoString() string { return "ControllerMonitorEventBody" }
func (ControllerMonitorEventBody) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorEventBody")
}
func (ControllerMonitorEventBody) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorEventBody) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorEventBody) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorEventBody) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorEventBody) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorEventBody) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorCloseNotifyBody) String() string   { return "ControllerMonitorCloseNotifyBody" }
func (ControllerMonitorCloseNotifyBody) GoString() string { return "ControllerMonitorCloseNotifyBody" }
func (ControllerMonitorCloseNotifyBody) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorCloseNotifyBody")
}
func (ControllerMonitorCloseNotifyBody) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorCloseNotifyBody) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorCloseNotifyBody) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorCloseNotifyBody) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorCloseNotifyBody) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorCloseNotifyBody) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorPacket) String() string   { return "ControllerMonitorPacket" }
func (ControllerMonitorPacket) GoString() string { return "ControllerMonitorPacket" }
func (ControllerMonitorPacket) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorPacket")
}
func (ControllerMonitorPacket) MarshalJSON() ([]byte, error) { return controllerMonitorMarshalDenied() }
func (ControllerMonitorPacket) MarshalText() ([]byte, error) { return controllerMonitorMarshalDenied() }
func (ControllerMonitorPacket) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorPacket) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorPacket) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorPacket) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorTransitionDecision) String() string {
	return "ControllerMonitorTransitionDecision"
}
func (ControllerMonitorTransitionDecision) GoString() string {
	return "ControllerMonitorTransitionDecision"
}
func (ControllerMonitorTransitionDecision) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorTransitionDecision")
}
func (ControllerMonitorTransitionDecision) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorTransitionDecision) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorTransitionDecision) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorTransitionDecision) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorTransitionDecision) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorTransitionDecision) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorProtocolPhase) String() string   { return "ControllerMonitorProtocolPhase" }
func (ControllerMonitorProtocolPhase) GoString() string { return "ControllerMonitorProtocolPhase" }
func (ControllerMonitorProtocolPhase) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorProtocolPhase")
}
func (ControllerMonitorProtocolPhase) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorProtocolPhase) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorProtocolPhase) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorProtocolPhase) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorProtocolPhase) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorProtocolPhase) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorExpected) String() string   { return "ControllerMonitorExpected" }
func (ControllerMonitorExpected) GoString() string { return "ControllerMonitorExpected" }
func (ControllerMonitorExpected) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorExpected")
}
func (ControllerMonitorExpected) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorExpected) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorExpected) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorExpected) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorExpected) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorExpected) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorLocalObservation) String() string { return "ControllerMonitorLocalObservation" }
func (ControllerMonitorLocalObservation) GoString() string {
	return "ControllerMonitorLocalObservation"
}
func (ControllerMonitorLocalObservation) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorLocalObservation")
}
func (ControllerMonitorLocalObservation) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorLocalObservation) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorLocalObservation) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorLocalObservation) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorLocalObservation) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorLocalObservation) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorPendingEvent) String() string   { return "ControllerMonitorPendingEvent" }
func (ControllerMonitorPendingEvent) GoString() string { return "ControllerMonitorPendingEvent" }
func (ControllerMonitorPendingEvent) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorPendingEvent")
}
func (ControllerMonitorPendingEvent) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPendingEvent) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPendingEvent) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorPendingEvent) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorPendingEvent) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorPendingEvent) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorSnapshot) String() string   { return "ControllerMonitorSnapshot" }
func (ControllerMonitorSnapshot) GoString() string { return "ControllerMonitorSnapshot" }
func (ControllerMonitorSnapshot) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorSnapshot")
}
func (ControllerMonitorSnapshot) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorSnapshot) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorSnapshot) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (*ControllerMonitorSnapshot) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorSnapshot) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (*ControllerMonitorSnapshot) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

func (ControllerMonitorState) String() string   { return "ControllerMonitorState" }
func (ControllerMonitorState) GoString() string { return "ControllerMonitorState" }
func (ControllerMonitorState) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorState")
}
func (ControllerMonitorState) MarshalJSON() ([]byte, error) { return controllerMonitorMarshalDenied() }
func (ControllerMonitorState) MarshalText() ([]byte, error) { return controllerMonitorMarshalDenied() }
func (ControllerMonitorState) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorState) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (ControllerMonitorState) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (ControllerMonitorState) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
