package l8composition

import "fmt"

func controllerSupervisorFormat(state fmt.State, name string) { _, _ = state.Write([]byte(name)) }
func controllerSupervisorMarshalDenied() ([]byte, error) {
	return nil, ErrControllerSupervisorSerialization
}
func controllerSupervisorUnmarshalDenied([]byte) error { return ErrControllerSupervisorSerialization }

func (ControllerSupervisorPacketType) String() string   { return "ControllerSupervisorPacketType" }
func (ControllerSupervisorPacketType) GoString() string { return "ControllerSupervisorPacketType" }
func (ControllerSupervisorPacketType) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorPacketType")
}
func (ControllerSupervisorPacketType) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorPacketType) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorPacketType) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorPacketType) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorPacketType) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorPacketType) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorDirection) String() string   { return "ControllerSupervisorDirection" }
func (ControllerSupervisorDirection) GoString() string { return "ControllerSupervisorDirection" }
func (ControllerSupervisorDirection) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorDirection")
}
func (ControllerSupervisorDirection) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorDirection) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorDirection) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorDirection) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorDirection) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorDirection) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorRightKind) String() string   { return "ControllerSupervisorRightKind" }
func (ControllerSupervisorRightKind) GoString() string { return "ControllerSupervisorRightKind" }
func (ControllerSupervisorRightKind) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorRightKind")
}
func (ControllerSupervisorRightKind) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorRightKind) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorRightKind) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorRightKind) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorRightKind) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorRightKind) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorRightAccess) String() string   { return "ControllerSupervisorRightAccess" }
func (ControllerSupervisorRightAccess) GoString() string { return "ControllerSupervisorRightAccess" }
func (ControllerSupervisorRightAccess) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorRightAccess")
}
func (ControllerSupervisorRightAccess) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorRightAccess) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorRightAccess) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorRightAccess) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorRightAccess) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorRightAccess) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorReason) String() string   { return "ControllerSupervisorReason" }
func (ControllerSupervisorReason) GoString() string { return "ControllerSupervisorReason" }
func (ControllerSupervisorReason) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorReason")
}
func (ControllerSupervisorReason) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorReason) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorReason) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorReason) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorReason) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorReason) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorEventCode) String() string   { return "ControllerSupervisorEventCode" }
func (ControllerSupervisorEventCode) GoString() string { return "ControllerSupervisorEventCode" }
func (ControllerSupervisorEventCode) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorEventCode")
}
func (ControllerSupervisorEventCode) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorEventCode) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorEventCode) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorEventCode) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorEventCode) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorEventCode) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorFailureCode) String() string   { return "ControllerSupervisorFailureCode" }
func (ControllerSupervisorFailureCode) GoString() string { return "ControllerSupervisorFailureCode" }
func (ControllerSupervisorFailureCode) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorFailureCode")
}
func (ControllerSupervisorFailureCode) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorFailureCode) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorFailureCode) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorFailureCode) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorFailureCode) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorFailureCode) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorExitCategory) String() string   { return "ControllerSupervisorExitCategory" }
func (ControllerSupervisorExitCategory) GoString() string { return "ControllerSupervisorExitCategory" }
func (ControllerSupervisorExitCategory) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorExitCategory")
}
func (ControllerSupervisorExitCategory) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorExitCategory) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorExitCategory) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorExitCategory) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorExitCategory) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorExitCategory) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorMonitorState) String() string   { return "ControllerSupervisorMonitorState" }
func (ControllerSupervisorMonitorState) GoString() string { return "ControllerSupervisorMonitorState" }
func (ControllerSupervisorMonitorState) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorMonitorState")
}
func (ControllerSupervisorMonitorState) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorMonitorState) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorMonitorState) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorMonitorState) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorMonitorState) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorMonitorState) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorCleanupCategory) String() string {
	return "ControllerSupervisorCleanupCategory"
}
func (ControllerSupervisorCleanupCategory) GoString() string {
	return "ControllerSupervisorCleanupCategory"
}
func (ControllerSupervisorCleanupCategory) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorCleanupCategory")
}
func (ControllerSupervisorCleanupCategory) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorCleanupCategory) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorCleanupCategory) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorCleanupCategory) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorCleanupCategory) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorCleanupCategory) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorHeader) String() string   { return "ControllerSupervisorHeader" }
func (ControllerSupervisorHeader) GoString() string { return "ControllerSupervisorHeader" }
func (ControllerSupervisorHeader) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorHeader")
}
func (ControllerSupervisorHeader) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorHeader) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorHeader) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorHeader) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorHeader) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorHeader) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorKernelCredential) String() string {
	return "ControllerSupervisorKernelCredential"
}
func (ControllerSupervisorKernelCredential) GoString() string {
	return "ControllerSupervisorKernelCredential"
}
func (ControllerSupervisorKernelCredential) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorKernelCredential")
}
func (ControllerSupervisorKernelCredential) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorKernelCredential) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorKernelCredential) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorKernelCredential) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorKernelCredential) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorKernelCredential) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorRightMetadata) String() string { return "ControllerSupervisorRightMetadata" }
func (ControllerSupervisorRightMetadata) GoString() string {
	return "ControllerSupervisorRightMetadata"
}
func (ControllerSupervisorRightMetadata) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorRightMetadata")
}
func (ControllerSupervisorRightMetadata) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorRightMetadata) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorRightMetadata) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorRightMetadata) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorRightMetadata) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorRightMetadata) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorReceiveMetadata) String() string {
	return "ControllerSupervisorReceiveMetadata"
}
func (ControllerSupervisorReceiveMetadata) GoString() string {
	return "ControllerSupervisorReceiveMetadata"
}
func (ControllerSupervisorReceiveMetadata) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorReceiveMetadata")
}
func (ControllerSupervisorReceiveMetadata) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorReceiveMetadata) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorReceiveMetadata) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorReceiveMetadata) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorReceiveMetadata) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorReceiveMetadata) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorSupervisorReadyBody) String() string {
	return "ControllerSupervisorSupervisorReadyBody"
}
func (ControllerSupervisorSupervisorReadyBody) GoString() string {
	return "ControllerSupervisorSupervisorReadyBody"
}
func (ControllerSupervisorSupervisorReadyBody) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorSupervisorReadyBody")
}
func (ControllerSupervisorSupervisorReadyBody) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorSupervisorReadyBody) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorSupervisorReadyBody) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorSupervisorReadyBody) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorSupervisorReadyBody) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorSupervisorReadyBody) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorCreateJobBody) String() string { return "ControllerSupervisorCreateJobBody" }
func (ControllerSupervisorCreateJobBody) GoString() string {
	return "ControllerSupervisorCreateJobBody"
}
func (ControllerSupervisorCreateJobBody) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorCreateJobBody")
}
func (ControllerSupervisorCreateJobBody) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorCreateJobBody) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorCreateJobBody) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorCreateJobBody) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorCreateJobBody) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorCreateJobBody) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorJobCreatedBody) String() string {
	return "ControllerSupervisorJobCreatedBody"
}
func (ControllerSupervisorJobCreatedBody) GoString() string {
	return "ControllerSupervisorJobCreatedBody"
}
func (ControllerSupervisorJobCreatedBody) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorJobCreatedBody")
}
func (ControllerSupervisorJobCreatedBody) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorJobCreatedBody) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorJobCreatedBody) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorJobCreatedBody) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorJobCreatedBody) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorJobCreatedBody) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorLaunchShimBody) String() string {
	return "ControllerSupervisorLaunchShimBody"
}
func (ControllerSupervisorLaunchShimBody) GoString() string {
	return "ControllerSupervisorLaunchShimBody"
}
func (ControllerSupervisorLaunchShimBody) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorLaunchShimBody")
}
func (ControllerSupervisorLaunchShimBody) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorLaunchShimBody) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorLaunchShimBody) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorLaunchShimBody) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorLaunchShimBody) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorLaunchShimBody) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorShimStartedBody) String() string {
	return "ControllerSupervisorShimStartedBody"
}
func (ControllerSupervisorShimStartedBody) GoString() string {
	return "ControllerSupervisorShimStartedBody"
}
func (ControllerSupervisorShimStartedBody) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorShimStartedBody")
}
func (ControllerSupervisorShimStartedBody) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorShimStartedBody) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorShimStartedBody) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorShimStartedBody) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorShimStartedBody) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorShimStartedBody) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorTerminateJobBody) String() string {
	return "ControllerSupervisorTerminateJobBody"
}
func (ControllerSupervisorTerminateJobBody) GoString() string {
	return "ControllerSupervisorTerminateJobBody"
}
func (ControllerSupervisorTerminateJobBody) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorTerminateJobBody")
}
func (ControllerSupervisorTerminateJobBody) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorTerminateJobBody) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorTerminateJobBody) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorTerminateJobBody) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorTerminateJobBody) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorTerminateJobBody) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorDestroyJobBody) String() string {
	return "ControllerSupervisorDestroyJobBody"
}
func (ControllerSupervisorDestroyJobBody) GoString() string {
	return "ControllerSupervisorDestroyJobBody"
}
func (ControllerSupervisorDestroyJobBody) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorDestroyJobBody")
}
func (ControllerSupervisorDestroyJobBody) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorDestroyJobBody) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorDestroyJobBody) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorDestroyJobBody) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorDestroyJobBody) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorDestroyJobBody) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorEventBody) String() string   { return "ControllerSupervisorEventBody" }
func (ControllerSupervisorEventBody) GoString() string { return "ControllerSupervisorEventBody" }
func (ControllerSupervisorEventBody) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorEventBody")
}
func (ControllerSupervisorEventBody) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorEventBody) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorEventBody) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorEventBody) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorEventBody) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorEventBody) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorControllerAttestationBody) String() string {
	return "ControllerSupervisorControllerAttestationBody"
}
func (ControllerSupervisorControllerAttestationBody) GoString() string {
	return "ControllerSupervisorControllerAttestationBody"
}
func (ControllerSupervisorControllerAttestationBody) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorControllerAttestationBody")
}
func (ControllerSupervisorControllerAttestationBody) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorControllerAttestationBody) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorControllerAttestationBody) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorControllerAttestationBody) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorControllerAttestationBody) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorControllerAttestationBody) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorCompositionAcceptedBody) String() string {
	return "ControllerSupervisorCompositionAcceptedBody"
}
func (ControllerSupervisorCompositionAcceptedBody) GoString() string {
	return "ControllerSupervisorCompositionAcceptedBody"
}
func (ControllerSupervisorCompositionAcceptedBody) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorCompositionAcceptedBody")
}
func (ControllerSupervisorCompositionAcceptedBody) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorCompositionAcceptedBody) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorCompositionAcceptedBody) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorCompositionAcceptedBody) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorCompositionAcceptedBody) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorCompositionAcceptedBody) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorCloseNotifyBody) String() string {
	return "ControllerSupervisorCloseNotifyBody"
}
func (ControllerSupervisorCloseNotifyBody) GoString() string {
	return "ControllerSupervisorCloseNotifyBody"
}
func (ControllerSupervisorCloseNotifyBody) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorCloseNotifyBody")
}
func (ControllerSupervisorCloseNotifyBody) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorCloseNotifyBody) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorCloseNotifyBody) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorCloseNotifyBody) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorCloseNotifyBody) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorCloseNotifyBody) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorPacket) String() string   { return "ControllerSupervisorPacket" }
func (ControllerSupervisorPacket) GoString() string { return "ControllerSupervisorPacket" }
func (ControllerSupervisorPacket) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorPacket")
}
func (ControllerSupervisorPacket) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorPacket) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorPacket) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorPacket) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorPacket) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorPacket) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorTransitionDecision) String() string {
	return "ControllerSupervisorTransitionDecision"
}
func (ControllerSupervisorTransitionDecision) GoString() string {
	return "ControllerSupervisorTransitionDecision"
}
func (ControllerSupervisorTransitionDecision) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorTransitionDecision")
}
func (ControllerSupervisorTransitionDecision) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorTransitionDecision) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorTransitionDecision) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorTransitionDecision) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorTransitionDecision) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorTransitionDecision) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorExpected) String() string   { return "ControllerSupervisorExpected" }
func (ControllerSupervisorExpected) GoString() string { return "ControllerSupervisorExpected" }
func (ControllerSupervisorExpected) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorExpected")
}
func (ControllerSupervisorExpected) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorExpected) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorExpected) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorExpected) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorExpected) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorExpected) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorShimExitObservation) String() string {
	return "ControllerSupervisorShimExitObservation"
}
func (ControllerSupervisorShimExitObservation) GoString() string {
	return "ControllerSupervisorShimExitObservation"
}
func (ControllerSupervisorShimExitObservation) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorShimExitObservation")
}
func (ControllerSupervisorShimExitObservation) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorShimExitObservation) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorShimExitObservation) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (*ControllerSupervisorShimExitObservation) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorShimExitObservation) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (*ControllerSupervisorShimExitObservation) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}

func (ControllerSupervisorState) String() string   { return "ControllerSupervisorState" }
func (ControllerSupervisorState) GoString() string { return "ControllerSupervisorState" }
func (ControllerSupervisorState) Format(state fmt.State, _ rune) {
	controllerSupervisorFormat(state, "ControllerSupervisorState")
}
func (ControllerSupervisorState) MarshalJSON() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorState) MarshalText() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorState) MarshalBinary() ([]byte, error) {
	return controllerSupervisorMarshalDenied()
}
func (ControllerSupervisorState) UnmarshalJSON(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (ControllerSupervisorState) UnmarshalText(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
func (ControllerSupervisorState) UnmarshalBinary(value []byte) error {
	return controllerSupervisorUnmarshalDenied(value)
}
