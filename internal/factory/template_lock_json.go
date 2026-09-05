package factory

import (
	"encoding/json"

	"github.com/jywlabs/hal/internal/sandbox"
)

func (metadata SandboxMetadata) MarshalJSON() ([]byte, error) {
	type sandboxMetadataJSON SandboxMetadata
	encoded := sandboxMetadataJSON(metadata)
	encoded.TemplateLock = sandbox.SanitizeSandboxTemplateLockMetadata(metadata.TemplateLock)
	return json.Marshal(encoded)
}

func (metadata *SandboxMetadata) UnmarshalJSON(data []byte) error {
	type sandboxMetadataJSON SandboxMetadata
	var decoded sandboxMetadataJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	decoded.TemplateLock = sandbox.SanitizeSandboxTemplateLockMetadata(decoded.TemplateLock)
	*metadata = SandboxMetadata(decoded)
	return nil
}

// SetTemplateLock attaches sanitized template lock metadata to sandbox metadata.
func (metadata *SandboxMetadata) SetTemplateLock(lock *sandbox.SandboxTemplateLockMetadata) {
	if metadata == nil {
		return
	}
	metadata.TemplateLock = sandbox.SanitizeSandboxTemplateLockMetadata(lock)
}

// SetTemplateLockFromRuntime adopts sanitized selected-template metadata from
// sandbox runtime state onto the existing factory sandbox metadata surface.
func (metadata *SandboxMetadata) SetTemplateLockFromRuntime(runtime *sandbox.SandboxRuntimeState) {
	if metadata == nil {
		return
	}
	if runtime == nil {
		metadata.TemplateLock = nil
		return
	}
	metadata.TemplateLock = sandbox.SanitizeSandboxTemplateLockMetadata(runtime.TemplateLock)
}
