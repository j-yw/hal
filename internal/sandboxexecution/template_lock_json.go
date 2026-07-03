package sandboxexecution

import (
	"encoding/json"

	"github.com/jywlabs/hal/internal/sandbox"
)

func (manifest Manifest) MarshalJSON() ([]byte, error) {
	type manifestJSON Manifest
	encoded := manifestJSON(manifest)
	encoded.TemplateLock = sandbox.SanitizeSandboxTemplateLockMetadata(manifest.TemplateLock)
	return json.Marshal(encoded)
}

func (manifest *Manifest) UnmarshalJSON(data []byte) error {
	type manifestJSON Manifest
	var decoded manifestJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	decoded.TemplateLock = sandbox.SanitizeSandboxTemplateLockMetadata(decoded.TemplateLock)
	*manifest = Manifest(decoded)
	return nil
}

// SetTemplateLock attaches sanitized template lock metadata to the manifest.
func (manifest *Manifest) SetTemplateLock(metadata *sandbox.SandboxTemplateLockMetadata) {
	if manifest == nil {
		return
	}
	manifest.TemplateLock = sandbox.SanitizeSandboxTemplateLockMetadata(metadata)
}
