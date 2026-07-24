package sandboxexecution

import (
	"encoding/json"
	"fmt"

	"github.com/jywlabs/hal/internal/sandbox"
)

func (manifest Manifest) MarshalJSON() ([]byte, error) {
	type manifestJSON Manifest
	encoded := manifestJSON(manifest)
	encoded.Runtime = sandbox.CloneSandboxRuntimeState(manifest.Runtime)
	encoded.WorkerJob = SanitizeWorkerJobReference(manifest.WorkerJob)
	encoded.TemplateLock = manifestTemplateLockForPersistence(manifest.TemplateLock, manifest.Runtime)
	return json.Marshal(encoded)
}

func (manifest *Manifest) UnmarshalJSON(data []byte) error {
	type manifestJSON Manifest
	var decoded manifestJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	decoded.Runtime = sandbox.CloneSandboxRuntimeState(decoded.Runtime)
	if decoded.WorkerJob != nil {
		decoded.WorkerJob = SanitizeWorkerJobReference(decoded.WorkerJob)
		if decoded.WorkerJob == nil {
			return fmt.Errorf("sandbox execution workerJob metadata is invalid")
		}
	}
	decoded.TemplateLock = manifestTemplateLockForPersistence(decoded.TemplateLock, decoded.Runtime)
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

// SetTemplateLockFromRuntime adopts sanitized selected-template metadata from
// runtime state onto the manifest's existing durable templateLock surface.
func (manifest *Manifest) SetTemplateLockFromRuntime(runtime *sandbox.SandboxRuntimeState) {
	if manifest == nil {
		return
	}
	if runtime == nil {
		manifest.TemplateLock = nil
		return
	}
	manifest.TemplateLock = sandbox.SanitizeSandboxTemplateLockMetadata(runtime.TemplateLock)
}

func manifestTemplateLockForPersistence(explicit *sandbox.SandboxTemplateLockMetadata, runtime *sandbox.SandboxRuntimeState) *sandbox.SandboxTemplateLockMetadata {
	if sanitized := sandbox.SanitizeSandboxTemplateLockMetadata(explicit); sanitized != nil {
		return sanitized
	}
	if runtime == nil {
		return nil
	}
	return sandbox.SanitizeSandboxTemplateLockMetadata(runtime.TemplateLock)
}
