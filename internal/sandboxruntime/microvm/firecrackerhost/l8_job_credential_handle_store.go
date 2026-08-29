package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	l8JobCredentialHandleContractVersion       = "firecracker-job-credential-handle-v1"
	l8JobCredentialHandleRecordLimit           = 16 << 10
	l8JobCredentialHandleStoreValuePlaceholder = "[firecracker-l8-job-credential-handle-store]"
	l8JobCredentialHandleRecordNamePrefix      = "job-credential-handle-"
	l8JobCredentialHandleRecordNameSuffix      = ".json"
)

type l8JobCredentialHandleStore interface {
	Save(context.Context, l8JobCredentialHandleRecordV1) error
	Load(context.Context, sandboxruntime.JobCredentialIdentity) (l8JobCredentialHandleRecordV1, bool, error)
}

type l8JobCredentialStoredHandleRevoker interface {
	RevokeStored(context.Context, sandboxruntime.JobCredentialIdentity, l8JobCredentialStoredBindingV1) error
}

type l8JobCredentialHandleRecordV1 struct {
	ContractVersion string                           `json:"contractVersion"`
	IdentityDigest  string                           `json:"identityDigest"`
	Revision        uint64                           `json:"revision"`
	Bindings        []l8JobCredentialStoredBindingV1 `json:"bindings"`
}

type l8JobCredentialStoredBindingV1 struct {
	BindingID         string `json:"bindingId"`
	Mode              string `json:"mode"`
	TargetPath        string `json:"targetPath,omitempty"`
	DeclaredFileBytes uint32 `json:"declaredFileBytes,omitempty"`
	FileSHA256        string `json:"fileSha256,omitempty"`
	ServiceID         string `json:"serviceId,omitempty"`
	SSHPolicyID       string `json:"sshPolicyId,omitempty"`
	SSHPolicyRevision uint64 `json:"sshPolicyRevision,omitempty"`
}

// NewProductionL8JobCredentialHandleStore constructs the explicit Linux
// durable handle-metadata store. It is never invoked by sandboxd, run, auto,
// factory, worker Service, or NewProductionL8JobCredentialRuntime unless a
// caller injects the returned store.
func NewProductionL8JobCredentialHandleStore(directory string) (l8JobCredentialHandleStore, error) {
	if !l8JobCredentialRuntimePlatformSupported() {
		return nil, ErrL8JobCredentialRuntimeUnsupported
	}
	return openL8JobCredentialHandleStore(directory)
}

func persistL8JobCredentialHandleRecord(
	ctx context.Context,
	store l8JobCredentialHandleStore,
	identity sandboxruntime.JobCredentialIdentity,
	revision uint64,
	manifests []l8JobCredentialGuestBindingManifest,
) error {
	if l8JobCredentialRuntimeValueIsNil(store) {
		return nil
	}
	record, err := l8JobCredentialHandleRecordFromManifests(identity, revision, manifests)
	if err != nil {
		return err
	}
	return callL8JobCredentialHandleStoreSave(store, ctx, record)
}

func loadL8JobCredentialHandleRecord(
	ctx context.Context,
	store l8JobCredentialHandleStore,
	identity sandboxruntime.JobCredentialIdentity,
) (record l8JobCredentialHandleRecordV1, present bool, err error) {
	if l8JobCredentialRuntimeValueIsNil(store) {
		return l8JobCredentialHandleRecordV1{}, false, nil
	}
	return callL8JobCredentialHandleStoreLoad(store, ctx, identity)
}

func recoverL8JobCredentialStoredHandles(
	ctx context.Context,
	deps l8JobCredentialRuntimeDependencies,
	identity sandboxruntime.JobCredentialIdentity,
	record l8JobCredentialHandleRecordV1,
) error {
	if l8JobCredentialRuntimeValueIsNil(ctx) {
		return ErrL8JobCredentialRuntimeInvalid
	}
	revokers := make([]l8JobCredentialStoredHandleRevoker, len(record.Bindings))
	for index, binding := range record.Bindings {
		var revoker l8JobCredentialStoredHandleRevoker
		switch sandboxruntime.JobCredentialDeliveryMode(binding.Mode) {
		case sandboxruntime.JobCredentialDeliveryModeHTTPProxy:
			revoker, _ = deps.HTTPProxy.(l8JobCredentialStoredHandleRevoker)
		case sandboxruntime.JobCredentialDeliveryModeFileTmpfs:
			revoker, _ = deps.FileTmpfs.(l8JobCredentialStoredHandleRevoker)
		case sandboxruntime.JobCredentialDeliveryModeSSHAgent:
			revoker, _ = deps.SSHRelay.(l8JobCredentialStoredHandleRevoker)
		default:
			return ErrL8JobCredentialRuntimeInvalid
		}
		if l8JobCredentialRuntimeValueIsNil(revoker) {
			return errL8JobCredentialRuntimeDependencyUnaccepted
		}
		revokers[index] = revoker
	}
	for index, binding := range record.Bindings {
		revoker := revokers[index]
		if err := callL8JobCredentialRevokeStored(revoker, ctx, identity, binding); err != nil {
			return err
		}
	}
	return nil
}

func l8JobCredentialHandleRecordFromManifests(
	identity sandboxruntime.JobCredentialIdentity,
	revision uint64,
	manifests []l8JobCredentialGuestBindingManifest,
) (l8JobCredentialHandleRecordV1, error) {
	digest, err := sandboxruntime.JobCredentialIdentityDigest(identity)
	if err != nil {
		return l8JobCredentialHandleRecordV1{}, sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	if revision == 0 || len(manifests) != len(identity.BindingIDs) {
		return l8JobCredentialHandleRecordV1{}, ErrL8JobCredentialRuntimeInvalid
	}
	bindings := make([]l8JobCredentialStoredBindingV1, len(manifests))
	for index, manifest := range manifests {
		if manifest.BindingID != identity.BindingIDs[index] || manifest.Mode != identity.DeliveryModes[index] {
			return l8JobCredentialHandleRecordV1{}, ErrL8JobCredentialRuntimeInvalid
		}
		binding := l8JobCredentialStoredBindingV1{
			BindingID: manifest.BindingID,
			Mode:      string(manifest.Mode),
		}
		switch manifest.Mode {
		case sandboxruntime.JobCredentialDeliveryModeHTTPProxy:
			binding.ServiceID = manifest.ServiceID
		case sandboxruntime.JobCredentialDeliveryModeFileTmpfs:
			binding.TargetPath = manifest.TargetPath
			binding.DeclaredFileBytes = manifest.DeclaredFileBytes
			binding.FileSHA256 = manifest.FileSHA256
		case sandboxruntime.JobCredentialDeliveryModeSSHAgent:
			binding.SSHPolicyID = manifest.SSHPolicyID
			binding.SSHPolicyRevision = manifest.SSHPolicyRevision
		default:
			return l8JobCredentialHandleRecordV1{}, ErrL8JobCredentialRuntimeInvalid
		}
		bindings[index] = binding
	}
	record := l8JobCredentialHandleRecordV1{
		ContractVersion: l8JobCredentialHandleContractVersion,
		IdentityDigest:  hex.EncodeToString(digest[:]),
		Revision:        revision,
		Bindings:        bindings,
	}
	if err := bindL8JobCredentialHandleRecord(record, identity); err != nil {
		return l8JobCredentialHandleRecordV1{}, err
	}
	return record, nil
}

func encodeL8JobCredentialHandleRecord(record l8JobCredentialHandleRecordV1) ([]byte, error) {
	if err := validateL8JobCredentialHandleRecordShape(record); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(record)
	if err != nil || len(payload)+1 > l8JobCredentialHandleRecordLimit {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	payload = append(payload, '\n')
	if !l8JobCredentialHandleUniqueJSONObject(payload[:len(payload)-1]) {
		return nil, ErrL8JobCredentialRuntimeInvalid
	}
	return payload, nil
}

func decodeL8JobCredentialHandleRecord(payload []byte) (l8JobCredentialHandleRecordV1, error) {
	if len(payload) < 3 || len(payload) > l8JobCredentialHandleRecordLimit || payload[len(payload)-1] != '\n' ||
		len(bytes.TrimSpace(payload[:len(payload)-1])) != len(payload)-1 || !l8JobCredentialHandleUniqueJSONObject(payload[:len(payload)-1]) {
		return l8JobCredentialHandleRecordV1{}, ErrL8JobCredentialRuntimeInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var record l8JobCredentialHandleRecordV1
	if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return l8JobCredentialHandleRecordV1{}, ErrL8JobCredentialRuntimeInvalid
	}
	if err := validateL8JobCredentialHandleRecordShape(record); err != nil {
		return l8JobCredentialHandleRecordV1{}, err
	}
	return record, nil
}

func bindL8JobCredentialHandleRecord(record l8JobCredentialHandleRecordV1, identity sandboxruntime.JobCredentialIdentity) error {
	if err := validateL8JobCredentialHandleRecordShape(record); err != nil {
		return err
	}
	digest, err := sandboxruntime.JobCredentialIdentityDigest(identity)
	if err != nil {
		return sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	encoded := hex.EncodeToString(digest[:])
	if subtle.ConstantTimeCompare([]byte(record.IdentityDigest), []byte(encoded)) != 1 {
		return sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	if len(record.Bindings) != len(identity.BindingIDs) {
		return sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	for index, binding := range record.Bindings {
		if binding.BindingID != identity.BindingIDs[index] || sandboxruntime.JobCredentialDeliveryMode(binding.Mode) != identity.DeliveryModes[index] {
			return sandboxruntime.ErrJobCredentialIdentityMismatch
		}
	}
	return nil
}

func validateL8JobCredentialHandleRecordShape(record l8JobCredentialHandleRecordV1) error {
	if record.ContractVersion != l8JobCredentialHandleContractVersion || record.Revision == 0 ||
		!validL8JobCredentialHandleDigest(record.IdentityDigest) || len(record.Bindings) == 0 {
		return ErrL8JobCredentialRuntimeInvalid
	}
	seen := make(map[string]struct{}, len(record.Bindings))
	for _, binding := range record.Bindings {
		if !validL8JobCredentialRuntimeToken(binding.BindingID) {
			return ErrL8JobCredentialRuntimeInvalid
		}
		if _, duplicate := seen[binding.BindingID]; duplicate {
			return ErrL8JobCredentialRuntimeInvalid
		}
		seen[binding.BindingID] = struct{}{}
		if err := validateL8JobCredentialStoredBinding(binding); err != nil {
			return err
		}
	}
	return nil
}

func validateL8JobCredentialStoredBinding(binding l8JobCredentialStoredBindingV1) error {
	switch sandboxruntime.JobCredentialDeliveryMode(binding.Mode) {
	case sandboxruntime.JobCredentialDeliveryModeHTTPProxy:
		if !validL8JobCredentialRuntimeToken(binding.ServiceID) || binding.TargetPath != "" || binding.DeclaredFileBytes != 0 ||
			binding.FileSHA256 != "" || binding.SSHPolicyID != "" || binding.SSHPolicyRevision != 0 {
			return ErrL8JobCredentialRuntimeInvalid
		}
	case sandboxruntime.JobCredentialDeliveryModeFileTmpfs:
		if !validL8JobCredentialRuntimeToken(binding.TargetPath) || strings.ContainsAny(binding.TargetPath, "/\\") ||
			binding.DeclaredFileBytes == 0 || !validL8JobCredentialHandleDigest(binding.FileSHA256) ||
			binding.ServiceID != "" || binding.SSHPolicyID != "" || binding.SSHPolicyRevision != 0 {
			return ErrL8JobCredentialRuntimeInvalid
		}
	case sandboxruntime.JobCredentialDeliveryModeSSHAgent:
		if !validL8JobCredentialRuntimeToken(binding.SSHPolicyID) || binding.SSHPolicyRevision == 0 ||
			binding.ServiceID != "" || binding.TargetPath != "" || binding.DeclaredFileBytes != 0 || binding.FileSHA256 != "" {
			return ErrL8JobCredentialRuntimeInvalid
		}
	default:
		return ErrL8JobCredentialRuntimeInvalid
	}
	return nil
}

func validL8JobCredentialHandleDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func l8JobCredentialHandleRecordName(digest [32]byte) string {
	return l8JobCredentialHandleRecordNamePrefix + hex.EncodeToString(digest[:]) + l8JobCredentialHandleRecordNameSuffix
}

func l8JobCredentialHandleDigestFromRecord(record l8JobCredentialHandleRecordV1) ([32]byte, error) {
	decoded, err := hex.DecodeString(record.IdentityDigest)
	if err != nil || len(decoded) != 32 {
		return [32]byte{}, ErrL8JobCredentialRuntimeInvalid
	}
	var digest [32]byte
	copy(digest[:], decoded)
	return digest, nil
}

func l8JobCredentialHandleUniqueJSONObject(payload []byte) bool {
	allowed := map[string]bool{
		"contractVersion": true,
		"identityDigest":  true,
		"revision":        true,
		"bindings":        true,
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool, len(allowed))
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
		switch name {
		case "revision":
			var number uint64
			if json.Unmarshal(value, &number) != nil {
				return false
			}
		case "bindings":
			if !l8JobCredentialHandleUniqueBindings(value) {
				return false
			}
		default:
			var text string
			if json.Unmarshal(value, &text) != nil {
				return false
			}
		}
	}
	token, err = decoder.Token()
	return err == nil && token == json.Delim('}') && len(seen) == len(allowed)
}

func l8JobCredentialHandleUniqueBindings(payload json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return false
	}
	for decoder.More() {
		var value json.RawMessage
		if decoder.Decode(&value) != nil || !l8JobCredentialHandleUniqueBindingObject(value) {
			return false
		}
	}
	token, err = decoder.Token()
	return err == nil && token == json.Delim(']')
}

func l8JobCredentialHandleUniqueBindingObject(payload json.RawMessage) bool {
	allowed := map[string]bool{
		"bindingId": true, "mode": true, "targetPath": true, "declaredFileBytes": true,
		"fileSha256": true, "serviceId": true, "sshPolicyId": true, "sshPolicyRevision": true,
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
		switch name {
		case "declaredFileBytes", "sshPolicyRevision":
			var number uint64
			if json.Unmarshal(value, &number) != nil {
				return false
			}
		default:
			var text string
			if json.Unmarshal(value, &text) != nil {
				return false
			}
		}
	}
	token, err = decoder.Token()
	return err == nil && token == json.Delim('}') && seen["bindingId"] && seen["mode"]
}

func callL8JobCredentialHandleStoreSave(store l8JobCredentialHandleStore, ctx context.Context, record l8JobCredentialHandleRecordV1) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrL8JobCredentialRuntimeUnavailable
		}
	}()
	if l8JobCredentialRuntimeValueIsNil(store) {
		return nil
	}
	return store.Save(ctx, record)
}

func callL8JobCredentialHandleStoreLoad(
	store l8JobCredentialHandleStore,
	ctx context.Context,
	identity sandboxruntime.JobCredentialIdentity,
) (record l8JobCredentialHandleRecordV1, present bool, err error) {
	defer func() {
		if recover() != nil {
			record = l8JobCredentialHandleRecordV1{}
			present = false
			err = ErrL8JobCredentialRuntimeUnavailable
		}
	}()
	if l8JobCredentialRuntimeValueIsNil(store) {
		return l8JobCredentialHandleRecordV1{}, false, nil
	}
	return store.Load(ctx, identity)
}

func callL8JobCredentialRevokeStored(
	revoker l8JobCredentialStoredHandleRevoker,
	ctx context.Context,
	identity sandboxruntime.JobCredentialIdentity,
	binding l8JobCredentialStoredBindingV1,
) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrL8JobCredentialRuntimeUnavailable
		}
	}()
	if l8JobCredentialRuntimeValueIsNil(revoker) {
		return errL8JobCredentialRuntimeDependencyUnaccepted
	}
	return revoker.RevokeStored(ctx, identity, binding)
}

func redactL8JobCredentialHandleStore(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, l8JobCredentialHandleStoreValuePlaceholder)
}
