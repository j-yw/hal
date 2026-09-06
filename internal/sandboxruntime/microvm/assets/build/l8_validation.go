package build

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// L8ValidationCode is a closed, redaction-safe validation classification.
type L8ValidationCode string

const (
	L8ValidationCodeSchemaInvalid       L8ValidationCode = "schema_invalid"
	L8ValidationCodeProfileInvalid      L8ValidationCode = "profile_invalid"
	L8ValidationCodeParentInvalid       L8ValidationCode = "parent_invalid"
	L8ValidationCodeVersionInvalid      L8ValidationCode = "version_invalid"
	L8ValidationCodeCatalogInvalid      L8ValidationCode = "catalog_invalid"
	L8ValidationCodeCountInvalid        L8ValidationCode = "count_invalid"
	L8ValidationCodeOrderInvalid        L8ValidationCode = "order_invalid"
	L8ValidationCodeFieldInvalid        L8ValidationCode = "field_invalid"
	L8ValidationCodeDigestInvalid       L8ValidationCode = "digest_invalid"
	L8ValidationCodeCorrelationMismatch L8ValidationCode = "correlation_mismatch"
)

// L8ValidationError intentionally contains no rejected input or wrapped parser
// error. Index identifies only a source or final-inspection record.
type L8ValidationError struct {
	Code  L8ValidationCode `json:"code"`
	Field string           `json:"field,omitempty"`
	Index *int             `json:"index,omitempty"`
}

func (e *L8ValidationError) Error() string {
	if e == nil {
		return "L8 image profile validation failed"
	}
	return "L8 image profile validation failed: " + string(e.Code)
}

var requiredL8Features = []string{
	"copy_in",
	"copy_out",
	"credential_delivery_v2",
	"exec",
	"readiness",
	"ssh_agent_relay_v1",
}

var requiredL8InspectionChecks = []string{
	"parent_l7_profile",
	"kernel_network_profile",
	"guest_binary_inventory",
	"binary_owner_mode",
	"node_runtime",
	"pi_runtime",
	"pi_dependency_tree",
	"offline_source_inventory",
	"package_manager_state_absent",
	"credential_material_absent",
	"identity_layout",
	"pid1_launch_order",
	"process_composition",
	"workload_snapshot",
	"runtime_profile",
	"policy_artifact",
	"native_bootstrap",
	"vsock_listener_table",
	"filesystem_privilege_absent",
	"filesystem_private_modes",
	"kernel_tmpfs_mount_namespace",
	"kernel_cgroup_v2_kill",
}

const l8MaxFileBytes int64 = 1 << 30
const l8MaxSourceAggregate uint64 = 1 << 32

// ValidateL8DistributionManifest validates an exact L8 distribution without
// changing the stable L5/L7 validator behavior.
func ValidateL8DistributionManifest(manifest DistributionManifest) error {
	if manifest.SchemaVersion != SchemaVersionV1 {
		return l8ValidationError(L8ValidationCodeSchemaInvalid, "schemaVersion", -1)
	}
	if manifest.ImageProfile != ImageProfileL8ProductionCredentials {
		return l8ValidationError(L8ValidationCodeProfileInvalid, "imageProfile", -1)
	}
	if manifest.L8Profile == nil {
		return l8ValidationError(L8ValidationCodeCountInvalid, "l8Profile", -1)
	}
	if len(manifest.Assets) != 2 || manifest.GuestNetwork == nil {
		return l8ValidationError(L8ValidationCodeCountInvalid, "assets", -1)
	}
	if err := validateL8Common(manifest.Architecture, manifest.Versions, manifest.GuestAgent, manifest.GuestNetwork); err != nil {
		return err
	}
	if err := validateL8ProfileFacts(*manifest.L8Profile); err != nil {
		return err
	}
	if err := validateDistributionAssets(manifest.Assets); err != nil {
		return l8ValidationError(L8ValidationCodeFieldInvalid, "assets", -1)
	}
	return nil
}

// ValidateL8Provenance validates exact L8 provenance.
func ValidateL8Provenance(provenance Provenance) error {
	if provenance.SchemaVersion != SchemaVersionV1 {
		return l8ValidationError(L8ValidationCodeSchemaInvalid, "schemaVersion", -1)
	}
	if provenance.ImageProfile != ImageProfileL8ProductionCredentials {
		return l8ValidationError(L8ValidationCodeProfileInvalid, "imageProfile", -1)
	}
	if provenance.L8Profile == nil {
		return l8ValidationError(L8ValidationCodeCountInvalid, "l8Profile", -1)
	}
	if provenance.GuestNetwork == nil || len(provenance.Outputs) != 2 {
		return l8ValidationError(L8ValidationCodeCountInvalid, "outputs", -1)
	}
	if err := validateL8Common(provenance.Architecture, provenance.Versions, provenance.GuestAgent, provenance.GuestNetwork); err != nil {
		return err
	}
	if !validHex(provenance.SourceRevision, 40) || !safeSourceTree(provenance.SourceTree) ||
		provenance.SourceDateEpoch <= 0 || !strings.HasPrefix(provenance.BuildImageDigest, "sha256:") ||
		!validSHA256(strings.TrimPrefix(provenance.BuildImageDigest, "sha256:")) {
		return l8ValidationError(L8ValidationCodeFieldInvalid, "provenance", -1)
	}
	if err := validateL8ProfileFacts(*provenance.L8Profile); err != nil {
		return err
	}
	if err := validateDistributionOutputs(provenance.Outputs); err != nil {
		return l8ValidationError(L8ValidationCodeFieldInvalid, "outputs", -1)
	}
	return nil
}

// ValidateL8ProvenanceAgainstManifest checks every duplicated L8 fact.
func ValidateL8ProvenanceAgainstManifest(provenance Provenance, manifest DistributionManifest) error {
	if err := ValidateL8DistributionManifest(manifest); err != nil {
		return err
	}
	if err := ValidateL8Provenance(provenance); err != nil {
		return err
	}
	if provenance.Architecture != manifest.Architecture || provenance.Versions != manifest.Versions ||
		provenance.GuestAgent.Protocol != manifest.GuestAgent.Protocol ||
		!equalStrings(provenance.GuestAgent.Features, manifest.GuestAgent.Features) ||
		!equalGuestNetwork(provenance.GuestNetwork, manifest.GuestNetwork) ||
		*provenance.L8Profile != *manifest.L8Profile {
		return l8ValidationError(L8ValidationCodeCorrelationMismatch, "l8Profile", -1)
	}
	assets := make(map[string]DistributionAsset, len(manifest.Assets))
	for _, asset := range manifest.Assets {
		assets[asset.Key] = asset
	}
	for _, output := range provenance.Outputs {
		asset, ok := assets[output.Key]
		if !ok || output.ID != asset.ID || output.Kind != asset.Kind ||
			output.SizeBytes != asset.SizeBytes || output.SHA256 != asset.SHA256 {
			return l8ValidationError(L8ValidationCodeCorrelationMismatch, "assets", -1)
		}
	}
	return nil
}

// ValidateL8SourceLock validates the exact ordered offline source inventory.
func ValidateL8SourceLock(lock L8SourceLock) error {
	if lock.SchemaVersion != L8SourceLockSchemaVersionV1 {
		return l8ValidationError(L8ValidationCodeSchemaInvalid, "schemaVersion", -1)
	}
	if lock.ImageProfile != ImageProfileL8ProductionCredentials {
		return l8ValidationError(L8ValidationCodeProfileInvalid, "imageProfile", -1)
	}
	if lock.Sources == nil || len(lock.Sources) < 4 || len(lock.Sources) > 4096 {
		return l8ValidationError(L8ValidationCodeCountInvalid, "sources", -1)
	}
	if lock.CatalogVersion != L8SourceLockCatalogVersionV1 {
		return l8ValidationError(L8ValidationCodeCatalogInvalid, "catalogVersion", -1)
	}
	if err := validateL8Parent(lock.ParentL7); err != nil {
		return err
	}
	if err := validateL8Runtime(lock.Runtime); err != nil {
		return err
	}

	wantKinds := [3]string{"node_source", "pi_package", "pi_shrinkwrap"}
	wantNames := [3]string{"node", "@earendil-works/pi-coding-agent", "pi-shrinkwrap"}
	wantVersions := [3]string{"22.22.0", "0.82.1", "0.82.1"}
	seenFilenames := make(map[string]struct{}, len(lock.Sources))
	seenTuples := make(map[string]struct{}, len(lock.Sources))
	var aggregate uint64
	previous := ""
	for index, source := range lock.Sources {
		if index < 3 {
			if source.Kind != wantKinds[index] || source.Name != wantNames[index] || source.Version != wantVersions[index] {
				return l8ValidationError(L8ValidationCodeOrderInvalid, "sources", index)
			}
		} else {
			if source.Kind != "npm_archive" {
				return l8ValidationError(L8ValidationCodeOrderInvalid, "sources", index)
			}
			orderKey := source.Name + "\x00" + source.Version + "\x00" + source.Filename
			if previous != "" && orderKey <= previous {
				return l8ValidationError(L8ValidationCodeOrderInvalid, "sources", index)
			}
			previous = orderKey
		}
		if !validL8SafeToken(source.Kind, 128) || !validL8SourceName(source.Name) ||
			!validL8SafeToken(source.Version, 128) || !validL8SourceFilename(source.Filename) {
			return l8ValidationError(L8ValidationCodeFieldInvalid, "sources", index)
		}
		if source.SizeBytes <= 0 || source.SizeBytes > l8MaxFileBytes {
			return l8ValidationError(L8ValidationCodeFieldInvalid, "sources", index)
		}
		if !validSHA256(source.SHA256) {
			return l8ValidationError(L8ValidationCodeDigestInvalid, "sources", index)
		}
		if _, exists := seenFilenames[source.Filename]; exists {
			return l8ValidationError(L8ValidationCodeOrderInvalid, "sources", index)
		}
		tuple := source.Kind + "\x00" + source.Name + "\x00" + source.Version + "\x00" + source.Filename
		if _, exists := seenTuples[tuple]; exists {
			return l8ValidationError(L8ValidationCodeOrderInvalid, "sources", index)
		}
		seenFilenames[source.Filename] = struct{}{}
		seenTuples[tuple] = struct{}{}
		if uint64(source.SizeBytes) > l8MaxSourceAggregate-aggregate {
			return l8ValidationError(L8ValidationCodeCountInvalid, "sources", index)
		}
		aggregate += uint64(source.SizeBytes)
	}
	if lock.Runtime.PiDependencyTreeSHA256 != l8PiDependencyTreeSHA256(lock.Sources) {
		return l8ValidationError(L8ValidationCodeCorrelationMismatch, "runtime", -1)
	}
	return nil
}

// ValidateL8FinalInspection validates the exact ordered 22-check catalog.
func ValidateL8FinalInspection(inspection L8FinalInspection) error {
	if inspection.SchemaVersion != L8FinalInspectionSchemaVersionV1 {
		return l8ValidationError(L8ValidationCodeSchemaInvalid, "schemaVersion", -1)
	}
	if inspection.ImageProfile != ImageProfileL8ProductionCredentials {
		return l8ValidationError(L8ValidationCodeProfileInvalid, "imageProfile", -1)
	}
	if inspection.Checks == nil || len(inspection.Checks) != len(requiredL8InspectionChecks) {
		return l8ValidationError(L8ValidationCodeCountInvalid, "checks", -1)
	}
	if inspection.CatalogVersion != L8FinalInspectionCatalogVersionV1 ||
		inspection.ProcessComposition.CatalogVersion != L8ProcessCompositionCatalogV1 {
		return l8ValidationError(L8ValidationCodeCatalogInvalid, "catalogVersion", -1)
	}
	if err := validateL8Parent(inspection.ParentL7); err != nil {
		return err
	}
	if err := validateL8Runtime(inspection.Runtime); err != nil {
		return err
	}
	if !validSHA256(inspection.RootfsSHA256) || !validSHA256(inspection.SourceLockSHA256) {
		return l8ValidationError(L8ValidationCodeDigestInvalid, "rootfsSha256", -1)
	}
	if err := validateL8ProcessComposition(inspection.ProcessComposition); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(inspection.Checks))
	for index, check := range inspection.Checks {
		if check.ID != requiredL8InspectionChecks[index] {
			return l8ValidationError(L8ValidationCodeOrderInvalid, "checks", index)
		}
		if check.Status != "pass" {
			return l8ValidationError(L8ValidationCodeFieldInvalid, "checks", index)
		}
		if !validSHA256(check.EvidenceSHA256) || check.EvidenceSHA256 == strings.Repeat("0", 64) {
			return l8ValidationError(L8ValidationCodeDigestInvalid, "checks", index)
		}
		if _, exists := seen[check.EvidenceSHA256]; exists {
			return l8ValidationError(L8ValidationCodeOrderInvalid, "checks", index)
		}
		seen[check.EvidenceSHA256] = struct{}{}
	}
	return nil
}

func validateL8Common(architecture string, versions Versions, agent GuestAgent, network *GuestNetwork) error {
	if architecture != "x86_64" || !validVersions(versions) || agent.Protocol != L8GuestAgentProtocolV2 ||
		!equalStrings(agent.Features, requiredL8Features) || network == nil ||
		network.Mode != GuestNetworkModeStaticProxy || !equalStrings(network.Features, requiredL7NetworkFeatures) {
		return l8ValidationError(L8ValidationCodeVersionInvalid, "guestAgent", -1)
	}
	return nil
}

func validateL8ProfileFacts(profile L8ProfileFacts) error {
	if profile.ContractVersion != L8ProfileContractVersionV1 {
		return l8ValidationError(L8ValidationCodeVersionInvalid, "contractVersion", -1)
	}
	if err := validateL8Parent(profile.ParentL7); err != nil {
		return err
	}
	if err := validateL8Runtime(profile.Runtime); err != nil {
		return err
	}
	if err := validateL8ProcessComposition(profile.ProcessComposition); err != nil {
		return err
	}
	if !validSHA256(profile.SourceLockSHA256) || !validSHA256(profile.FinalInspectionSHA256) {
		return l8ValidationError(L8ValidationCodeDigestInvalid, "l8Profile", -1)
	}
	return nil
}

func validateL8Parent(parent L8ParentL7Evidence) error {
	if parent.ImageProfile != ImageProfileL7Network || parent.KernelSizeBytes <= 0 || parent.KernelSizeBytes > l8MaxFileBytes ||
		parent.RootfsSizeBytes <= 0 || parent.RootfsSizeBytes > l8MaxFileBytes {
		return l8ValidationError(L8ValidationCodeParentInvalid, "parentL7", -1)
	}
	for _, digest := range []string{parent.ManifestSHA256, parent.ProvenanceSHA256, parent.ChecksumsSHA256, parent.KernelSHA256, parent.RootfsSHA256, parent.EvidenceSHA256} {
		if !validSHA256(digest) {
			return l8ValidationError(L8ValidationCodeDigestInvalid, "parentL7", -1)
		}
	}
	if parent.EvidenceSHA256 != l8ParentEvidenceSHA256(parent) {
		return l8ValidationError(L8ValidationCodeParentInvalid, "parentL7", -1)
	}
	return nil
}

func validateL8Runtime(runtime L8RuntimeFacts) error {
	if runtime.NodeVersion != "22.22.0" || runtime.PiPackage != "@earendil-works/pi-coding-agent" || runtime.PiVersion != "0.82.1" {
		return l8ValidationError(L8ValidationCodeVersionInvalid, "runtime", -1)
	}
	if !validSHA256(runtime.NodeSHA256) || !validSHA256(runtime.PiLauncherSHA256) || !validSHA256(runtime.PiDependencyTreeSHA256) {
		return l8ValidationError(L8ValidationCodeDigestInvalid, "runtime", -1)
	}
	return nil
}

func validateL8ProcessComposition(composition L8ProcessCompositionFacts) error {
	if composition.CatalogVersion != L8ProcessCompositionCatalogV1 {
		return l8ValidationError(L8ValidationCodeCatalogInvalid, "processComposition", -1)
	}
	digests := []string{
		composition.GuestAgentSHA256, composition.GuestInitSHA256, composition.CredentialHelperSHA256,
		composition.MountMonitorSHA256, composition.WorkloadShimSHA256, composition.RoleBootstrapSHA256,
		composition.HelperDescriptorSHA256, composition.ClientDescriptorSHA256, composition.CompositionSHA256,
		composition.WorkloadSnapshotSHA256, composition.RuntimeProfileSHA256, composition.PolicyArtifactSHA256,
		composition.PolicySourceLockSHA256, composition.PolicyBinaryBindingSetSHA256, composition.PinnedCallsiteEvidenceSHA256,
	}
	for _, digest := range digests {
		if !validSHA256(digest) || digest == strings.Repeat("0", 64) {
			return l8ValidationError(L8ValidationCodeDigestInvalid, "processComposition", -1)
		}
	}
	return nil
}

func validateDistributionAssets(assets []DistributionAsset) error {
	required := map[string]struct{ id, kind string }{
		"rootfs.ext4": {"rootfs", "rootfs_image"},
		"vmlinux":     {"kernel", "kernel_image"},
	}
	seenKeys := make(map[string]struct{}, len(assets))
	seenIDs := make(map[string]struct{}, len(assets))
	for _, asset := range assets {
		want, ok := required[asset.Key]
		if !ok || asset.ID != want.id || asset.Kind != want.kind || asset.SizeBytes <= 0 || asset.SizeBytes > l8MaxFileBytes ||
			!validSHA256(asset.SHA256) || !safeRelativeKey(asset.Key) {
			return fmt.Errorf("invalid asset")
		}
		if _, ok := seenKeys[asset.Key]; ok {
			return fmt.Errorf("duplicate asset")
		}
		if _, ok := seenIDs[asset.ID]; ok {
			return fmt.Errorf("duplicate asset")
		}
		seenKeys[asset.Key], seenIDs[asset.ID] = struct{}{}, struct{}{}
	}
	return nil
}

func validateDistributionOutputs(outputs []Output) error {
	seenKeys := make(map[string]struct{}, len(outputs))
	seenIDs := make(map[string]struct{}, len(outputs))
	for _, output := range outputs {
		if !safeRelativeKey(output.Key) || output.ID == "" || output.Kind == "" || output.SizeBytes <= 0 ||
			output.SizeBytes > l8MaxFileBytes || !validSHA256(output.SHA256) {
			return fmt.Errorf("invalid output")
		}
		if _, ok := seenKeys[output.Key]; ok {
			return fmt.Errorf("duplicate output")
		}
		if _, ok := seenIDs[output.ID]; ok {
			return fmt.Errorf("duplicate output")
		}
		seenKeys[output.Key], seenIDs[output.ID] = struct{}{}, struct{}{}
	}
	return nil
}

func l8ValidationError(code L8ValidationCode, field string, index int) error {
	result := &L8ValidationError{Code: code, Field: field}
	if index >= 0 {
		copyIndex := index
		result.Index = &copyIndex
	}
	return result
}

func validL8SafeToken(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' && char != '-' && char != '.' {
			return false
		}
	}
	return true
}

func validL8SourceName(value string) bool {
	if len(value) == 0 || len(value) > 214 {
		return false
	}
	if value[0] != '@' {
		return validL8SafeToken(value, 128)
	}
	if strings.Count(value, "/") != 1 {
		return false
	}
	parts := strings.SplitN(value[1:], "/", 2)
	return len(parts) == 2 && validL8SafeToken(parts[0], 128) && validL8SafeToken(parts[1], 128)
}

func validL8SourceFilename(value string) bool {
	if len(value) == 0 || len(value) > 240 || strings.Contains(value, "..") {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char < 0x21 || char > 0x7e || char == '/' || char == '\\' {
			return false
		}
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{"://", "http:", "https:", "ssh:", "tcp:", "udp:", "grpc:", "file:", "authorization", "bearer", "token", "secret", "credential", "password", "api_key", "apikey", "access_key", "private_key", "ghp_", "github_pat_", "sk-"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func l8ParentEvidenceSHA256(parent L8ParentL7Evidence) string {
	hash := sha256.New()
	l8WriteToken(hash, "hal/l8/image-profile/parent-l7-evidence/v1")
	l8WriteToken(hash, ImageProfileL7Network)
	l8WriteDigest(hash, parent.ManifestSHA256)
	l8WriteDigest(hash, parent.ProvenanceSHA256)
	l8WriteDigest(hash, parent.ChecksumsSHA256)
	l8WriteUint64(hash, uint64(parent.KernelSizeBytes))
	l8WriteDigest(hash, parent.KernelSHA256)
	l8WriteUint64(hash, uint64(parent.RootfsSizeBytes))
	l8WriteDigest(hash, parent.RootfsSHA256)
	return hex.EncodeToString(hash.Sum(nil))
}

func l8PiDependencyTreeSHA256(sources []L8LockedSource) string {
	if len(sources) < 3 {
		return ""
	}
	hash := sha256.New()
	l8WriteToken(hash, "hal/l8/pi-dependency-tree/v1")
	for _, source := range sources[1:3] {
		l8WriteToken(hash, source.Kind)
		l8WriteToken(hash, source.Name)
		l8WriteToken(hash, source.Version)
		l8WriteToken(hash, source.Filename)
		l8WriteUint64(hash, uint64(source.SizeBytes))
		l8WriteDigest(hash, source.SHA256)
	}
	countValue := uint32(len(sources) - 3)
	count := [4]byte{byte(countValue >> 24), byte(countValue >> 16), byte(countValue >> 8), byte(countValue)}
	_, _ = hash.Write(count[:])
	for _, source := range sources[3:] {
		l8WriteToken(hash, source.Kind)
		l8WriteToken(hash, source.Name)
		l8WriteToken(hash, source.Version)
		l8WriteToken(hash, source.Filename)
		l8WriteUint64(hash, uint64(source.SizeBytes))
		l8WriteDigest(hash, source.SHA256)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type l8HashWriter interface{ Write([]byte) (int, error) }

func l8WriteToken(writer l8HashWriter, value string) {
	if len(value) > 65535 {
		return
	}
	var length [2]byte
	lengthValue := uint16(len(value))
	length = [2]byte{byte(lengthValue >> 8), byte(lengthValue)}
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}

func l8WriteDigest(writer l8HashWriter, value string) {
	digest, err := hex.DecodeString(value)
	if err == nil && len(digest) == sha256.Size {
		_, _ = writer.Write(digest)
	}
}

func l8WriteUint64(writer l8HashWriter, value uint64) {
	var encoded [8]byte
	encoded = [8]byte{
		byte(value >> 56), byte(value >> 48), byte(value >> 40), byte(value >> 32),
		byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value),
	}
	_, _ = writer.Write(encoded[:])
}
