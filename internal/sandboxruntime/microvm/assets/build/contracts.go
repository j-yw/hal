package build

const SchemaVersionV1 = "hal-microvm-image-v1"

const (
	ImageProfileL7Network               = "l7-firecracker-network-v1"
	ImageProfileL8ProductionCredentials = "l8-production-credentials-v1"
	GuestNetworkModeStaticProxy         = "static_proxy"
)

const (
	L8ProfileContractVersionV1        = "hal-microvm-l8-profile-v1"
	L8SourceLockSchemaVersionV1       = "hal-microvm-l8-source-lock-v1"
	L8SourceLockCatalogVersionV1      = "l8-source-lock-catalog-v1"
	L8ProcessCompositionCatalogV1     = "l8-process-composition-catalog-v1"
	L8FinalInspectionSchemaVersionV1  = "hal-microvm-l8-final-inspection-v1"
	L8FinalInspectionCatalogVersionV1 = "l8-final-inspection-catalog-v1"
	L8GuestAgentProtocolV2            = "guest-agent-v2"
)

// Versions records the exact source/tool versions that define an L5 image.
type Versions struct {
	Buildroot   string `json:"buildroot"`
	Linux       string `json:"linux"`
	BusyBox     string `json:"busybox"`
	E2fsprogs   string `json:"e2fsprogs"`
	Go          string `json:"go"`
	Firecracker string `json:"firecracker"`
}

// GuestAgent records the path-free protocol surface built into the rootfs.
type GuestAgent struct {
	Protocol string   `json:"protocol"`
	Features []string `json:"features"`
}

// GuestNetwork contains only safe image capability labels. It never carries
// addresses, interfaces, routes, endpoints, or boot parameters.
type GuestNetwork struct {
	Mode     string   `json:"mode"`
	Features []string `json:"features"`
}

// DistributionAsset identifies one relative installed artifact.
type DistributionAsset struct {
	Key       string `json:"key"`
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
}

// DistributionManifest is the path-free install/distribution contract.
type DistributionManifest struct {
	SchemaVersion string              `json:"schemaVersion"`
	ImageProfile  string              `json:"imageProfile,omitempty"`
	Architecture  string              `json:"architecture"`
	Versions      Versions            `json:"versions"`
	GuestAgent    GuestAgent          `json:"guestAgent"`
	GuestNetwork  *GuestNetwork       `json:"guestNetwork,omitempty"`
	L8Profile     *L8ProfileFacts     `json:"l8Profile,omitempty"`
	Assets        []DistributionAsset `json:"assets"`
}

// Output is one reproducible output fact in build provenance.
type Output struct {
	Key       string `json:"key"`
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
}

// Provenance contains only deterministic, path-free build facts.
type Provenance struct {
	SchemaVersion    string          `json:"schemaVersion"`
	ImageProfile     string          `json:"imageProfile,omitempty"`
	SourceRevision   string          `json:"sourceRevision"`
	SourceTree       string          `json:"sourceTree"`
	SourceDateEpoch  int64           `json:"sourceDateEpoch"`
	BuildImageDigest string          `json:"buildImageDigest"`
	Architecture     string          `json:"architecture"`
	Versions         Versions        `json:"versions"`
	GuestAgent       GuestAgent      `json:"guestAgent"`
	GuestNetwork     *GuestNetwork   `json:"guestNetwork,omitempty"`
	L8Profile        *L8ProfileFacts `json:"l8Profile,omitempty"`
	Outputs          []Output        `json:"outputs"`
}

// L8ParentL7Evidence binds the exact verified L7 distribution from which an
// L8 image was built. It contains only measured, path-free facts.
type L8ParentL7Evidence struct {
	ImageProfile     string `json:"imageProfile"`
	ManifestSHA256   string `json:"manifestSha256"`
	ProvenanceSHA256 string `json:"provenanceSha256"`
	ChecksumsSHA256  string `json:"checksumsSha256"`
	KernelSizeBytes  int64  `json:"kernelSizeBytes"`
	KernelSHA256     string `json:"kernelSha256"`
	RootfsSizeBytes  int64  `json:"rootfsSizeBytes"`
	RootfsSHA256     string `json:"rootfsSha256"`
	EvidenceSHA256   string `json:"evidenceSha256"`
}

// L8RuntimeFacts binds the exact Node and Pi runtime installed in the image.
type L8RuntimeFacts struct {
	NodeVersion            string `json:"nodeVersion"`
	NodeSHA256             string `json:"nodeSha256"`
	PiPackage              string `json:"piPackage"`
	PiVersion              string `json:"piVersion"`
	PiLauncherSHA256       string `json:"piLauncherSha256"`
	PiDependencyTreeSHA256 string `json:"piDependencyTreeSha256"`
}

// L8ProcessCompositionFacts binds the exact guest processes, descriptors,
// policy artifact, and external policy evidence.
type L8ProcessCompositionFacts struct {
	CatalogVersion               string `json:"catalogVersion"`
	GuestAgentSHA256             string `json:"guestAgentSha256"`
	GuestInitSHA256              string `json:"guestInitSha256"`
	CredentialHelperSHA256       string `json:"credentialHelperSha256"`
	MountMonitorSHA256           string `json:"mountMonitorSha256"`
	WorkloadShimSHA256           string `json:"workloadShimSha256"`
	RoleBootstrapSHA256          string `json:"roleBootstrapSha256"`
	HelperDescriptorSHA256       string `json:"helperDescriptorSha256"`
	ClientDescriptorSHA256       string `json:"clientDescriptorSha256"`
	CompositionSHA256            string `json:"compositionSha256"`
	WorkloadSnapshotSHA256       string `json:"workloadSnapshotSha256"`
	RuntimeProfileSHA256         string `json:"runtimeProfileSha256"`
	PolicyArtifactSHA256         string `json:"policyArtifactSha256"`
	PolicySourceLockSHA256       string `json:"policySourceLockSha256"`
	PolicyBinaryBindingSetSHA256 string `json:"policyBinaryBindingSetSha256"`
	PinnedCallsiteEvidenceSHA256 string `json:"pinnedCallsiteEvidenceSha256"`
}

// L8ProfileFacts is the additive, path-free L8 manifest/provenance contract.
type L8ProfileFacts struct {
	ContractVersion       string                    `json:"contractVersion"`
	ParentL7              L8ParentL7Evidence        `json:"parentL7"`
	Runtime               L8RuntimeFacts            `json:"runtime"`
	ProcessComposition    L8ProcessCompositionFacts `json:"processComposition"`
	SourceLockSHA256      string                    `json:"sourceLockSha256"`
	FinalInspectionSHA256 string                    `json:"finalInspectionSha256"`
}

// L8LockedSource is one exact offline input used for the Node/Pi runtime.
type L8LockedSource struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Filename  string `json:"filename"`
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
}

// L8SourceLock is the complete ordered offline source inventory.
type L8SourceLock struct {
	SchemaVersion  string             `json:"schemaVersion"`
	CatalogVersion string             `json:"catalogVersion"`
	ImageProfile   string             `json:"imageProfile"`
	ParentL7       L8ParentL7Evidence `json:"parentL7"`
	Runtime        L8RuntimeFacts     `json:"runtime"`
	Sources        []L8LockedSource   `json:"sources"`
}

// L8InspectionCheck is one safe, canonical final-inspection assertion.
type L8InspectionCheck struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	EvidenceSHA256 string `json:"evidenceSha256"`
}

// L8FinalInspection is the bounded final rootfs inspection result.
type L8FinalInspection struct {
	SchemaVersion      string                    `json:"schemaVersion"`
	CatalogVersion     string                    `json:"catalogVersion"`
	ImageProfile       string                    `json:"imageProfile"`
	RootfsSHA256       string                    `json:"rootfsSha256"`
	SourceLockSHA256   string                    `json:"sourceLockSha256"`
	ParentL7           L8ParentL7Evidence        `json:"parentL7"`
	Runtime            L8RuntimeFacts            `json:"runtime"`
	ProcessComposition L8ProcessCompositionFacts `json:"processComposition"`
	Checks             []L8InspectionCheck       `json:"checks"`
}

// DependencyLock is one immutable fetch input.
type DependencyLock struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Filename  string `json:"filename"`
	URL       string `json:"url"`
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
}

// DependencyFile is one measured cache entry.
type DependencyFile struct {
	Filename  string `json:"filename"`
	SizeBytes int64  `json:"sizeBytes"`
	SHA256    string `json:"sha256"`
}
