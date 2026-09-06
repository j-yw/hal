package build

import "strings"

const (
	ImageProfileL8MinimalCredentials = "l8-minimal-credentials-v1"
	L8MinimalProfileContractV1       = "hal-microvm-l8-minimal-profile-v1"
	L8MinimalSourceLockSchemaV1      = "hal-microvm-l8-minimal-source-lock-v1"
	L8MinimalInspectionSchemaV1      = "hal-microvm-l8-minimal-inspection-v1"
)

// The minimal contracts intentionally do not extend legacy L5/L7/L8 JSON.
type L8MinimalDistributionManifest struct {
	SchemaVersion  string                `json:"schemaVersion"`
	ImageProfile   string                `json:"imageProfile"`
	Architecture   string                `json:"architecture"`
	Versions       Versions              `json:"versions"`
	GuestAgent     GuestAgent            `json:"guestAgent"`
	GuestNetwork   *GuestNetwork         `json:"guestNetwork"`
	MinimalProfile L8MinimalProfileFacts `json:"minimalProfile"`
	Assets         []DistributionAsset   `json:"assets"`
}

type L8MinimalProvenance struct {
	SchemaVersion    string                `json:"schemaVersion"`
	ImageProfile     string                `json:"imageProfile"`
	SourceRevision   string                `json:"sourceRevision"`
	SourceTree       string                `json:"sourceTree"`
	SourceDateEpoch  int64                 `json:"sourceDateEpoch"`
	BuildImageDigest string                `json:"buildImageDigest"`
	Architecture     string                `json:"architecture"`
	Versions         Versions              `json:"versions"`
	GuestAgent       GuestAgent            `json:"guestAgent"`
	GuestNetwork     *GuestNetwork         `json:"guestNetwork"`
	MinimalProfile   L8MinimalProfileFacts `json:"minimalProfile"`
	Outputs          []Output              `json:"outputs"`
}

type L8MinimalProfileFacts struct {
	ContractVersion       string             `json:"contractVersion"`
	ParentL7              L8ParentL7Evidence `json:"parentL7"`
	Runtime               L8RuntimeFacts     `json:"runtime"`
	GuestInitSHA256       string             `json:"guestInitSha256"`
	GuestAgentSHA256      string             `json:"guestAgentSha256"`
	SourceLockSHA256      string             `json:"sourceLockSha256"`
	FinalInspectionSHA256 string             `json:"finalInspectionSha256"`
}

type L8MinimalSourceLock struct {
	SchemaVersion  string             `json:"schemaVersion"`
	ImageProfile   string             `json:"imageProfile"`
	SourceRevision string             `json:"sourceRevision"`
	ParentL7       L8ParentL7Evidence `json:"parentL7"`
	Runtime        L8RuntimeFacts     `json:"runtime"`
	Sources        []L8LockedSource   `json:"sources"`
}

// L8MinimalExecutable is a measured final-image executable, not a live process.
type L8MinimalExecutable struct {
	Role      string  `json:"role"`
	Type      string  `json:"type"`
	SHA256    string  `json:"sha256"`
	SizeBytes int64   `json:"sizeBytes"`
	UID       *uint32 `json:"uid"`
	GID       *uint32 `json:"gid"`
	Mode      uint32  `json:"mode"`
}

// L8MinimalInventory records bounded image-inspector measurements. Findings
// must be explicitly empty, never absent. The bundle verifier correlates this
// document to a caller-pinned digest; it does not inspect ext4 contents itself.
type L8MinimalInventory struct {
	// Inodes counts unique reachable inodes visited, not allocated capacity.
	Inodes uint64 `json:"inodes"`
	// DirectoryRecords counts records visited by the bounded traversal.
	DirectoryRecords uint64   `json:"directoryRecords"`
	LogicalBytes     uint64   `json:"logicalBytes"`
	Findings         []string `json:"findings"`
}

type L8MinimalFinalInspection struct {
	SchemaVersion    string                `json:"schemaVersion"`
	ImageProfile     string                `json:"imageProfile"`
	SourceRevision   string                `json:"sourceRevision"`
	RootfsSHA256     string                `json:"rootfsSha256"`
	SourceLockSHA256 string                `json:"sourceLockSha256"`
	ParentL7         L8ParentL7Evidence    `json:"parentL7"`
	Runtime          L8RuntimeFacts        `json:"runtime"`
	Executables      []L8MinimalExecutable `json:"executables"`
	Inventory        L8MinimalInventory    `json:"inventory"`
	AgentUID         uint32                `json:"agentUid"`
	WorkloadUID      uint32                `json:"workloadUid"`
	WorkspaceUID     uint32                `json:"workspaceUid"`
	WorkspaceMode    uint32                `json:"workspaceMode"`
}

// ValidateL8MinimalDocuments validates exact minimal-profile metadata without
// granting live authority or entering the legacy policy-evidence validator.
func ValidateL8MinimalDocuments(m L8MinimalDistributionManifest, p L8MinimalProvenance, s L8MinimalSourceLock, i L8MinimalFinalInspection) error {
	fail := func() error { return l8ValidationError(L8ValidationCodeCorrelationMismatch, "minimalProfile", -1) }
	if m.SchemaVersion != SchemaVersionV1 || p.SchemaVersion != SchemaVersionV1 || s.SchemaVersion != L8MinimalSourceLockSchemaV1 || i.SchemaVersion != L8MinimalInspectionSchemaV1 ||
		m.ImageProfile != ImageProfileL8MinimalCredentials || p.ImageProfile != m.ImageProfile || s.ImageProfile != m.ImageProfile || i.ImageProfile != m.ImageProfile {
		return fail()
	}
	if m.Architecture != "x86_64" || p.Architecture != m.Architecture || !validVersions(m.Versions) || p.Versions != m.Versions ||
		m.GuestAgent.Protocol != "guest-agent-v1" || !equalStrings(m.GuestAgent.Features, requiredFeatures) || p.GuestAgent.Protocol != m.GuestAgent.Protocol || !equalStrings(p.GuestAgent.Features, m.GuestAgent.Features) ||
		!validImageNetworkProfile(ImageProfileL7Network, m.GuestNetwork) || !equalGuestNetwork(m.GuestNetwork, p.GuestNetwork) {
		return fail()
	}
	if !validHex(p.SourceRevision, 40) || p.SourceRevision != s.SourceRevision || p.SourceRevision != i.SourceRevision || !safeSourceTree(p.SourceTree) || p.SourceDateEpoch <= 0 ||
		!strings.HasPrefix(p.BuildImageDigest, "sha256:") || !minimalDigest(strings.TrimPrefix(p.BuildImageDigest, "sha256:")) {
		return fail()
	}
	facts := m.MinimalProfile
	if facts.ContractVersion != L8MinimalProfileContractV1 || facts != p.MinimalProfile || facts.ParentL7 != s.ParentL7 || facts.ParentL7 != i.ParentL7 ||
		facts.Runtime != s.Runtime || facts.Runtime != i.Runtime || validateL8Parent(facts.ParentL7) != nil || validateL8Runtime(facts.Runtime) != nil {
		return fail()
	}
	for _, digest := range []string{facts.GuestInitSHA256, facts.GuestAgentSHA256, facts.SourceLockSHA256, facts.FinalInspectionSHA256, facts.Runtime.NodeSHA256, facts.Runtime.PiLauncherSHA256, facts.Runtime.PiDependencyTreeSHA256, i.RootfsSHA256} {
		if !minimalDigest(digest) {
			return fail()
		}
	}
	if i.SourceLockSHA256 != facts.SourceLockSHA256 || len(m.Assets) != 2 || validateDistributionAssets(m.Assets) != nil || len(p.Outputs) != 2 || validateDistributionOutputs(p.Outputs) != nil {
		return fail()
	}
	for index, asset := range m.Assets {
		output := p.Outputs[index]
		if asset.Key != output.Key || asset.ID != output.ID || asset.Kind != output.Kind || asset.SHA256 != output.SHA256 || asset.SizeBytes != output.SizeBytes || asset.SizeBytes > l8MaxFileBytes {
			return fail()
		}
		if (asset.Key == "vmlinux" && (asset.SHA256 != facts.ParentL7.KernelSHA256 || asset.SizeBytes != facts.ParentL7.KernelSizeBytes)) || (asset.Key == "rootfs.ext4" && asset.SHA256 != i.RootfsSHA256) {
			return fail()
		}
	}
	if err := ValidateL8MinimalSourceLock(s); err != nil {
		return err
	}
	if len(i.Executables) != 4 {
		return fail()
	}
	roles := []string{"hal-init", "hal-guest-agent", "node", "pi-launcher"}
	digests := []string{facts.GuestInitSHA256, facts.GuestAgentSHA256, facts.Runtime.NodeSHA256, facts.Runtime.PiLauncherSHA256}
	for index, executable := range i.Executables {
		if executable.Role != roles[index] || executable.Type != "regular" || executable.SHA256 != digests[index] || executable.SizeBytes <= 0 || executable.SizeBytes > l8MaxFileBytes || executable.UID == nil || executable.GID == nil || *executable.UID != 0 || *executable.GID != 0 || executable.Mode != 0755 {
			return fail()
		}
	}
	if i.Inventory.Inodes < 4 || i.Inventory.Inodes > 65536 || i.Inventory.DirectoryRecords < 4 || i.Inventory.DirectoryRecords > 262144 || i.Inventory.LogicalBytes == 0 || i.Inventory.LogicalBytes > 512<<20 || i.Inventory.Findings == nil || len(i.Inventory.Findings) != 0 ||
		i.AgentUID != 1000 || i.WorkloadUID != 1000 || i.WorkspaceUID != 1000 || i.WorkspaceMode != 0700 {
		return fail()
	}
	return nil
}

// ValidateL8MinimalSourceLock validates the minimal source metadata envelope
// and its complete pinned inventory. Callers still must measure source bytes;
// this pure validation does not issue an image profile or runtime authority.
func ValidateL8MinimalSourceLock(lock L8MinimalSourceLock) error {
	if lock.SchemaVersion != L8MinimalSourceLockSchemaV1 || lock.ImageProfile != ImageProfileL8MinimalCredentials || !validHex(lock.SourceRevision, 40) {
		return l8ValidationError(L8ValidationCodeCorrelationMismatch, "minimalProfile", -1)
	}
	// Reuse the exact offline inventory validator, not the legacy image or
	// process-policy validator. This conversion never issues a legacy profile.
	return ValidateL8SourceLock(L8SourceLock{SchemaVersion: L8SourceLockSchemaVersionV1, CatalogVersion: L8SourceLockCatalogVersionV1, ImageProfile: ImageProfileL8ProductionCredentials, ParentL7: lock.ParentL7, Runtime: lock.Runtime, Sources: lock.Sources})
}

// L8MinimalDependencyTreeSHA256 reuses the canonical source inventory digest;
// callers must measure each source record before recording it in the lock.
func L8MinimalDependencyTreeSHA256(sources []L8LockedSource) string {
	return l8PiDependencyTreeSHA256(sources)
}

func minimalDigest(value string) bool { return validSHA256(value) && value != strings.Repeat("0", 64) }
