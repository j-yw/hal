package build

const SchemaVersionV1 = "hal-microvm-image-v1"

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
	Architecture  string              `json:"architecture"`
	Versions      Versions            `json:"versions"`
	GuestAgent    GuestAgent          `json:"guestAgent"`
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
	SchemaVersion    string     `json:"schemaVersion"`
	SourceRevision   string     `json:"sourceRevision"`
	SourceTree       string     `json:"sourceTree"`
	SourceDateEpoch  int64      `json:"sourceDateEpoch"`
	BuildImageDigest string     `json:"buildImageDigest"`
	Architecture     string     `json:"architecture"`
	Versions         Versions   `json:"versions"`
	GuestAgent       GuestAgent `json:"guestAgent"`
	Outputs          []Output   `json:"outputs"`
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
