package build

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const l5SourceRevision = "762ee1a61d2efc5bb9241a6e87409ca20d68f976"

func TestL5DistributionManifestIsPathFreeAndCorrelated(t *testing.T) {
	manifest := validL5DistributionManifest()
	if err := ValidateDistributionManifest(manifest); err != nil {
		t.Fatalf("ValidateDistributionManifest() error = %v", err)
	}

	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{
		"/private/l5-source-canary",
		"/private/l5-output-canary",
		"hostPath",
		"sourcePath",
		"outputPath",
		"endpoint",
		"hostname",
		"username",
		"command",
		"environment",
	} {
		if strings.Contains(strings.ToLower(string(encoded)), strings.ToLower(forbidden)) {
			t.Fatalf("distribution manifest contains forbidden value %q: %s", forbidden, encoded)
		}
	}

	provenance := validL5Provenance(manifest)
	if err := ValidateProvenance(provenance); err != nil {
		t.Fatalf("ValidateProvenance() error = %v", err)
	}
	if err := ValidateProvenanceAgainstManifest(provenance, manifest); err != nil {
		t.Fatalf("ValidateProvenanceAgainstManifest() error = %v", err)
	}

	provenanceEncoded, err := json.Marshal(provenance)
	if err != nil {
		t.Fatalf("json.Marshal(provenance) error = %v", err)
	}
	for _, forbidden := range []string{
		"/private/l5-source-canary",
		"/private/l5-output-canary",
		"path",
		"endpoint",
		"hostname",
		"username",
		"command",
		"environment",
	} {
		if strings.Contains(strings.ToLower(string(provenanceEncoded)), strings.ToLower(forbidden)) {
			t.Fatalf("provenance contains forbidden value %q: %s", forbidden, provenanceEncoded)
		}
	}
}

func TestL5DistributionManifestRequiresExactUniqueOutputsAndFeatures(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DistributionManifest)
	}{
		{
			name: "duplicate asset key",
			mutate: func(manifest *DistributionManifest) {
				manifest.Assets[1].Key = manifest.Assets[0].Key
			},
		},
		{
			name: "duplicate asset id",
			mutate: func(manifest *DistributionManifest) {
				manifest.Assets[1].ID = manifest.Assets[0].ID
			},
		},
		{
			name: "missing kernel",
			mutate: func(manifest *DistributionManifest) {
				manifest.Assets = manifest.Assets[1:]
			},
		},
		{
			name: "extra output",
			mutate: func(manifest *DistributionManifest) {
				manifest.Assets = append(manifest.Assets, DistributionAsset{
					Key:       "unexpected.bin",
					ID:        "unexpected",
					Kind:      "unexpected",
					SizeBytes: 1,
					SHA256:    strings.Repeat("c", 64),
				})
			},
		},
		{
			name: "unsafe traversal key",
			mutate: func(manifest *DistributionManifest) {
				manifest.Assets[0].Key = "../vmlinux"
			},
		},
		{
			name: "absolute key",
			mutate: func(manifest *DistributionManifest) {
				manifest.Assets[0].Key = "/vmlinux"
			},
		},
		{
			name: "missing feature",
			mutate: func(manifest *DistributionManifest) {
				manifest.GuestAgent.Features = manifest.GuestAgent.Features[:3]
			},
		},
		{
			name: "duplicate feature",
			mutate: func(manifest *DistributionManifest) {
				manifest.GuestAgent.Features[3] = manifest.GuestAgent.Features[2]
			},
		},
		{
			name: "feature order drift",
			mutate: func(manifest *DistributionManifest) {
				manifest.GuestAgent.Features[0], manifest.GuestAgent.Features[1] =
					manifest.GuestAgent.Features[1], manifest.GuestAgent.Features[0]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := validL5DistributionManifest()
			tt.mutate(&manifest)
			if err := ValidateDistributionManifest(manifest); err == nil {
				t.Fatal("ValidateDistributionManifest() error = nil, want fail-closed error")
			}
		})
	}
}

func TestL5DistributionManifestRejectsPinnedVersionDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Versions)
	}{
		{name: "buildroot", mutate: func(value *Versions) { value.Buildroot = "2026.05" }},
		{name: "linux", mutate: func(value *Versions) { value.Linux = "6.1.177" }},
		{name: "busybox", mutate: func(value *Versions) { value.BusyBox = "1.37.0" }},
		{name: "e2fsprogs", mutate: func(value *Versions) { value.E2fsprogs = "1.47.3" }},
		{name: "go", mutate: func(value *Versions) { value.Go = "1.25.6" }},
		{name: "firecracker", mutate: func(value *Versions) { value.Firecracker = "v1.15.0" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := validL5DistributionManifest()
			tt.mutate(&manifest.Versions)
			if err := ValidateDistributionManifest(manifest); err == nil {
				t.Fatal("ValidateDistributionManifest() error = nil, want pinned-version failure")
			}

			provenance := validL5Provenance(validL5DistributionManifest())
			tt.mutate(&provenance.Versions)
			if err := ValidateProvenance(provenance); err == nil {
				t.Fatal("ValidateProvenance() error = nil, want pinned-version failure")
			}
		})
	}
}

func TestL5ProvenanceMustCorrelateWithDistributionManifest(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Provenance)
	}{
		{name: "architecture", mutate: func(value *Provenance) { value.Architecture = "arm64" }},
		{name: "versions", mutate: func(value *Provenance) { value.Versions.Go = "1.25.6" }},
		{name: "protocol", mutate: func(value *Provenance) { value.GuestAgent.Protocol = "guest-agent-v2" }},
		{name: "features", mutate: func(value *Provenance) { value.GuestAgent.Features = value.GuestAgent.Features[:3] }},
		{name: "output key", mutate: func(value *Provenance) { value.Outputs[0].Key = "kernel" }},
		{name: "output digest", mutate: func(value *Provenance) { value.Outputs[0].SHA256 = strings.Repeat("c", 64) }},
		{name: "output size", mutate: func(value *Provenance) { value.Outputs[0].SizeBytes++ }},
	}

	manifest := validL5DistributionManifest()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provenance := validL5Provenance(manifest)
			tt.mutate(&provenance)
			if err := ValidateProvenanceAgainstManifest(provenance, manifest); err == nil {
				t.Fatal("ValidateProvenanceAgainstManifest() error = nil, want correlation failure")
			}
		})
	}
}

func TestL5VerifyDependencyLocksFailsClosedOnMissingExtraDuplicateOrMismatch(t *testing.T) {
	locks := []DependencyLock{
		{
			Name:      "buildroot",
			Version:   "2026.05.1",
			Filename:  "buildroot-2026.05.1.tar.xz",
			URL:       "https://buildroot.org/downloads/buildroot-2026.05.1.tar.xz",
			SizeBytes: 1,
			SHA256:    strings.Repeat("a", 64),
		},
		{
			Name:      "linux",
			Version:   "6.1.178",
			Filename:  "linux-6.1.178.tar.xz",
			URL:       "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.178.tar.xz",
			SizeBytes: 2,
			SHA256:    strings.Repeat("b", 64),
		},
	}
	valid := []DependencyFile{
		{Filename: "buildroot-2026.05.1.tar.xz", SizeBytes: 1, SHA256: strings.Repeat("a", 64)},
		{Filename: "linux-6.1.178.tar.xz", SizeBytes: 2, SHA256: strings.Repeat("b", 64)},
	}
	if err := VerifyDependencyLocks(locks, valid); err != nil {
		t.Fatalf("VerifyDependencyLocks(valid) error = %v", err)
	}

	tests := []struct {
		name   string
		values []DependencyFile
	}{
		{name: "missing", values: valid[:1]},
		{name: "extra", values: append(append([]DependencyFile{}, valid...), DependencyFile{Filename: "other.tar", SizeBytes: 3, SHA256: strings.Repeat("c", 64)})},
		{name: "duplicate", values: append(append([]DependencyFile{}, valid...), valid[1])},
		{name: "size mismatch", values: []DependencyFile{valid[0], {Filename: valid[1].Filename, SizeBytes: 3, SHA256: valid[1].SHA256}}},
		{name: "digest mismatch", values: []DependencyFile{valid[0], {Filename: valid[1].Filename, SizeBytes: valid[1].SizeBytes, SHA256: strings.Repeat("c", 64)}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyDependencyLocks(locks, tt.values); err == nil {
				t.Fatal("VerifyDependencyLocks() error = nil, want fail-closed error")
			}
		})
	}
}

func validL5DistributionManifest() DistributionManifest {
	return DistributionManifest{
		SchemaVersion: SchemaVersionV1,
		Architecture:  "x86_64",
		Versions: Versions{
			Buildroot:   "2026.05.1",
			Linux:       "6.1.178",
			BusyBox:     "1.38.0",
			E2fsprogs:   "1.47.4",
			Go:          "1.25.7",
			Firecracker: "v1.15.1",
		},
		GuestAgent: GuestAgent{
			Protocol: "guest-agent-v1",
			Features: []string{"copy_in", "copy_out", "exec", "readiness"},
		},
		Assets: []DistributionAsset{
			{
				Key:       "vmlinux",
				ID:        "kernel",
				Kind:      "kernel_image",
				SizeBytes: 4096,
				SHA256:    strings.Repeat("a", 64),
			},
			{
				Key:       "rootfs.ext4",
				ID:        "rootfs",
				Kind:      "rootfs_image",
				SizeBytes: 8192,
				SHA256:    strings.Repeat("b", 64),
			},
		},
	}
}

func validL5Provenance(manifest DistributionManifest) Provenance {
	outputs := make([]Output, len(manifest.Assets))
	for i, asset := range manifest.Assets {
		outputs[i] = Output(asset)
	}
	return Provenance{
		SchemaVersion:    SchemaVersionV1,
		SourceRevision:   l5SourceRevision,
		SourceTree:       "tree-0123456789abcdef",
		SourceDateEpoch:  1785024000,
		BuildImageDigest: "sha256:" + strings.Repeat("d", 64),
		Architecture:     manifest.Architecture,
		Versions:         manifest.Versions,
		GuestAgent:       manifest.GuestAgent,
		Outputs:          outputs,
	}
}

func TestL5FeatureOrderIsLocked(t *testing.T) {
	got := validL5DistributionManifest().GuestAgent.Features
	want := []string{"copy_in", "copy_out", "exec", "readiness"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("guest features = %v, want %v", got, want)
	}
}
