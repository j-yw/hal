package cloud

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
)

// BundleAllowlist is the set of .hal paths included in a state bundle.
// Paths ending with /** are recursive glob patterns.
var BundleAllowlist = []string{
	".hal/prd.json",
	".hal/auto-prd.json",
	".hal/progress.txt",
	".hal/auto-state.json",
	".hal/prompt.md",
	".hal/config.yaml",
	".hal/standards/**",
}

// BundleDenylist is the set of paths excluded from a state bundle.
// Paths ending with /** are recursive glob patterns.
var BundleDenylist = []string{
	".hal/archive/**",
	".hal/reports/**",
	".hal/skills/**",
	".hal/commands/**",
	".pi/**",
	".claude/**",
	"~/.codex/**",
}

// BundleManifestRecord represents a single file entry in a bundle manifest.
type BundleManifestRecord struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// BundleManifest represents the manifest for a .hal state bundle upload.
type BundleManifest struct {
	Records   []BundleManifestRecord `json:"records"`
	SHA256    string                 `json:"sha256"`
	CreatedAt time.Time              `json:"created_at"`
}

// Validate checks that the manifest has a valid hash, at least one record,
// and all records have required fields with no duplicate paths.
func (m *BundleManifest) Validate() error {
	if m.SHA256 == "" {
		return fmt.Errorf("bundle_manifest.sha256 must not be empty")
	}
	if len(m.Records) == 0 {
		return fmt.Errorf("bundle_manifest.records must not be empty")
	}
	seen := make(map[string]bool, len(m.Records))
	for i, r := range m.Records {
		if r.Path == "" {
			return fmt.Errorf("bundle_manifest.records[%d].path must not be empty", i)
		}
		if r.SHA256 == "" {
			return fmt.Errorf("bundle_manifest.records[%d].sha256 must not be empty", i)
		}
		if r.SizeBytes < 0 {
			return fmt.Errorf("bundle_manifest.records[%d].size_bytes must be >= 0, got %d", i, r.SizeBytes)
		}
		normalized := NormalizeBundlePath(r.Path)
		if seen[normalized] {
			return fmt.Errorf("bundle_manifest.records contains duplicate path %q", r.Path)
		}
		seen[normalized] = true
	}
	return nil
}

// VerifyHash checks that the manifest SHA256 matches the computed hash of its records.
func (m *BundleManifest) VerifyHash() error {
	computed := ComputeBundleHash(m.Records)
	if computed != m.SHA256 {
		return fmt.Errorf("bundle hash mismatch: manifest=%s computed=%s", m.SHA256, computed)
	}
	return nil
}

// NormalizeBundlePath normalizes a file path for deterministic hashing.
// It cleans the path and converts to forward slashes.
func NormalizeBundlePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean(p)
	return p
}

// ComputeBundleHash computes a deterministic SHA-256 hash over sorted
// path + content-byte records. The hash input for each record is:
//
//	<normalized_path>\x00<file_sha256>\n
//
// Records are sorted by normalized path before hashing.
func ComputeBundleHash(records []BundleManifestRecord) string {
	// Sort by normalized path for determinism.
	sorted := make([]BundleManifestRecord, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		return NormalizeBundlePath(sorted[i].Path) < NormalizeBundlePath(sorted[j].Path)
	})

	h := sha256.New()
	for _, r := range sorted {
		// Write normalized_path NUL file_sha256 LF
		h.Write([]byte(NormalizeBundlePath(r.Path)))
		h.Write([]byte{0x00})
		h.Write([]byte(r.SHA256))
		h.Write([]byte{0x0a})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// IsBundlePathAllowed reports whether the given path passes the bundle
// allowlist/denylist checks. The path should be relative (e.g., ".hal/prd.json").
func IsBundlePathAllowed(filePath string) bool {
	normalized := NormalizeBundlePath(filePath)

	// Check denylist first — denied paths are always excluded.
	for _, pattern := range BundleDenylist {
		if matchBundlePattern(pattern, normalized) {
			return false
		}
	}

	// Check allowlist — path must match at least one allow pattern.
	for _, pattern := range BundleAllowlist {
		if matchBundlePattern(pattern, normalized) {
			return true
		}
	}
	return false
}

// matchBundlePattern matches a path against a bundle pattern.
// Patterns ending with /** match the directory and all descendants.
// Exact patterns match only the specified path.
func matchBundlePattern(pattern, filePath string) bool {
	pattern = NormalizeBundlePath(pattern)

	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		// Match the directory itself or any path under it.
		return filePath == prefix || strings.HasPrefix(filePath, prefix+"/")
	}
	return filePath == pattern
}

// ComputeFileSHA256 computes the SHA-256 hash of file content.
func ComputeFileSHA256(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// NewBundleManifestRecord creates a BundleManifestRecord from a path and content.
func NewBundleManifestRecord(filePath string, content []byte) BundleManifestRecord {
	return BundleManifestRecord{
		Path:      NormalizeBundlePath(filePath),
		SHA256:    ComputeFileSHA256(content),
		SizeBytes: int64(len(content)),
	}
}

// NewBundleManifest creates a BundleManifest from a set of records.
// Records are sorted by path and the bundle hash is computed automatically.
func NewBundleManifest(records []BundleManifestRecord) BundleManifest {
	// Sort records by normalized path for deterministic ordering.
	sorted := make([]BundleManifestRecord, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		return NormalizeBundlePath(sorted[i].Path) < NormalizeBundlePath(sorted[j].Path)
	})

	return BundleManifest{
		Records:   sorted,
		SHA256:    ComputeBundleHash(sorted),
		CreatedAt: time.Now(),
	}
}
