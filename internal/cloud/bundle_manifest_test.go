package cloud

import (
	"strings"
	"testing"
)

func validBundleManifest() BundleManifest {
	records := []BundleManifestRecord{
		{Path: ".hal/prd.json", SHA256: "abc123", SizeBytes: 100},
		{Path: ".hal/progress.txt", SHA256: "def456", SizeBytes: 200},
	}
	return BundleManifest{
		Records: records,
		SHA256:  ComputeBundleHash(records),
	}
}

func TestBundleManifest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(m *BundleManifest)
		wantErr string
	}{
		{
			name:   "valid manifest passes",
			modify: func(m *BundleManifest) {},
		},
		{
			name:    "empty sha256",
			modify:  func(m *BundleManifest) { m.SHA256 = "" },
			wantErr: "bundle_manifest.sha256 must not be empty",
		},
		{
			name:    "empty records",
			modify:  func(m *BundleManifest) { m.Records = nil },
			wantErr: "bundle_manifest.records must not be empty",
		},
		{
			name: "record with empty path",
			modify: func(m *BundleManifest) {
				m.Records[0].Path = ""
			},
			wantErr: "bundle_manifest.records[0].path must not be empty",
		},
		{
			name: "record with empty sha256",
			modify: func(m *BundleManifest) {
				m.Records[0].SHA256 = ""
			},
			wantErr: "bundle_manifest.records[0].sha256 must not be empty",
		},
		{
			name: "record with negative size_bytes",
			modify: func(m *BundleManifest) {
				m.Records[0].SizeBytes = -1
			},
			wantErr: "bundle_manifest.records[0].size_bytes must be >= 0",
		},
		{
			name: "duplicate paths",
			modify: func(m *BundleManifest) {
				m.Records = []BundleManifestRecord{
					{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
					{Path: ".hal/prd.json", SHA256: "def", SizeBytes: 20},
				}
			},
			wantErr: "duplicate path",
		},
		{
			name: "duplicate paths with different separators",
			modify: func(m *BundleManifest) {
				m.Records = []BundleManifestRecord{
					{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
					{Path: ".hal\\prd.json", SHA256: "def", SizeBytes: 20},
				}
			},
			wantErr: "duplicate path",
		},
		{
			name: "zero size_bytes is valid",
			modify: func(m *BundleManifest) {
				m.Records[0].SizeBytes = 0
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validBundleManifest()
			tt.modify(&m)
			err := m.Validate()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBundleManifest_VerifyHash(t *testing.T) {
	t.Run("valid hash passes", func(t *testing.T) {
		m := validBundleManifest()
		if err := m.VerifyHash(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("tampered hash fails", func(t *testing.T) {
		m := validBundleManifest()
		m.SHA256 = "tampered"
		err := m.VerifyHash()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "bundle hash mismatch") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("modified records fail hash", func(t *testing.T) {
		m := validBundleManifest()
		m.Records[0].SHA256 = "modified"
		err := m.VerifyHash()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "bundle hash mismatch") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func TestComputeBundleHash(t *testing.T) {
	t.Run("deterministic across calls", func(t *testing.T) {
		records := []BundleManifestRecord{
			{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
			{Path: ".hal/progress.txt", SHA256: "def", SizeBytes: 20},
		}
		hash1 := ComputeBundleHash(records)
		hash2 := ComputeBundleHash(records)
		if hash1 != hash2 {
			t.Fatalf("hash not deterministic: %s != %s", hash1, hash2)
		}
	})

	t.Run("order independent", func(t *testing.T) {
		records1 := []BundleManifestRecord{
			{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
			{Path: ".hal/progress.txt", SHA256: "def", SizeBytes: 20},
		}
		records2 := []BundleManifestRecord{
			{Path: ".hal/progress.txt", SHA256: "def", SizeBytes: 20},
			{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
		}
		hash1 := ComputeBundleHash(records1)
		hash2 := ComputeBundleHash(records2)
		if hash1 != hash2 {
			t.Fatalf("hash not order-independent: %s != %s", hash1, hash2)
		}
	})

	t.Run("different content produces different hash", func(t *testing.T) {
		records1 := []BundleManifestRecord{
			{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
		}
		records2 := []BundleManifestRecord{
			{Path: ".hal/prd.json", SHA256: "xyz", SizeBytes: 10},
		}
		hash1 := ComputeBundleHash(records1)
		hash2 := ComputeBundleHash(records2)
		if hash1 == hash2 {
			t.Fatal("different content should produce different hash")
		}
	})

	t.Run("different paths produce different hash", func(t *testing.T) {
		records1 := []BundleManifestRecord{
			{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
		}
		records2 := []BundleManifestRecord{
			{Path: ".hal/config.yaml", SHA256: "abc", SizeBytes: 10},
		}
		hash1 := ComputeBundleHash(records1)
		hash2 := ComputeBundleHash(records2)
		if hash1 == hash2 {
			t.Fatal("different paths should produce different hash")
		}
	})

	t.Run("normalized paths produce same hash", func(t *testing.T) {
		records1 := []BundleManifestRecord{
			{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
		}
		records2 := []BundleManifestRecord{
			{Path: ".hal\\prd.json", SHA256: "abc", SizeBytes: 10},
		}
		hash1 := ComputeBundleHash(records1)
		hash2 := ComputeBundleHash(records2)
		if hash1 != hash2 {
			t.Fatalf("normalized paths should produce same hash: %s != %s", hash1, hash2)
		}
	})

	t.Run("empty records", func(t *testing.T) {
		hash := ComputeBundleHash(nil)
		if hash == "" {
			t.Fatal("empty records should still produce a valid hash")
		}
	})

	t.Run("does not mutate input", func(t *testing.T) {
		records := []BundleManifestRecord{
			{Path: ".hal/progress.txt", SHA256: "def", SizeBytes: 20},
			{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
		}
		_ = ComputeBundleHash(records)
		if records[0].Path != ".hal/progress.txt" {
			t.Fatal("ComputeBundleHash mutated input slice")
		}
	})
}

func TestNormalizeBundlePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{".hal/prd.json", ".hal/prd.json"},
		{".hal\\prd.json", ".hal/prd.json"},
		{".hal//prd.json", ".hal/prd.json"},
		{".hal/./prd.json", ".hal/prd.json"},
		{".hal/standards/../prd.json", ".hal/prd.json"},
		{".//.hal/prd.json", ".hal/prd.json"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeBundlePath(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeBundlePath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsBundlePathAllowed(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// Allowlisted exact paths
		{"prd.json allowed", ".hal/prd.json", true},
		{"auto-prd.json allowed", ".hal/auto-prd.json", true},
		{"progress.txt allowed", ".hal/progress.txt", true},
		{"prompt.md allowed", ".hal/prompt.md", true},
		{"config.yaml allowed", ".hal/config.yaml", true},

		// Allowlisted glob paths
		{"standards file allowed", ".hal/standards/style.md", true},
		{"standards nested allowed", ".hal/standards/sub/deep.md", true},

		// Denylisted paths
		{"archive denied", ".hal/archive/2024-01-01-feature.tar.gz", false},
		{"reports denied", ".hal/reports/summary.txt", false},
		{"skills denied", ".hal/skills/default.md", false},
		{"commands denied", ".hal/commands/test.md", false},
		{".pi denied", ".pi/config", false},
		{".claude denied", ".claude/config.json", false},
		{"~/.codex denied", "~/.codex/config", false},

		// Not in allowlist
		{"unknown .hal file", ".hal/unknown.txt", false},
		{"root file", "main.go", false},
		{"empty path", "", false},

		// Path normalization
		{"backslash normalized", ".hal\\prd.json", true},
		{"double slash normalized", ".hal//prd.json", true},

		// Denylist takes priority
		{"archive subdir denied despite being under .hal", ".hal/archive/old/state.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBundlePathAllowed(tt.path)
			if got != tt.want {
				t.Errorf("IsBundlePathAllowed(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestMatchBundlePattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"exact match", ".hal/prd.json", ".hal/prd.json", true},
		{"exact no match", ".hal/prd.json", ".hal/config.yaml", false},
		{"glob matches child", ".hal/standards/**", ".hal/standards/style.md", true},
		{"glob matches deep child", ".hal/standards/**", ".hal/standards/sub/deep.md", true},
		{"glob no match parent", ".hal/standards/**", ".hal/other.txt", false},
		{"glob no match partial", ".hal/standards/**", ".hal/standards_extra/file.txt", false},
		{"glob matches directory itself", ".hal/standards/**", ".hal/standards", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchBundlePattern(tt.pattern, NormalizeBundlePath(tt.path))
			if got != tt.want {
				t.Errorf("matchBundlePattern(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

func TestComputeFileSHA256(t *testing.T) {
	t.Run("deterministic", func(t *testing.T) {
		content := []byte("hello world")
		hash1 := ComputeFileSHA256(content)
		hash2 := ComputeFileSHA256(content)
		if hash1 != hash2 {
			t.Fatalf("not deterministic: %s != %s", hash1, hash2)
		}
	})

	t.Run("different content different hash", func(t *testing.T) {
		hash1 := ComputeFileSHA256([]byte("hello"))
		hash2 := ComputeFileSHA256([]byte("world"))
		if hash1 == hash2 {
			t.Fatal("different content should produce different hash")
		}
	})

	t.Run("empty content valid hash", func(t *testing.T) {
		hash := ComputeFileSHA256([]byte{})
		if hash == "" {
			t.Fatal("empty content should produce valid hash")
		}
		if len(hash) != 64 {
			t.Fatalf("sha256 hex should be 64 chars, got %d", len(hash))
		}
	})

	t.Run("known value", func(t *testing.T) {
		// SHA-256 of empty string is well-known
		hash := ComputeFileSHA256([]byte{})
		want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		if hash != want {
			t.Fatalf("got %s, want %s", hash, want)
		}
	})
}

func TestNewBundleManifestRecord(t *testing.T) {
	content := []byte("test content")
	record := NewBundleManifestRecord(".hal/prd.json", content)

	if record.Path != ".hal/prd.json" {
		t.Errorf("Path = %q, want %q", record.Path, ".hal/prd.json")
	}
	if record.SizeBytes != int64(len(content)) {
		t.Errorf("SizeBytes = %d, want %d", record.SizeBytes, len(content))
	}
	if record.SHA256 != ComputeFileSHA256(content) {
		t.Errorf("SHA256 mismatch")
	}
}

func TestNewBundleManifest(t *testing.T) {
	t.Run("sorts records by path", func(t *testing.T) {
		records := []BundleManifestRecord{
			{Path: ".hal/progress.txt", SHA256: "def", SizeBytes: 20},
			{Path: ".hal/config.yaml", SHA256: "ghi", SizeBytes: 30},
			{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
		}
		m := NewBundleManifest(records)

		if m.Records[0].Path != ".hal/config.yaml" {
			t.Errorf("first record should be config.yaml, got %s", m.Records[0].Path)
		}
		if m.Records[1].Path != ".hal/prd.json" {
			t.Errorf("second record should be prd.json, got %s", m.Records[1].Path)
		}
		if m.Records[2].Path != ".hal/progress.txt" {
			t.Errorf("third record should be progress.txt, got %s", m.Records[2].Path)
		}
	})

	t.Run("computes hash", func(t *testing.T) {
		records := []BundleManifestRecord{
			{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
		}
		m := NewBundleManifest(records)

		if m.SHA256 == "" {
			t.Fatal("SHA256 should not be empty")
		}
		if err := m.VerifyHash(); err != nil {
			t.Fatalf("hash verification failed: %v", err)
		}
	})

	t.Run("does not mutate input", func(t *testing.T) {
		records := []BundleManifestRecord{
			{Path: ".hal/progress.txt", SHA256: "def", SizeBytes: 20},
			{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
		}
		_ = NewBundleManifest(records)
		if records[0].Path != ".hal/progress.txt" {
			t.Fatal("NewBundleManifest mutated input slice")
		}
	})

	t.Run("sets created_at", func(t *testing.T) {
		records := []BundleManifestRecord{
			{Path: ".hal/prd.json", SHA256: "abc", SizeBytes: 10},
		}
		m := NewBundleManifest(records)
		if m.CreatedAt.IsZero() {
			t.Fatal("CreatedAt should not be zero")
		}
	})
}

func TestBundleAllowlist(t *testing.T) {
	t.Run("contains required paths", func(t *testing.T) {
		required := []string{
			".hal/prd.json",
			".hal/auto-prd.json",
			".hal/progress.txt",
			".hal/prompt.md",
			".hal/config.yaml",
			".hal/standards/**",
		}
		for _, r := range required {
			found := false
			for _, a := range BundleAllowlist {
				if a == r {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("allowlist missing required path %q", r)
			}
		}
	})
}

func TestBundleDenylist(t *testing.T) {
	t.Run("contains required paths", func(t *testing.T) {
		required := []string{
			".hal/archive/**",
			".hal/reports/**",
			".hal/skills/**",
			".hal/commands/**",
			".pi/**",
			".claude/**",
			"~/.codex/**",
		}
		for _, r := range required {
			found := false
			for _, d := range BundleDenylist {
				if d == r {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("denylist missing required path %q", r)
			}
		}
	})
}

func TestBundleHashUsesNormalizedPaths(t *testing.T) {
	// Records with backslash and forward slash paths should produce the same hash.
	records1 := []BundleManifestRecord{
		{Path: ".hal/standards/style.md", SHA256: "abc", SizeBytes: 10},
	}
	records2 := []BundleManifestRecord{
		{Path: ".hal\\standards\\style.md", SHA256: "abc", SizeBytes: 10},
	}
	hash1 := ComputeBundleHash(records1)
	hash2 := ComputeBundleHash(records2)
	if hash1 != hash2 {
		t.Fatalf("hashes should be equal after normalization: %s != %s", hash1, hash2)
	}
}
