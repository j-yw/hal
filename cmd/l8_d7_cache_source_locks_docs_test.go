package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

const l8D7CacheSourceLocksDoc = "sandbox-runtime-v2-l8-d7-cache-source-locks.md"

func TestL8D7CacheSourceLocksVerificationDocument(t *testing.T) {
	doc := strings.Join(strings.Fields(readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7CacheSourceLocksDoc))), " ")
	for _, required := range []string{
		"authors the exact L8 `cache.manifest`",
		"Digests are not invented",
		"Tarball bytes stay in the operator cache",
		"`VerifyL8DistributionBundle` is not called",
		"HL8E remains unissued",
		"does not claim D7 live",
		"does not claim L8 complete",
		"does not claim L10",
		"does not claim L11",
		"does not change live D7 stub fatals",
		"tools/microvm/l8/cache.manifest",
		"digest<TAB>size<TAB>filename",
		"lowercase hex SHA-256",
		"must not duplicate any L5",
		"firecracker-*.tgz",
		"node-v22.22.0.tar.xz",
		"50902788",
		"4c138012bb5352f49822a8f3e6d1db71e00639d0c36d5b6756f91e4c6f30b683",
		"https://nodejs.org/dist/v22.22.0/node-v22.22.0.tar.xz",
		"pi-coding-agent-0.82.1.tgz",
		"4978133",
		"8343ab95cbab5766f2f5d48844df8db13e772ead2e2976166cbb820a29dacb7d",
		"npm pack @earendil-works/pi-coding-agent@0.82.1",
		"pi-shrinkwrap-0.82.1.json",
		"61545",
		"ac68e6c713a3fa13b56d2e41855dcfce44fe2ca1645ccc90977bea3afbeaf50a",
		"package/npm-shrinkwrap.json",
		"lockfileVersion 3",
		"139 transitive npm archives",
		"142 entries",
		"Unit tests do not download",
		"fail-closes on missing files",
		"unsorted records",
		"duplicate L5/L8 filenames",
		"go test ./tools/microvm/l8 -count=1",
		"go test ./cmd -run '^TestL8D7CacheSourceLocks' -count=1",
		"bash -n tools/microvm/l8/verify-cache.sh",
		"go vet ./tools/microvm/l8 ./cmd",
		"These commands are fake-only",
		"do not boot a VM",
		"call billed APIs",
		"select live tags",
		"command -v golangci-lint",
		"accept D7 prepared-Linux live proof",
		"issue HL8E or enable `generateEvidence` success",
		"call `VerifyL8DistributionBundle`",
		"generate `verified-pinned-callsites.hl8e` from a fixture",
		"treat L5 images as L8 proof",
		"boot Firecracker or require KVM",
		"commit Node/Pi/npm tarball bytes",
		"billed Azure/OpenAI",
		"Hetzner/Lightsail",
		"merge to `develop`",
	} {
		if !strings.Contains(doc, required) {
			t.Fatalf("L8 D7 cache source locks verification document omits %q", required)
		}
	}
	for _, forbidden := range []string{
		"L8 is complete",
		"L10 is complete",
		"L11 is complete",
		"D7 prepared-Linux acceptance is accepted",
		"HL8E is issued",
		"HL8E issuance is accepted",
		"D7 live is accepted",
	} {
		if strings.Contains(doc, forbidden) {
			t.Fatalf("L8 D7 cache source locks verification document contains forbidden claim %q", forbidden)
		}
	}
}

func TestL8D7CacheSourceLocksDocumentForbidsCompleteClaims(t *testing.T) {
	doc := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8D7CacheSourceLocksDoc))
	normalized := strings.Join(strings.Fields(doc), " ")
	if strings.Contains(normalized, "This slice claims L8 complete") {
		t.Fatal("cache source locks document claims L8 complete")
	}
	if !strings.Contains(normalized, "does not change live D7 stub fatals") {
		t.Fatal("cache source locks document must leave live D7 stub fatals unchanged")
	}
	if !strings.Contains(normalized, "`VerifyL8DistributionBundle` is not called") {
		t.Fatal("cache source locks document must forbid calling VerifyL8DistributionBundle")
	}
}
