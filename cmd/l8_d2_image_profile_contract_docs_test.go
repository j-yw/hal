package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D2ImageProfileContractClosureIsImplementationReady(t *testing.T) {
	seam := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", "sandbox-runtime-v2-l8-guest-extension-seams.md"))
	architecture := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialArchitectureDoc))
	verification := readL8CredentialDeliveryFile(t, filepath.Join("..", "docs", "design", l8CredentialVerificationDoc))
	combined := seam + "\n" + architecture + "\n" + verification

	for _, required := range []string{
		"### L8 D2 image-profile concrete closure",
		`ImageProfileL8ProductionCredentials = "l8-production-credentials-v1"`,
		`L8GuestAgentProtocolV2 = "guest-agent-v2"`,
		`"copy_in", "copy_out", "credential_delivery_v2"`,
		`"exec", "readiness", "ssh_agent_relay_v1"`,
		"generic L5/L7 validator is not called on an L8 value",
		"manifest and provenance GuestAgent values must match exactly",
		"L8SourceLockSchemaVersionV1",
		"L8FinalInspectionSchemaVersionV1",
		"Node 22.22.0",
		"@earendil-works/pi-coding-agent 0.82.1",
		"type L8SourceLock struct",
		"type L8FinalInspection struct",
		"type L8ProcessCompositionFacts struct",
		"NodeSHA256",
		"PiLauncherSHA256",
		"4..4096 entries",
		"at most 4 MiB",
		"exactly these 22 records",
		"l8-production-credentials-image",
		"exactly seven regular files",
		"final-inspection.json",
		"sources.lock.json",
		"parent L7 evidence fingerprint",
		`opaque16("hal/l8/image-profile/parent-l7-evidence/v1")`,
		`opaque16("hal/l8/image-profile/descriptor/v1")`,
		`opaque16("hal/l8/image-profile/evidence/v1")`,
		"evidence substitution",
		"ValidateL8DistributionManifest",
		"ValidateL8ProvenanceAgainstManifest",
		"ValidateL8SourceLock",
		"ValidateL8FinalInspection",
		"type L8ValidationError struct",
		"type L8LaunchMaterialWriter interface",
		"failure leaves writer",
		"ownership with the caller",
		"failed call does not consume the successful single-use latch",
		"success atomically transfers writer ownership to the lease",
		"joins the sanitized",
		"close error with the primary error",
		`opaque16("hal/l8/pi-dependency-tree/v1")`,
		"uint32_be(npmArchiveCount)",
		"case-insensitive",
		"URL/credential-marker algorithm",
		`"authorization", "bearer", "token", "secret"`,
		`"credential", "password"`,
		`"api_key", "apikey"`,
		`"access_key", "private_key"`,
		`"ghp_", "github_pat_"`,
		`"sk-"`,
		"schema_invalid",
		"correlation_mismatch",
		"first error in this exact precedence",
		"L8Profile() (VerifiedL8Profile, bool)",
		"type L8DistributionRequest struct",
		"ParentL7 VerifiedDistribution",
		"VerifyL8DistributionBundle(L8DistributionRequest)",
		"five-file L5/L7\nentry point and cannot issue L8 authority",
		"AcquireL8AssetLease",
		"PrepareLaunch",
		"evidence fingerprint is copied unchanged",
		"VerifiedL8ProfileMatches",
		"VerifiedL8ProfileMatchesLease",
		"same evidence fingerprint",
		"no public constructor or fingerprint accessor",
		"VerifiedL8Profile *localresolver.VerifiedL8Profile `json:\"-\"`",
		"VerifiedL8Assets *localresolver.VerifiedL8AssetLease `json:\"-\"`",
		"L7 and L8 profile/lease fields are mutually exclusive",
		"type L8LiveBootConfigRequest struct",
		"type L8LiveBootConfigOverlay struct",
		"type L8LiveBootConfigProvider interface",
		"ProvideL8LiveBootConfig(context.Context, L8LiveBootConfigRequest)",
		"provider retains ownership of every returned value",
		"confirms current assets before ownership of",
		"L8 lease transfers to Backend",
		"recursively deep-copies",
		"launch descriptor and every nested slice/pointer",
		"snapshots every caller-mutable safe field before validation",
		"does not parse a source lock",
		"host profile never enters the guest",
		"D7 embeds the exact expected workload, runtime, and syscall-policy catalog digests",
		"D2 is schema, pure validation, opaque issuance/matching, guards, and fakes only",
		"D6 consumes only the opaque profile and lease",
		"D7 owns real source-lock contents, building, inspection, reproducibility, and live issuance",
		"L5 and L7 JSON bytes remain unchanged",
		"TestL8D2ImageProfile",
		"./internal/sandboxruntime/microvm/assets/build",
		"./internal/sandboxruntime/microvm/assets/localresolver",
		"./internal/sandboxruntime/microvm/firecracker",
	} {
		if !strings.Contains(combined, required) {
			t.Fatalf("L8 D2 image-profile contract omits normative marker %q", required)
		}
	}

	for _, required := range []string{
		"Profile/lease pair correlation",
		"same sealed evidence fingerprint",
		"L8LiveBootConfigProvider",
		"ownership-transferring live overlay",
		"post-start validation failure stops and reaps",
	} {
		if !strings.Contains(architecture, required) {
			t.Fatalf("L8 architecture omits image-profile ownership marker %q", required)
		}
	}

	for _, required := range []string{
		"cross-bundle profile/lease substitution",
		"provider-error ownership retention",
		"post-return validation failure closes the lease exactly once",
		"post-start revalidation failure forces stop/reap",
	} {
		if !strings.Contains(verification, required) {
			t.Fatalf("L8 verification omits image-profile ownership marker %q", required)
		}
	}
}

func TestL8D2ImageProfileMintAuthorityStaysNarrow(t *testing.T) {
	allowed := []string{
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "build"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecracker"),
		filepath.Join("..", "internal", "sandboxruntime", "microvm", "firecrackerhost"),
	}
	for _, root := range []string{
		".",
		filepath.Join("..", "internal"),
		filepath.Join("..", "tools"),
		filepath.Join("..", "sandbox"),
		filepath.Join("..", "main.go"),
	} {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			clean := filepath.Clean(path)
			for _, approved := range allowed {
				if clean == approved || strings.HasPrefix(clean, approved+string(filepath.Separator)) {
					return nil
				}
			}
			payload, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			text := string(payload)
			for _, marker := range []string{
				"ImageProfileL8ProductionCredentials",
				"VerifiedL8Profile",
				"VerifiedL8AssetLease",
				"l8-production-credentials-v1",
			} {
				if strings.Contains(text, marker) {
					t.Errorf("unapproved production file %s contains L8 image-profile authority marker %q", filepath.ToSlash(path), marker)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", root, err)
		}
	}

	issuerRoot := filepath.Join("..", "internal", "sandboxruntime", "microvm", "assets", "localresolver")
	err := filepath.WalkDir("..", func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		clean := filepath.Clean(path)
		if clean == issuerRoot || strings.HasPrefix(clean, issuerRoot+string(filepath.Separator)) {
			return nil
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(payload), "VerifyL8DistributionBundle(") {
			t.Errorf("unapproved production file %s invokes the sole L8 profile issuer", filepath.ToSlash(path))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan L8 issuer boundary: %v", err)
	}
}
