package build

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestL8BuildContractsValidateAndPreserveLegacyJSON(t *testing.T) {
	manifest, provenance, sourceLock, inspection := validL8BuildContracts(t)

	if err := ValidateL8DistributionManifest(manifest); err != nil {
		t.Fatalf("ValidateL8DistributionManifest() error = %v", err)
	}
	if err := ValidateL8Provenance(provenance); err != nil {
		t.Fatalf("ValidateL8Provenance() error = %v", err)
	}
	if err := ValidateL8ProvenanceAgainstManifest(provenance, manifest); err != nil {
		t.Fatalf("ValidateL8ProvenanceAgainstManifest() error = %v", err)
	}
	if err := ValidateL8SourceLock(sourceLock); err != nil {
		t.Fatalf("ValidateL8SourceLock() error = %v", err)
	}
	if err := ValidateL8FinalInspection(inspection); err != nil {
		t.Fatalf("ValidateL8FinalInspection() error = %v", err)
	}

	legacy := validL5DistributionManifest()
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "l8Profile") {
		t.Fatalf("legacy manifest JSON gained l8Profile: %s", encoded)
	}
}

func TestL8BuildContractsFailClosedWithoutMutation(t *testing.T) {
	manifest, provenance, sourceLock, inspection := validL8BuildContracts(t)
	wantManifest := cloneL8Contract(t, manifest)
	wantProvenance := cloneL8Contract(t, provenance)
	wantSourceLock := cloneL8Contract(t, sourceLock)
	wantInspection := cloneL8Contract(t, inspection)

	mutations := []struct {
		name string
		run  func() error
		code L8ValidationCode
	}{
		{"manifest protocol", func() error {
			value := manifest
			value.GuestAgent.Protocol = "guest-agent-v1"
			return ValidateL8DistributionManifest(value)
		}, L8ValidationCodeVersionInvalid},
		{"manifest missing profile", func() error { value := manifest; value.L8Profile = nil; return ValidateL8DistributionManifest(value) }, L8ValidationCodeCountInvalid},
		{"provenance profile drift", func() error {
			value := cloneL8Contract(t, provenance)
			value.L8Profile.Runtime.NodeVersion = "22.21.0"
			return ValidateL8Provenance(value)
		}, L8ValidationCodeVersionInvalid},
		{"cross document drift", func() error {
			value := cloneL8Contract(t, provenance)
			value.L8Profile.SourceLockSHA256 = strings.Repeat("e", 64)
			return ValidateL8ProvenanceAgainstManifest(value, manifest)
		}, L8ValidationCodeCorrelationMismatch},
		{"source lock nil", func() error { value := sourceLock; value.Sources = nil; return ValidateL8SourceLock(value) }, L8ValidationCodeCountInvalid},
		{"source order", func() error {
			value := sourceLock
			value.Sources = append([]L8LockedSource(nil), sourceLock.Sources...)
			value.Sources[2], value.Sources[3] = value.Sources[3], value.Sources[2]
			return ValidateL8SourceLock(value)
		}, L8ValidationCodeOrderInvalid},
		{"source credential filename", func() error {
			value := sourceLock
			value.Sources = append([]L8LockedSource(nil), sourceLock.Sources...)
			value.Sources[3].Filename = "AUTHORIZATION.tgz"
			return ValidateL8SourceLock(value)
		}, L8ValidationCodeFieldInvalid},
		{"source dependency digest", func() error {
			value := sourceLock
			value.Runtime.PiDependencyTreeSHA256 = strings.Repeat("f", 64)
			return ValidateL8SourceLock(value)
		}, L8ValidationCodeCorrelationMismatch},
		{"inspection nil", func() error { value := inspection; value.Checks = nil; return ValidateL8FinalInspection(value) }, L8ValidationCodeCountInvalid},
		{"inspection order", func() error {
			value := inspection
			value.Checks = append([]L8InspectionCheck(nil), inspection.Checks...)
			value.Checks[0], value.Checks[1] = value.Checks[1], value.Checks[0]
			return ValidateL8FinalInspection(value)
		}, L8ValidationCodeOrderInvalid},
	}

	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			err := mutation.run()
			var validation *L8ValidationError
			if !errors.As(err, &validation) {
				t.Fatalf("error = %v, want *L8ValidationError", err)
			}
			if validation.Code != mutation.code {
				t.Fatalf("code = %q, want %q", validation.Code, mutation.code)
			}
		})
	}

	if !reflect.DeepEqual(manifest, wantManifest) || !reflect.DeepEqual(provenance, wantProvenance) ||
		!reflect.DeepEqual(sourceLock, wantSourceLock) || !reflect.DeepEqual(inspection, wantInspection) {
		t.Fatal("validation mutated caller-owned input")
	}
}

func validL8BuildContracts(t *testing.T) (DistributionManifest, Provenance, L8SourceLock, L8FinalInspection) {
	t.Helper()
	digest := func(char string) string { return strings.Repeat(char, 64) }
	parent := L8ParentL7Evidence{
		ImageProfile: ImageProfileL7Network, ManifestSHA256: digest("1"), ProvenanceSHA256: digest("2"),
		ChecksumsSHA256: digest("3"), KernelSizeBytes: 101, KernelSHA256: digest("4"),
		RootfsSizeBytes: 202, RootfsSHA256: digest("5"),
	}
	parent.EvidenceSHA256 = l8ParentEvidenceSHA256(parent)
	sources := []L8LockedSource{
		{Kind: "node_source", Name: "node", Version: "22.22.0", Filename: "node-v22.22.0.tar.gz", SizeBytes: 11, SHA256: digest("6")},
		{Kind: "pi_package", Name: "@earendil-works/pi-coding-agent", Version: "0.82.1", Filename: "pi-coding-agent-0.82.1.tgz", SizeBytes: 12, SHA256: digest("7")},
		{Kind: "pi_shrinkwrap", Name: "pi-shrinkwrap", Version: "0.82.1", Filename: "npm-shrinkwrap.json", SizeBytes: 13, SHA256: digest("8")},
		{Kind: "npm_archive", Name: "zod", Version: "3.25.1", Filename: "zod-3.25.1.tgz", SizeBytes: 14, SHA256: digest("9")},
	}
	runtime := L8RuntimeFacts{
		NodeVersion: "22.22.0", NodeSHA256: digest("a"), PiPackage: "@earendil-works/pi-coding-agent",
		PiVersion: "0.82.1", PiLauncherSHA256: digest("b"), PiDependencyTreeSHA256: l8PiDependencyTreeSHA256(sources),
	}
	composition := L8ProcessCompositionFacts{
		CatalogVersion:   L8ProcessCompositionCatalogV1,
		GuestAgentSHA256: digest("1"), GuestInitSHA256: digest("2"), CredentialHelperSHA256: digest("3"),
		MountMonitorSHA256: digest("4"), WorkloadShimSHA256: digest("5"), RoleBootstrapSHA256: digest("6"),
		HelperDescriptorSHA256: digest("7"), ClientDescriptorSHA256: digest("8"), CompositionSHA256: digest("9"),
		WorkloadSnapshotSHA256: digest("a"), RuntimeProfileSHA256: digest("b"), PolicyArtifactSHA256: digest("c"),
		PolicySourceLockSHA256: digest("d"), PolicyBinaryBindingSetSHA256: digest("e"), PinnedCallsiteEvidenceSHA256: digest("f"),
	}
	profile := L8ProfileFacts{
		ContractVersion: L8ProfileContractVersionV1, ParentL7: parent, Runtime: runtime,
		ProcessComposition: composition, SourceLockSHA256: digest("c"), FinalInspectionSHA256: digest("d"),
	}
	manifest := validL5DistributionManifest()
	manifest.ImageProfile = ImageProfileL8ProductionCredentials
	manifest.GuestAgent = GuestAgent{Protocol: L8GuestAgentProtocolV2, Features: append([]string(nil), requiredL8Features...)}
	manifest.GuestNetwork = &GuestNetwork{Mode: GuestNetworkModeStaticProxy, Features: append([]string(nil), requiredL7NetworkFeatures...)}
	manifest.L8Profile = &profile
	provenance := validL5Provenance(manifest)
	provenance.ImageProfile = manifest.ImageProfile
	provenance.GuestAgent = manifest.GuestAgent
	provenance.GuestNetwork = &GuestNetwork{Mode: manifest.GuestNetwork.Mode, Features: append([]string(nil), manifest.GuestNetwork.Features...)}
	copyProfile := profile
	provenance.L8Profile = &copyProfile
	sourceLock := L8SourceLock{
		SchemaVersion: L8SourceLockSchemaVersionV1, CatalogVersion: L8SourceLockCatalogVersionV1,
		ImageProfile: ImageProfileL8ProductionCredentials, ParentL7: parent, Runtime: runtime, Sources: sources,
	}
	checks := make([]L8InspectionCheck, len(requiredL8InspectionChecks))
	for index, id := range requiredL8InspectionChecks {
		checks[index] = L8InspectionCheck{ID: id, Status: "pass", EvidenceSHA256: fmt.Sprintf("%064x", index+1)}
	}
	inspection := L8FinalInspection{
		SchemaVersion: L8FinalInspectionSchemaVersionV1, CatalogVersion: L8FinalInspectionCatalogVersionV1,
		ImageProfile: ImageProfileL8ProductionCredentials, RootfsSHA256: manifest.Assets[1].SHA256,
		SourceLockSHA256: profile.SourceLockSHA256, ParentL7: parent, Runtime: runtime,
		ProcessComposition: composition, Checks: checks,
	}
	return manifest, provenance, sourceLock, inspection
}

func cloneL8Contract[T any](t *testing.T, value T) T {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result T
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
