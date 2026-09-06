package localresolver

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

func TestL8MinimalMeasuredContractsRejectMissingOrInconsistentFacts(t *testing.T) {
	for _, scenario := range []string{"profile", "protocol", "parent", "provenance", "kernel", "rootfs", "sources", "source_version", "dependency_digest", "source_revision", "missing_executable", "process_role", "process_type", "process_digest", "owner", "owner_absent", "group_absent", "mode", "inventory_missing", "inventory_excess", "findings_absent", "findings_present", "workload_uid", "workspace_mode"} {
		t.Run(scenario, func(t *testing.T) {
			request := minimalDistributionFixture(t)
			m, p, s, i := minimalReadDocuments(t, request.RootDir)
			if err := assetbuild.ValidateL8MinimalDocuments(m, p, s, i); err != nil {
				t.Fatalf("fixture invalid: %v", err)
			}
			switch scenario {
			case "profile":
				m.ImageProfile = assetbuild.ImageProfileL8ProductionCredentials
			case "protocol":
				m.GuestAgent.Protocol = "guest-agent-v2"
			case "parent":
				m.MinimalProfile.ParentL7.RootfsSHA256 = strings.Repeat("a", 64)
			case "provenance":
				p.MinimalProfile.GuestInitSHA256 = strings.Repeat("a", 64)
			case "kernel":
				m.Assets[0].SHA256 = strings.Repeat("a", 64)
			case "rootfs":
				i.RootfsSHA256 = strings.Repeat("a", 64)
			case "sources":
				s.Sources = nil
			case "source_version":
				s.Sources[0].Version = "untrusted"
			case "dependency_digest":
				s.Runtime.PiDependencyTreeSHA256 = strings.Repeat("a", 64)
			case "source_revision":
				s.SourceRevision = strings.Repeat("a", 40)
			case "missing_executable":
				i.Executables = i.Executables[1:]
			case "process_role":
				i.Executables[0].Role = "credential-helper"
			case "process_type":
				i.Executables[0].Type = "symlink"
			case "process_digest":
				i.Executables[0].SHA256 = strings.Repeat("a", 64)
			case "owner":
				*i.Executables[0].UID = 1000
			case "owner_absent":
				i.Executables[0].UID = nil
			case "group_absent":
				i.Executables[0].GID = nil
			case "mode":
				i.Executables[0].Mode = 04755
			case "inventory_missing":
				i.Inventory.Inodes = 0
			case "inventory_excess":
				i.Inventory.LogicalBytes = 1 << 40
			case "findings_absent":
				i.Inventory.Findings = nil
			case "findings_present":
				i.Inventory.Findings = []string{"credential_material"}
			case "workload_uid":
				i.WorkloadUID = 0
			case "workspace_mode":
				i.WorkspaceMode = 0777
			}
			if err := assetbuild.ValidateL8MinimalDocuments(m, p, s, i); err == nil {
				t.Fatal("invalid measured facts accepted")
			}
		})
	}
}

func TestL8MinimalSelectionCopiesMetadataAndSerializesClose(t *testing.T) {
	request := minimalDistributionFixture(t)
	verified, err := VerifyL8MinimalDistributionBundle(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = verified.Close() })
	descriptor, err := SelectL8MinimalDistribution(verified)
	if err != nil {
		t.Fatal(err)
	}
	descriptor.ID = "forged"
	descriptor.Assets[0].Source.HostPath.Path = "/not-owned"
	request.ParentL7.Manifest.GuestAgent.Features[0] = "forged"
	selected, err := SelectL8MinimalDistribution(verified)
	if err != nil || selected.ID != "l8-minimal-credentials-image" || selected.Assets[0].Source.HostPath.Path == "/not-owned" {
		t.Fatalf("caller mutated retained identity: %#v, %v", selected, err)
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 4 {
				_, _ = SelectL8MinimalDistribution(verified)
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := verified.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	}()
	workers.Wait()
	if _, err := SelectL8MinimalDistribution(verified); err == nil {
		t.Fatal("closed selection accepted")
	}
}

func TestL8MinimalPathHasNoLegacyPolicyAuthorityDependency(t *testing.T) {
	for _, filename := range []string{"l8_minimal_distribution.go", "../build/l8_minimal.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			if strings.Contains(imported.Path.Value, "syscallpolicy") {
				t.Fatalf("minimal path imports legacy policy authority: %s", filename)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if identifier, ok := node.(*ast.Ident); ok {
				for _, forbidden := range []string{"VerifyL8DistributionBundle", "PinnedCallsiteEvidence", "EmbeddedVerifiedPolicyArtifact", "ImportPinnedCallsiteEvidence", "sealVerifiedL8Profile", "newVerifiedL7Profile"} {
					if identifier.Name == forbidden {
						t.Errorf("%s references legacy authority %s", filename, forbidden)
					}
				}
			}
			return true
		})
	}
}

func TestL8MinimalEntrySetRejectsOversizedDirectoryWithBoundedEnumeration(t *testing.T) {
	request := minimalDistributionFixture(t)
	for index := range 64 {
		writeL5DistributionFile(t, request.RootDir, "extra-"+strconv.Itoa(index), []byte("not a bundle member"))
	}
	root, _, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := verifyMinimalEntrySet(root); err == nil {
		t.Fatal("oversized distribution inventory accepted")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "l8_minimal_distribution.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "ReadDir" {
			return true
		}
		if len(call.Args) != 1 {
			t.Fatal("unexpected directory enumeration")
		}
		bound, ok := call.Args[0].(*ast.BinaryExpr)
		if !ok || bound.Op != token.ADD {
			t.Fatal("directory enumeration lost exact-set plus one bound")
		}
		return true
	})
}

func TestL8MinimalInventoryUsesTraversalCountsNotAllocatedCapacity(t *testing.T) {
	request := minimalDistributionFixture(t)
	m, p, s, i := minimalReadDocuments(t, request.RootDir)
	i.Inventory.DirectoryRecords = 4
	if err := assetbuild.ValidateL8MinimalDocuments(m, p, s, i); err != nil {
		t.Fatalf("independently bounded traversal totals rejected: %v", err)
	}
}

func minimalReadDocuments(t *testing.T, root string) (m assetbuild.L8MinimalDistributionManifest, p assetbuild.L8MinimalProvenance, s assetbuild.L8MinimalSourceLock, i assetbuild.L8MinimalFinalInspection) {
	t.Helper()
	for _, document := range []struct {
		name        string
		destination any
	}{{distributionManifestName, &m}, {distributionProvenanceName, &p}, {l8SourceLockName, &s}, {l8FinalInspectionName, &i}} {
		if err := json.Unmarshal(l5ReadDistributionFile(t, filepath.Join(root, document.name)), document.destination); err != nil {
			t.Fatal(err)
		}
	}
	return
}
