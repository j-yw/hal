package localresolver

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8MinimalMetadataCallsitesUseAuthenticatedSnapshots(t *testing.T) {
	source, err := os.ReadFile("l8_minimal_distribution.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "l8_minimal_distribution.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately narrow wiring guard: behavioral helper tests alone would
	// still pass if the production verifier stopped calling the safe helper.
	required := map[string][]string{
		"VerifyL8MinimalDistributionBundle": {
			"{distributionManifestName, &manifest}", "{distributionProvenanceName, &provenance}",
			"{l8SourceLockName, &sources}", "{l8FinalInspectionName, &inspection}",
			"decodeMinimalMetadata(state.files[document.name], document.destination)",
			"verifyMinimalChecksums(state.files)",
		},
		"decodeMinimalMetadata": {
			"snapshotMinimalMetadata(pinned)", "json.NewDecoder(bytes.NewReader(snapshot))",
		},
		"verifyMinimalChecksums": {
			"snapshotMinimalMetadata(files[distributionChecksumsName])", "bufio.NewScanner(bytes.NewReader(snapshot))",
		},
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || required[function.Name.Name] == nil {
			continue
		}
		body := string(source[function.Body.Pos()-1 : function.Body.End()-1])
		for _, fragment := range required[function.Name.Name] {
			if !strings.Contains(body, fragment) {
				t.Errorf("%s lost authenticated metadata wiring %q", function.Name.Name, fragment)
			}
		}
		delete(required, function.Name.Name)
	}
	if len(required) != 0 {
		t.Fatalf("missing metadata verification functions: %v", required)
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if identifier, ok := node.(*ast.Ident); ok && identifier.Name == "decodeL8RetainedParentJSON" {
			t.Error("minimal metadata path references mutable legacy JSON decoder")
		}
		return true
	})
}

func TestL8MinimalMetadataRejectsMutationBetweenPinAndDecode(t *testing.T) {
	rootDir := t.TempDir()
	const original = `{"value":"pinned"}`
	const replacement = `{"value":"forged"}`
	writeL5DistributionFile(t, rootDir, distributionProvenanceName, []byte(original))
	root, _, err := openRequestedDistributionRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pinned, err := pinMinimalFile(root, distributionProvenanceName)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.file.Close()
	writeL5DistributionFile(t, rootDir, distributionProvenanceName, []byte(replacement))
	var decoded struct {
		Value string `json:"value"`
	}
	decodeErr := decodeMinimalMetadata(pinned, &decoded)
	// Restoring the original bytes defeats a later pathname/currentness check;
	// decoding itself must be bound to the digest established at pinning.
	writeL5DistributionFile(t, rootDir, distributionProvenanceName, []byte(original))
	if err := confirmMinimalFiles(root, map[string]l8PinnedAsset{distributionProvenanceName: pinned}); err != nil {
		t.Fatalf("restored pin should remain current: %v", err)
	}
	if !errors.Is(decodeErr, ErrAssetLockMismatch) || decoded.Value != "" {
		t.Fatalf("decoded mutable bytes = %q, error %v; want digest mismatch before decode", decoded.Value, decodeErr)
	}
}

func TestL8MinimalMetadataStrictDecodeAndPinBounds(t *testing.T) {
	for _, scenario := range []string{"unknown_field", "trailing_json", "trailing_garbage", "wrong_digest", "wrong_size", "oversized_pin", "empty_pin"} {
		t.Run(scenario, func(t *testing.T) {
			payload := []byte(`{"value":"pinned"}`)
			switch scenario {
			case "unknown_field":
				payload = []byte(`{"value":"pinned","extra":true}`)
			case "trailing_json":
				payload = []byte(`{"value":"pinned"} {}`)
			case "trailing_garbage":
				payload = []byte(`{"value":"pinned"} broken`)
			}
			rootDir := t.TempDir()
			writeL5DistributionFile(t, rootDir, distributionProvenanceName, payload)
			root, _, err := openRequestedDistributionRoot(rootDir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			pinned, err := pinMinimalFile(root, distributionProvenanceName)
			if err != nil {
				t.Fatal(err)
			}
			defer pinned.file.Close()
			switch scenario {
			case "wrong_digest":
				pinned.digest[0] ^= 1
			case "wrong_size":
				pinned.size--
			case "oversized_pin":
				pinned.size = l8MaxMetadataBytes + 1
			case "empty_pin":
				pinned.size = 0
			}
			var decoded struct {
				Value string `json:"value"`
			}
			if err := decodeMinimalMetadata(pinned, &decoded); err == nil {
				t.Fatal("unbound or non-strict metadata accepted")
			}
		})
	}
}

func TestL8MinimalMetadataDecodeUsesImmutableBytes(t *testing.T) {
	rootDir := t.TempDir()
	const original = `{"value":"pinned"}`
	writeL5DistributionFile(t, rootDir, distributionProvenanceName, []byte(original))
	root, _, err := openRequestedDistributionRoot(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pinned, err := pinMinimalFile(root, distributionProvenanceName)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.file.Close()
	decoded := minimalMutatingJSONDestination{path: filepath.Join(rootDir, distributionProvenanceName)}
	if err := decodeMinimalMetadata(pinned, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.value != "pinned" {
		t.Fatalf("decoded bytes changed after snapshot: %q", decoded.value)
	}
}

type minimalMutatingJSONDestination struct {
	path  string
	value string
}

func (destination *minimalMutatingJSONDestination) UnmarshalJSON(data []byte) error {
	if err := os.WriteFile(destination.path, []byte(`{"value":"forged"}`), 0600); err != nil {
		return err
	}
	var parsed struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	destination.value = parsed.Value
	return nil
}

func TestL8MinimalChecksumsRejectPinMismatch(t *testing.T) {
	request := minimalDistributionFixture(t)
	root, _, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	files := make(map[string]l8PinnedAsset)
	for _, name := range l8RequiredDistributionOutputs {
		pinned, err := pinMinimalFile(root, name)
		if err != nil {
			t.Fatal(err)
		}
		defer pinned.file.Close()
		files[name] = pinned
	}
	checksum := files[distributionChecksumsName]
	checksum.digest[0] ^= 1
	files[distributionChecksumsName] = checksum
	if err := verifyMinimalChecksums(files); !errors.Is(err, ErrAssetLockMismatch) {
		t.Fatalf("checksum scanner ignored its pin: %v", err)
	}
}
