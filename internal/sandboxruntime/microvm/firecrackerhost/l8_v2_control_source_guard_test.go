package firecrackerhost

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestL8D6V2ControlFoundationHasNoCredentialRuntimeOrProofClaims(t *testing.T) {
	files := []string{"l8_v2_control_session.go", "l8_v2_control_connector.go"}
	for _, name := range files {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for _, forbidden := range []string{
			"JobCredentialRuntime", "JobCredentialRuntimePreflight", "JobCredentialSession",
			"NewJobCredentialActiveProof", "NewJobCredentialCleanupProof", "NewJobCredentialRuntimeAbsenceProof",
			"PreflightJobCredentials", "PrepareJobCredentials", "RecoverJobCredentials", "RevokeJobCredentials",
			"ActiveProof", "CleanupProof", "AbsenceProof", "credential_prepare", "credential_renew", "credential_revoke",
		} {
			if strings.Contains(string(source), forbidden) {
				t.Fatalf("%s contains forbidden later-slice claim %q", name, forbidden)
			}
		}
	}
}

func TestL8D6V2ControlFoundationFixedPortAndConnectorOwnership(t *testing.T) {
	source, err := os.ReadFile("l8_v2_control_connector.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"session.ControlPort", "bridge.sessionForTarget(target)", "bridge.SessionActive(",
		"bridge.lifecycle.resolveLiveProcessIdentity", "statVsockSocket", "verifyVsockPeer",
		"CONNECT ", "wire.register(conn)", "wire.unregister(conn)",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("connector omits exact correlation marker %q", required)
		}
	}
	for _, forbidden := range []string{"GuestPort", "guestPort", "Port uint32", "port uint32", "L5GuestAgentPort"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("connector exposes/selects forbidden port marker %q", forbidden)
		}
	}
}

func TestL8D6V2ControlFoundationRemainsDefaultInert(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", "..", "..", ".."))
	set := token.NewFileSet()
	callers := 0
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(set, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch function := call.Fun.(type) {
			case *ast.Ident:
				name = function.Name
			case *ast.SelectorExpr:
				name = function.Sel.Name
			}
			if name == "NewProductionL8V2ControlBridge" {
				callers++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callers != 0 {
		t.Fatalf("production NewProductionL8V2ControlBridge callers = %d, want zero", callers)
	}
}
