package credentialprotocol

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestSSHAgentRelayStateImportBoundary(t *testing.T) {
	t.Parallel()

	const filename = "ssh_agent_relay_state.go"
	source, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), filename, source, 0)
	if err != nil {
		t.Fatal(err)
	}
	allowedImports := map[string]bool{"errors": true, "sync": true, "time": true}
	for _, imported := range file.Imports {
		path, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			t.Fatal(unquoteErr)
		}
		if imported.Name != nil || !allowedImports[path] {
			t.Errorf("%s imports %q; only the exact pure state-machine set is allowed", filename, path)
		}
		delete(allowedImports, path)
	}
	for missing := range allowedImports {
		t.Errorf("%s exact import %q is missing", filename, missing)
	}

	forbidden := map[string]bool{
		"Dial": true, "DialContext": true, "Listen": true, "ListenUnix": true,
		"SCM_RIGHTS": true, "Socket": true, "Socketpair": true, "Command": true,
		"CommandContext": true, "Open": true, "OpenFile": true, "Read": true,
		"ReadFile": true, "Write": true, "WriteFile": true, "Now": true,
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.MapType:
			t.Error("SSH-agent relay state declares a map owner")
		case *ast.InterfaceType:
			t.Error("SSH-agent relay state declares an interface")
		case *ast.GoStmt:
			t.Error("SSH-agent relay state starts a goroutine")
		case *ast.TypeSpec:
			if typed.TypeParams != nil && len(typed.TypeParams.List) != 0 {
				t.Errorf("SSH-agent relay state declares generic type %s", typed.Name)
			}
		case *ast.FuncDecl:
			if typed.Type.TypeParams != nil && len(typed.Type.TypeParams.List) != 0 {
				t.Errorf("SSH-agent relay state declares generic function %s", typed.Name)
			}
		case *ast.SelectorExpr:
			if forbidden[typed.Sel.Name] {
				t.Errorf("SSH-agent relay state contains forbidden live identifier %s", typed.Sel.Name)
			}
		case *ast.Ident:
			if forbidden[typed.Name] {
				t.Errorf("SSH-agent relay state contains forbidden live identifier %s", typed.Name)
			}
		}
		return true
	})

	for _, forbiddenText := range []string{"net.Conn", "unix", "vsock", "host agent", "relay pump", "payload", "frame []byte"} {
		if strings.Contains(string(source), forbiddenText) {
			t.Errorf("SSH-agent relay state contains forbidden live/raw surface %q", forbiddenText)
		}
	}
}
