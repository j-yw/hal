package vsock

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
)

// This deliberately checks only the fixed dispatch/bind seam, without creating
// any socket. Actual AF_VSOCK availability is a separate live prerequisite.
func TestFixedLinuxListenerPortsHaveNoPublicPortOverride(t *testing.T) {
	if GuestAgentPort != 1024 || session.ControlPort != 1025 {
		t.Fatal("fixed protocol ports changed")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "listener_linux.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		if ast.IsExported(fn.Name.Name) && fn.Name.Name != "ListenLinux" && fn.Name.Name != "ListenLinuxControl" {
			t.Fatalf("new public listener constructor bypasses fixed port review: %s", fn.Name.Name)
		}
		switch fn.Name.Name {
		case "ListenLinux", "ListenLinuxControl":
			if len(fn.Type.Params.List) != 0 || len(fn.Body.List) != 1 {
				t.Fatal("fixed listener accepts configuration")
			}
			result, ok := fn.Body.List[0].(*ast.ReturnStmt)
			if !ok || len(result.Results) != 1 {
				t.Fatal("fixed listener has unexpected route")
			}
			call, ok := result.Results[0].(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				t.Fatal("fixed listener did not call shared constructor")
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok || name.Name != "listenLinuxPort" {
				t.Fatal("fixed listener bypasses shared implementation")
			}
			if fn.Name.Name == "ListenLinux" {
				port, ok := call.Args[0].(*ast.Ident)
				if !ok || port.Name != "GuestAgentPort" {
					t.Fatal("legacy listener changed port")
				}
			} else {
				port, ok := call.Args[0].(*ast.SelectorExpr)
				if !ok || port.Sel.Name != "ControlPort" {
					t.Fatal("control listener changed port")
				}
				owner, ok := port.X.(*ast.Ident)
				if !ok || owner.Name != "session" {
					t.Fatal("control port is not the session contract")
				}
			}
			seen[fn.Name.Name] = true
		case "listenLinuxPort":
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				typ, ok := literal.Type.(*ast.SelectorExpr)
				if !ok || typ.Sel.Name != "SockaddrVM" {
					return true
				}
				for _, element := range literal.Elts {
					field, ok := element.(*ast.KeyValueExpr)
					if !ok {
						continue
					}
					key, ok := field.Key.(*ast.Ident)
					if !ok || key.Name != "Port" {
						continue
					}
					value, ok := field.Value.(*ast.Ident)
					if !ok || value.Name != "port" {
						t.Fatal("shared bind ignores selected fixed port")
					}
					seen["bind"] = true
				}
				return true
			})
		}
	}
	if len(seen) != 3 {
		t.Fatal("missing fixed listener or bind route")
	}
}
