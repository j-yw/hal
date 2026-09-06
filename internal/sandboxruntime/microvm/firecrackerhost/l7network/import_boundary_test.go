package l7network_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFirecrackerHostTopologyImportBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(".", entry.Name()), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(path, "github.com/jywlabs/hal/") && !allowedHostTopologyImport(path) {
				t.Fatalf("production file %s imports forbidden cross-lane package %q", entry.Name(), path)
			}
		}
	}
}

func allowedHostTopologyImport(path string) bool {
	return path == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement" ||
		path == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxrules" ||
		path == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/linuxtopology" ||
		path == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy"
}

func TestFirecrackerHostTopologyIsNotWiredIntoDefaultPaths(t *testing.T) {
	parent := ".."
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		if entry.Name() == "l7_runtime_controller.go" || entry.Name() == "l7_live_composition.go" ||
			entry.Name() == "l8_runtime_owner_recovery.go" || entry.Name() == "l8_l7_recovery_session_factory.go" {
			continue
		}
		payload, err := os.ReadFile(filepath.Join(parent, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if entry.Name() == "minimal_l7_config.go" {
			if err := validateMinimalL7ConfigSource(payload); err != nil {
				t.Fatalf("descriptor-only mapper %s: %v", entry.Name(), err)
			}
			continue
		}
		if strings.Contains(string(payload), "firecrackerhost/l7network") || strings.Contains(string(payload), "l7network.New(") {
			t.Fatalf("default Firecracker host path %s wires explicit L7 topology", entry.Name())
		}
	}
}

// This is a closed check of the one pure mapper, not a blanket filename
// exemption. Any additional dependency or callable surface needs review.
func validateMinimalL7ConfigSource(payload []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "minimal_l7_config.go", payload, 0)
	if err != nil {
		return err
	}
	const prefix = "github.com/jywlabs/hal/internal/sandboxruntime/microvm/"
	allowedPackages := map[string]string{
		"bytes":                              "NewReader",
		"encoding/json":                      "NewDecoder RawMessage",
		"io":                                 "EOF",
		"strings":                            "Join Fields Cut ToLower Trim HasPrefix",
		prefix + "firecrackerhost/l7network": "LaunchDescriptor",
		prefix + "guestagent/minimalcontrol": "MaximumBootCommandLineBytes",
		prefix + "guestnetwork":              "ParseBootCommandLine",
	}
	imports := make(map[string]string)
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || allowedPackages[path] == "" {
			return fmt.Errorf("unapproved mapper import %s", spec.Path.Value)
		}
		name := filepath.Base(path)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if name == "." || name == "_" || imports[name] != "" {
			return fmt.Errorf("ambiguous mapper import %q", name)
		}
		imports[name] = path
	}
	contains := func(set, name string) bool {
		return strings.Contains(" "+set+" ", " "+name+" ")
	}
	// Include field access and read-only descriptor/guest value getters, not
	// session, namespace, factory, process, or network lifecycle operations.
	const fields = "descriptor runtimeGeneration topologyGeneration NetworkInterfaces BootSource BootArgs"
	const methods = "ProofGenerations NetworkInterface StaticNetwork Decode DisallowUnknownFields InterfaceName IPv4Address IPv4Gateway IPv6Address IPv6Gateway ProxyURL"
	const functions = "len make new invalid minimalL7Mapping minimalL7BootFields minimalL7BootFragment invalidMinimalL7Config newStrictJailerCoordinatorError"
	typeReferences := make(map[ast.Expr]bool)
	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.Field:
			typeReferences[node.Type] = true
		case *ast.TypeSpec:
			typeReferences[node.Type] = true
		}
		return true
	})
	ast.Inspect(file, func(node ast.Node) bool {
		if err != nil {
			return false
		}
		switch node := node.(type) {
		case *ast.SelectorExpr:
			if ident, ok := node.X.(*ast.Ident); ok && imports[ident.Name] != "" {
				if ident.Obj != nil || !contains(allowedPackages[imports[ident.Name]], node.Sel.Name) {
					err = fmt.Errorf("unapproved package selector %s.%s", ident.Name, node.Sel.Name)
				} else if imports[ident.Name] == prefix+"firecrackerhost/l7network" && !typeReferences[node] {
					err = fmt.Errorf("L7 package selector is not a declared descriptor type")
				}
			} else if !contains(fields+" "+methods, node.Sel.Name) {
				err = fmt.Errorf("unapproved mapper selector %s", node.Sel.Name)
			}
		case *ast.CallExpr:
			switch target := node.Fun.(type) {
			case *ast.Ident:
				if !contains(functions, target.Name) {
					err = fmt.Errorf("unapproved mapper function %s", target.Name)
				} else if target.Obj != nil {
					switch declaration := target.Obj.Decl.(type) {
					case *ast.FuncDecl:
						// Calls to the declared pure helpers are checked recursively.
					case *ast.AssignStmt:
						if target.Name != "invalid" || len(declaration.Rhs) != 1 {
							err = fmt.Errorf("mapper callable alias needs review")
						} else if _, ok := declaration.Rhs[0].(*ast.FuncLit); !ok {
							err = fmt.Errorf("mapper callable alias needs review")
						}
					default:
						err = fmt.Errorf("mapper callable binding needs review")
					}
				}
			case *ast.SelectorExpr:
				if ident, ok := target.X.(*ast.Ident); ok && imports[ident.Name] != "" {
					if imports[ident.Name] == prefix+"firecrackerhost/l7network" {
						err = fmt.Errorf("mapper calls L7 package selector %s", target.Sel.Name)
					}
				} else if !contains(methods, target.Sel.Name) {
					err = fmt.Errorf("unapproved mapper method %s", target.Sel.Name)
				}
			default:
				err = fmt.Errorf("indirect mapper call needs review")
			}
		case *ast.GoStmt, *ast.DeferStmt:
			err = fmt.Errorf("asynchronous or deferred mapper operation needs review")
		}
		return err == nil
	})
	return err
}

func TestFirecrackerHostTopologyProductionSourceForbidsGlobalNetworkMutation(t *testing.T) {
	for _, name := range []string{"tap.go", "tap_command_linux.go"} {
		payload, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		lower := strings.ToLower(string(payload))
		for _, forbidden := range []string{"iptables", "masquerade", " snat", " dnat", "sudo", "0.0.0.0", "listen("} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("production file %s contains forbidden marker %q", name, forbidden)
			}
		}
	}
}
