package l7network_test

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
)

// This is a closed check of a few composition entries, not a call graph or an
// exemption for arbitrary code in these files. In particular, old exempt L7
// files are still checked for newly introduced callers of the selected entry.
func validateMinimalPreexecSourceBoundary(sources map[string][]byte) error {
	const host = "minimal_preexec_host_linux.go"
	const assembly = "minimal_preexec_assembler_linux.go"
	entries := map[string]string{
		"newMinimalPreexecHost": host, "newMinimalPreexecHostForUID": host,
		"prepareMinimalInputs": assembly, "prepareMinimalInputsWithOps": assembly,
		"newMinimalPreexecNetwork": assembly,
	}
	callers := map[string]string{
		"newMinimalPreexecHostForUID": "newMinimalPreexecHost",
		"prepareMinimalInputsWithOps": "prepareMinimalInputs",
		"newMinimalPreexecNetwork":    "prepareMinimalInputs",
	}
	// These short authority-bearing bodies are parsed, not matched as comments
	// or formatting. They keep root rejection, fixed real ops and incapable proof
	// returns intact; the rest of the assembler is not frozen token-by-token.
	bodies := map[string]string{
		"newMinimalPreexecHost": `{
			if os.Geteuid() != 0 { return nil, sandboxruntime.ErrMinimalLaunchUnavailable }
			return newMinimalPreexecHostForUID(ctx, provider, input, 0)
		}`,
		"prepareMinimalInputs": `{
			if host == nil || host.uid != 0 || os.Geteuid() != 0 { return sandboxruntime.ErrMinimalLaunchUnavailable }
			return owner.prepareMinimalInputsWithOps(host, minimalPreexecOps{
				network: newMinimalPreexecNetwork, seed: newMinimalControllerSeed,
				entropy: minimalControlControllerEntropy{}.Read, duplicate: duplicateJailerRecoveryFile, seal: sealJailerRecoveryBytes,
			})
		}`,
		"VerifyRunningGuestRawPacketIsolation": `{ return l7network.RunningGuestRawPacketIsolationProof{}, sandboxruntime.ErrMinimalLaunchUnavailable }`,
		"VerifyVMTermination":                  `{ return l7network.VMTerminationProof{}, sandboxruntime.ErrMinimalLaunchUnavailable }`,
	}
	found := make(map[string]bool)
	for name, source := range sources {
		file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
		if err != nil {
			return fmt.Errorf("selected preexec caller source %s: %w", name, err)
		}
		selected := name == host || name == assembly
		imports := make(map[string]string)
		for _, spec := range file.Imports {
			path, _ := strconv.Unquote(spec.Path.Value)
			alias := filepath.Base(path)
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			if selected && (alias == "." || alias == "_" || imports[alias] != "") {
				return fmt.Errorf("selected preexec ambiguous import in %s", name)
			}
			imports[alias] = path
		}
		for _, decl := range file.Decls {
			fn, isFunction := decl.(*ast.FuncDecl)
			current := ""
			var body ast.Node = decl
			if isFunction {
				current, body = fn.Name.Name, fn.Body
				if fn.Body == nil {
					if selected || entries[current] != "" {
						return fmt.Errorf("selected preexec entry has no checked body: %s", current)
					}
					continue
				}
				if wantFile := entries[current]; wantFile != "" {
					if name != wantFile || found[current] {
						return fmt.Errorf("selected preexec entry moved or duplicated: %s", current)
					}
					found[current] = true
				}
				if selected {
					if current == "init" || ast.IsExported(current) && bodies[current] == "" {
						return fmt.Errorf("selected preexec new public/init entry: %s", current)
					}
					if expected := bodies[current]; expected != "" {
						if !sameMinimalPreexecBody(fn.Body, expected) {
							return fmt.Errorf("selected preexec root/proof entry changed: %s", current)
						}
						found[current] = true
					}
				}
			}
			if selected && (current == "validMinimalPreexecHostInput" || current == "newMinimalPreexecNetwork") {
				if err := validateMinimalPreexecInertConstructor(fn, imports); err != nil {
					return err
				}
			}
			directCalls := make(map[ast.Expr]bool)
			if selected {
				ast.Inspect(body, func(node ast.Node) bool {
					if call, ok := node.(*ast.CallExpr); ok {
						directCalls[call.Fun] = true
					}
					return true
				})
			}
			ast.Inspect(body, func(node ast.Node) bool {
				if err != nil {
					return false
				}
				if ident, ok := node.(*ast.Ident); ok && entries[ident.Name] != "" {
					if current == "" || callers[ident.Name] != current || name != entries[ident.Name] {
						err = fmt.Errorf("selected preexec unreviewed caller/escape: %s in %s", ident.Name, name)
					}
				}
				if !selected {
					return true
				}
				if selector, ok := node.(*ast.SelectorExpr); ok {
					if ident, ok := selector.X.(*ast.Ident); ok && strings.HasSuffix(imports[ident.Name], "/firecrackerhost/l7network") && strings.HasPrefix(selector.Sel.Name, "New") {
						if !directCalls[selector] || current != "newMinimalPreexecNetwork" && !(current == "validMinimalPreexecHostInput" && selector.Sel.Name == "NewLinuxTAP") {
							err = fmt.Errorf("selected preexec unreviewed L7 constructor: %s", current)
						}
					}
				}
				// A borrowed Command field is data, not a Command invocation.
				// No direct proxy serving, tool/process activation or guest-ready
				// transition belongs to these pre-exec construction files.
				if call, ok := node.(*ast.CallExpr); ok {
					if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
						switch selector.Sel.Name {
						case "StartProxyListener", "Start", "Run", "Listen", "ListenPacket", "Dial", "DialContext", "StartProcess", "Command", "CommandContext", "InspectAfterGuestReady", "CleanupAfterVMQuiesced":
							err = fmt.Errorf("selected preexec direct activation: %s", selector.Sel.Name)
						}
					}
				}
				return err == nil
			})
			if err != nil {
				return err
			}
		}
	}
	for entry := range entries {
		if !found[entry] {
			return fmt.Errorf("selected preexec private entry missing: %s", entry)
		}
	}
	for entry := range bodies {
		if !found[entry] {
			return fmt.Errorf("selected preexec root/proof entry missing: %s", entry)
		}
	}
	return nil
}

func sameMinimalPreexecBody(actual *ast.BlockStmt, expected string) bool {
	file, err := parser.ParseFile(token.NewFileSet(), "expected.go", "package check; func check() "+expected, 0)
	if err != nil || actual == nil {
		return false
	}
	var a, b bytes.Buffer
	return format.Node(&a, token.NewFileSet(), actual) == nil &&
		format.Node(&b, token.NewFileSet(), file.Decls[0].(*ast.FuncDecl).Body) == nil && bytes.Equal(a.Bytes(), b.Bytes())
}

// Only these two small constructors are call-closed. This is not an allowlist
// for every identifier, field, method or syscall in the 1,000-line assembler.
func validateMinimalPreexecInertConstructor(fn *ast.FuncDecl, imports map[string]string) error {
	var err error
	proofs := 0
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if err != nil {
			return false
		}
		switch node.(type) {
		case *ast.GoStmt, *ast.DeferStmt:
			err = fmt.Errorf("selected preexec asynchronous constructor")
		}
		if field, ok := node.(*ast.KeyValueExpr); ok && fn.Name.Name == "newMinimalPreexecNetwork" {
			if key, ok := field.Key.(*ast.Ident); ok && (key.Name == "GuestIsolation" || key.Name == "VMTermination") {
				literal, ok := field.Value.(*ast.CompositeLit)
				if !ok || len(literal.Elts) != 0 {
					err = fmt.Errorf("selected preexec capable verifier substitution")
				} else if typ, ok := literal.Type.(*ast.Ident); !ok || typ.Name != "minimalPreexecNoGuest" {
					err = fmt.Errorf("selected preexec capable verifier substitution")
				} else {
					proofs++
				}
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return err == nil
		}
		allowed := false
		switch target := call.Fun.(type) {
		case *ast.Ident:
			if fn.Name.Name == "validMinimalPreexecHostInput" {
				switch target.Name {
				case "filepathIsCleanAbsolute", "cleanupFilesystemRoot", "validJailerStagingDigest", "interfaceValueIsNil", "validMinimalPreexecPolicy", "int64", "uint", "string":
					allowed = target.Obj == nil || target.Obj.Kind == ast.Fun
				}
			}
		case *ast.SelectorExpr:
			if ident, ok := target.X.(*ast.Ident); ok && ident.Obj == nil {
				path := imports[ident.Name]
				if fn.Name.Name == "validMinimalPreexecHostInput" {
					allowed = path == "path/filepath" && target.Sel.Name == "Rel" || path == "strings" && (target.Sel.Name == "TrimSpace" || target.Sel.Name == "ContainsAny" || target.Sel.Name == "HasPrefix")
				}
				const prefix = "github.com/jywlabs/hal/internal/sandboxruntime/"
				if path == prefix+"networkenforcement/policyproxy" && target.Sel.Name == "New" || path == prefix+"microvm/firecrackerhost/l7network" && target.Sel.Name == "NewLinuxTAP" {
					allowed = true
				}
				if fn.Name.Name == "newMinimalPreexecNetwork" {
					switch path {
					case prefix + "networkenforcement":
						allowed = target.Sel.Name == "NewPolicyProxyPolicyInput"
					case prefix + "networkenforcement/linuxtopology":
						allowed = target.Sel.Name == "New"
					case prefix + "networkenforcement/linuxrules":
						allowed = target.Sel.Name == "NewAdapter" || target.Sel.Name == "NewProductionExecutor"
					case prefix + "microvm/firecrackerhost/l7network":
						allowed = target.Sel.Name == "New" || target.Sel.Name == "NewLinuxTAP" || target.Sel.Name == "NewLinuxTopology" || target.Sel.Name == "NewProductionProxy"
					}
				}
			}
		}
		if !allowed {
			var target bytes.Buffer
			_ = format.Node(&target, token.NewFileSet(), call.Fun)
			err = fmt.Errorf("selected preexec non-inert constructor call %s in %s", target.String(), fn.Name.Name)
		}
		return err == nil
	})
	if err == nil && fn.Name.Name == "newMinimalPreexecNetwork" && proofs != 2 {
		err = fmt.Errorf("selected preexec incapable verifiers missing")
	}
	return err
}
