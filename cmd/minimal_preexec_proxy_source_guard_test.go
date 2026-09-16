package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
)

// This check owns only direct L6 imports. The paired L7 guard checks private
// entry/caller closure, root checks and inert constructor bodies before either
// selected file is recognized as explicit composition rather than a default.
func validateMinimalPreexecProxySource(name string, source []byte) error {
	invalid := fmt.Errorf("selected proxy boundary changed in %s", name)
	file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
	if err != nil {
		return invalid
	}
	alias := ""
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return invalid
		}
		if path == "github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement/policyproxy" {
			if alias != "" {
				return invalid
			}
			alias = "policyproxy"
			if spec.Name != nil {
				alias = spec.Name.Name
			}
		}
	}
	if alias == "" || alias == "." || alias == "_" {
		return invalid
	}
	allowed := make(map[ast.Expr]string)
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok &&
			(name == "minimal_preexec_host_linux.go" && fn.Name.Name == "validMinimalPreexecHostInput" ||
				name == "minimal_preexec_assembler_linux.go" && fn.Name.Name == "newMinimalPreexecNetwork") {
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok {
					allowed[call.Fun] = "New"
				}
				return true
			})
		}
		if group, ok := decl.(*ast.GenDecl); ok && name == "minimal_preexec_host_linux.go" {
			for _, spec := range group.Specs {
				if typ, ok := spec.(*ast.TypeSpec); ok && typ.Name.Name == "minimalPreexecHostInputs" {
					if fields, ok := typ.Type.(*ast.StructType); ok {
						for _, field := range fields.Fields.List {
							if len(field.Names) == 1 && field.Names[0].Name == "proxy" {
								allowed[field.Type] = "Config"
							}
						}
					}
				}
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if ident, ok := selector.X.(*ast.Ident); ok && ident.Name == alias {
			if ident.Obj != nil || allowed[selector] != selector.Sel.Name {
				err = invalid
			}
		}
		return err == nil
	})
	return err
}
