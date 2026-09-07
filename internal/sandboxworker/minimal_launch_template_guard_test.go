package sandboxworker

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestMinimalLaunchSourceGuardLocksOriginalTemplateProjection(t *testing.T) {
	check := func(source string) bool {
		t.Helper()
		fs := token.NewFileSet()
		file, err := parser.ParseFile(fs, "minimal_launch_dispatch.go", source, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, node := range file.Decls {
			if fn, ok := node.(*ast.FuncDecl); ok && fn.Name.Name == "handleMinimalLaunch" {
				return l8WorkerV2ExactMinimalDispatchDeclaration(l8WorkerV2GuardScope{file: &l8WorkerV2ParsedFile{path: "minimal_launch_dispatch.go", fileSet: fs, parsed: file}, node: fn})
			}
		}
		t.Fatal("missing original selected handler")
		return false
	}
	source := l8ReadWorkerSource(t, "minimal_launch_dispatch.go")
	if !check(source) {
		t.Fatal("actual original-template composition lacks reviewed pin")
	}
	for _, fixture := range []struct{ name, old, replacement string }{
		{"omit extraction", "template, err := minimalLaunchTemplateIdentity(start.Exec.Target.Runtime)", "var template []sandboxruntime.MinimalLaunchTemplateIdentity; var err error"},
		{"skip extraction error", "template, err := minimalLaunchTemplateIdentity(start.Exec.Target.Runtime)\n\tif err != nil {", "template, err := minimalLaunchTemplateIdentity(start.Exec.Target.Runtime)\n\tif false {"},
		{"substitute source", "minimalLaunchTemplateIdentity(start.Exec.Target.Runtime)", "minimalLaunchTemplateIdentity(RuntimeTarget{})"},
		{"foreign source", "minimalLaunchTemplateIdentity(start.Exec.Target.Runtime)", "minimalLaunchTemplateIdentity(foreign.Exec.Target.Runtime)"},
		{"omit forwarding", "service.workerID, hints, template...)", "service.workerID, hints)"},
		{"substitute tuple", "service.workerID, hints, template...)", "service.workerID, hints, foreignTemplate...)"},
		{"foreign resolver", "service.minimalLaunch.Authorizer.ResolveSelection", "foreign.Authorizer.ResolveSelection"},
		{"rekey after callback", "if selection.Current(preparation.ctx) != nil {", "key, _ = jobRequestKeyV2(request.DriverID, principalID, service.daemonGeneration, start); if selection.Current(preparation.ctx) != nil {"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			if !strings.Contains(source, fixture.old) {
				t.Fatal("template bypass mutation did not match")
			}
			if check(strings.Replace(source, fixture.old, fixture.replacement, 1)) {
				t.Fatal("changed original template intake borrowed selected authority")
			}
		})
	}
}
