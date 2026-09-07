package sandboxworker

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

func TestMinimalLaunchSourceGuardLocksOriginalRequestCorrelation(t *testing.T) {
	for _, fixture := range []struct{ name, path, function, old, replacement string }{
		{"omitted issuance input", "minimal_launch_dispatch.go", "reserveMinimalLaunch", "requestKey, deadline, requested)", "requestKey, deadline)"},
		{"substituted credential ID", "minimal_launch_dispatch.go", "reserveMinimalLaunch", "AdmissionGrantID: request.AdmissionGrantID", "AdmissionGrantID: request.PlanID"},
		{"substituted credential revision", "minimal_launch_dispatch.go", "reserveMinimalLaunch", "AdmissionGrantRevision: request.AdmissionGrantRevision", "AdmissionGrantRevision: 1"},
		{"skip issued pair check", "minimal_launch_dispatch.go", "reserveMinimalLaunch", "correlation != requested", "false"},
		{"skip issued accessor error", "minimal_launch_dispatch.go", "reserveMinimalLaunch", "if correlationErr != nil || correlation != requested", "if false || correlation != requested"},
		{"foreign issued accessor", "minimal_launch_dispatch.go", "reserveMinimalLaunch", "correlation, correlationErr := reservation.RequestCorrelation()", "correlation, correlationErr := foreignReservation.RequestCorrelation()"},
		{"skip final request key", "minimal_launch_dispatch.go", "checkMinimalDispatch", "state.RequestKey != identity.RequestKey", "false"},
		{"skip final credential ID", "minimal_launch_dispatch.go", "checkMinimalDispatch", "correlation.AdmissionGrantID != state.JobV2.CredentialIntent.AdmissionGrantID", "false"},
		{"skip final credential revision", "minimal_launch_dispatch.go", "checkMinimalDispatch", "correlation.AdmissionGrantRevision != state.JobV2.CredentialIntent.AdmissionGrantRevision", "false"},
		{"foreign final accessor", "minimal_launch_dispatch.go", "checkMinimalDispatch", "entry.reservation.RequestCorrelation()", "foreignEntry.reservation.RequestCorrelation()"},
		{"skip cancel accessor error", "minimal_launch_cancel.go", "minimalLaunchCancelIdentityMatches", "return err == nil &&", "return true &&"},
		{"skip cancel credential ID", "minimal_launch_cancel.go", "minimalLaunchCancelIdentityMatches", "correlation.AdmissionGrantID == job.CredentialIntent.AdmissionGrantID", "true"},
		{"skip cancel credential revision", "minimal_launch_cancel.go", "minimalLaunchCancelIdentityMatches", "correlation.AdmissionGrantRevision == job.CredentialIntent.AdmissionGrantRevision", "true"},
		{"foreign cancel accessor", "minimal_launch_cancel.go", "minimalLaunchCancelIdentityMatches", "entry.reservation.RequestCorrelation()", "foreignEntry.reservation.RequestCorrelation()"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			check := func(source string) bool {
				fs := token.NewFileSet()
				file, err := parser.ParseFile(fs, fixture.path, source, 0)
				if err != nil {
					t.Fatal(err)
				}
				for _, node := range file.Decls {
					if fn, ok := node.(*ast.FuncDecl); ok && fn.Name.Name == fixture.function {
						return l8WorkerV2ExactMinimalDeclaration(l8WorkerV2GuardScope{file: &l8WorkerV2ParsedFile{path: fixture.path, fileSet: fs, parsed: file}, node: fn})
					}
				}
				t.Fatal("missing original selected declaration")
				return false
			}
			source := l8ReadWorkerSource(t, fixture.path)
			if !check(source) {
				t.Fatal("actual correlation composition lacks its reviewed exact source pin")
			}
			if !strings.Contains(source, fixture.old) {
				t.Fatal("correlation bypass mutation did not match")
			}
			if check(strings.Replace(source, fixture.old, fixture.replacement, 1)) {
				t.Fatal("altered original-request correlation borrowed selected authority")
			}
		})
	}
}
