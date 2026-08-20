package sandboxruntime

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestL8JobCredentialLiveHandlesUseOnlySafeFormattingAndDenialCodecs(t *testing.T) {
	matches, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	liveProduction := 0
	denialMethods := map[string]map[string]bool{
		"AuthenticatedWorkerPrincipalAuthority": {},
		"authenticatedWorkerPrincipal":          {},
		"JobCredentialLifecycle":                {},
		"JobCredentialActiveProof":              {},
		"JobCredentialCleanupProof":             {},
		"JobCredentialRuntimeBinder":            {},
		"JobCredentialRuntimeBinding":           {},
		"JobCredentialRuntimePreflightBinding":  {},
	}
	formatLiterals := l8JobCredentialFormatLiterals()
	for _, path := range matches {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		allowedLiveFile := strings.HasPrefix(filepath.Base(path), "job_credential")
		if allowedLiveFile {
			liveProduction++
		}
		set := token.NewFileSet()
		file, err := parser.ParseFile(set, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		fmtAliases, fmtDotImport := l8JobCredentialImportAliases(file, "fmt")
		if allowedLiveFile && fmtDotImport {
			t.Errorf("neutral job credential contract %s uses forbidden dot import of fmt", path)
		}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if allowedLiveFile && (importPath == "encoding/json" || importPath == "encoding/gob" || importPath == "encoding/xml" ||
				importPath == "log" || importPath == "log/slog" ||
				importPath == "os" || importPath == "os/exec" || importPath == "syscall" || importPath == "unsafe" ||
				importPath == "net" || strings.HasPrefix(importPath, "net/") || importPath == "golang.org/x/sys/unix") {
				t.Errorf("neutral job credential contract %s imports forbidden encoder/formatter/live peer-credential package %q", path, importPath)
			}
		}
		for _, issue := range l8JobCredentialRawErrorCompositionIssues(file) {
			t.Errorf("sandboxruntime production file %s %s", path, issue)
		}
		if allowedLiveFile {
			for _, issue := range l8JobCredentialFmtFileIssues(file, fmtAliases, formatLiterals) {
				t.Errorf("neutral job credential contract %s %s", path, issue)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.TypeSpec:
				if l8CredentialLiveDeclarationName(typed.Name.Name) && !allowedLiveFile {
					t.Errorf("live job credential type %s bypasses allowed job_credential files in %s", typed.Name.Name, path)
				}
			case *ast.FuncDecl:
				if typed.Name.Name == "NewAuthenticatedWorkerPrincipal" {
					t.Errorf("%s exposes forbidden direct principal minting constructor", path)
				}
				if l8CredentialLiveDeclarationName(typed.Name.Name) && !allowedLiveFile {
					t.Errorf("live job credential function %s bypasses allowed job_credential files in %s", typed.Name.Name, path)
				}
				receiver := ""
				if typed.Recv != nil {
					receiver = l8ReceiverName(typed.Recv.List[0].Type)
				}
				if typed.Recv == nil || !allowedLiveFile {
					return true
				}
				switch typed.Name.Name {
				case "MarshalBinary", "GobEncode", "Bytes", "Value", "Unwrap":
					t.Errorf("live job credential receiver %s defines forbidden method %s", receiver, typed.Name.Name)
				case "String", "GoString", "MarshalJSON", "MarshalText", "Format":
					allowed, ok := denialMethods[receiver]
					if !ok {
						t.Errorf("live job credential receiver %s defines unexpected formatting/codec method %s", receiver, typed.Name.Name)
						return true
					}
					allowed[typed.Name.Name] = true
				}
			}
			return true
		})
	}
	if liveProduction == 0 {
		t.Fatal("L8 neutral job credential production contracts do not exist")
	}
	for receiver, found := range denialMethods {
		for _, required := range []string{"String", "GoString", "MarshalJSON", "MarshalText", "Format"} {
			if !found[required] {
				t.Errorf("live job credential receiver %s omits safe/denial method %s", receiver, required)
			}
		}
	}
}

func TestL8JobCredentialRawErrorCompositionGuardIsAliasAware(t *testing.T) {
	for _, tt := range []struct {
		name       string
		source     string
		wantIssues int
	}{
		{name: "default join", source: "package fixture\nimport \"errors\"\nvar _ = errors.Join\n", wantIssues: 1},
		{name: "aliased join", source: "package fixture\nimport stableerrors \"errors\"\nvar _ = stableerrors.Join\n", wantIssues: 1},
		{name: "dot import rejected", source: "package fixture\nimport . \"errors\"\nvar _ = Join\n", wantIssues: 1},
		{name: "default is allowed", source: "package fixture\nimport \"errors\"\nvar _ = errors.Is\n"},
		{name: "aliased is allowed", source: "package fixture\nimport stableerrors \"errors\"\nvar _ = stableerrors.Is\n"},
		{name: "unrelated join allowed", source: "package fixture\ntype helper struct{}\nfunc (helper) Join() {}\nvar value helper\nvar _ = value.Join\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", tt.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if issues := l8JobCredentialRawErrorCompositionIssues(file); len(issues) != tt.wantIssues {
				t.Fatalf("raw error composition issues = %v, want %d", issues, tt.wantIssues)
			}
		})
	}
}

func TestL8JobCredentialRawErrorCompositionGuardCoversCrossFileHelpers(t *testing.T) {
	for _, tt := range []struct {
		name       string
		files      map[string]string
		wantIssues int
	}{
		{
			name: "generic helper joins raw causes",
			files: map[string]string{
				"job_credential_live.go": "package sandboxruntime\nfunc denyLive() error { return composeCredentialErrors() }\n",
				"errors.go":              "package sandboxruntime\nimport stableerrors \"errors\"\nfunc composeCredentialErrors() error { return stableerrors.Join() }\n",
			},
			wantIssues: 1,
		},
		{
			name: "legitimate helpers remain available",
			files: map[string]string{
				"job_credential_live.go": "package sandboxruntime\nfunc inspectLive(err error) bool { return inspectCredentialError(err) }\n",
				"helpers.go":             "package sandboxruntime\nimport (\"errors\"; \"strings\")\nfunc inspectCredentialError(err error) bool { _ = strings.Join([]string{\"safe\"}, \",\"); return errors.Is(err, nil) }\n",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var files []*ast.File
			for name, source := range tt.files {
				file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
				if err != nil {
					t.Fatal(err)
				}
				files = append(files, file)
			}
			if issues := l8JobCredentialRawErrorCompositionIssues(files...); len(issues) != tt.wantIssues {
				t.Fatalf("package-wide raw error composition issues = %v, want %d", issues, tt.wantIssues)
			}
		})
	}
}

func l8JobCredentialRawErrorCompositionIssues(files ...*ast.File) []string {
	var issues []string
	for _, file := range files {
		aliases := map[string]bool{}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil || importPath != "errors" {
				continue
			}
			alias := "errors"
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			if alias == "." {
				issues = append(issues, "uses forbidden dot import of errors")
				continue
			}
			if alias != "_" {
				aliases[alias] = true
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Join" {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if ok && aliases[identifier.Name] {
				issues = append(issues, "uses forbidden raw-error composition errors.Join")
			}
			return true
		})
	}
	return issues
}

func TestL8JobCredentialFmtUsageIsRestrictedToExactFormatMethods(t *testing.T) {
	for receiver, requiredFormat := range l8JobCredentialFormatLiterals() {
		t.Run("exact "+receiver, func(t *testing.T) {
			source := "package fixture\nimport safeformat \"fmt\"\ntype " + receiver + " struct{}\nfunc (" + receiver + ") Format(state safeformat.State, verb rune) { safeformat.Fprint(state, " + strconv.Quote(requiredFormat) + ") }\n"
			l8JobCredentialAssertFmtFixture(t, source, requiredFormat, false, false)
		})
	}

	for _, tt := range []struct {
		name           string
		source         string
		requiredFormat string
		wantDotImport  bool
	}{
		{name: "generic formatting in formatter", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprintf(state, \"%v\", verb) }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "sprint in formatter", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { _ = safeformat.Sprint(verb) }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "formatting outside formatter", source: "package fixture\nimport safeformat \"fmt\"\nfunc render(value any) string { return safeformat.Sprint(value) }\n"},
		{name: "wrong fixed literal", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<sandboxruntime.JobCredentialActiveProof>\") }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "package payload", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, safeformat.Stringer(nil)) }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "captured payload", source: "package fixture\nimport safeformat \"fmt\"\nvar captured = \"raw\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, captured) }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "raw identifier payload", source: "package fixture\nimport safeformat \"fmt\"\nvar rawIdentifier any\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, rawIdentifier) }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "helper payload", source: "package fixture\nimport safeformat \"fmt\"\nfunc fixed() string { return \"fixed\" }\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, fixed()) }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "receiver payload", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (lifecycle JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, lifecycle) }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "wrong destination", source: "package fixture\nimport safeformat \"fmt\"\nvar other safeformat.State\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(other, \"<sandboxruntime.JobCredentialLifecycle>\") }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "extra argument", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\", verb) }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "variadic argument", source: "package fixture\nimport safeformat \"fmt\"\nvar parts []any\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, parts...) }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "concatenated payload", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<sandboxruntime.\" + \"JobCredentialLifecycle>\") }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "multiple calls", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\"); safeformat.Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\") }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "import alias shadowed by receiver", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (safeformat JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\") }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "state shadowed in closure", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { func(state safeformat.State) { safeformat.Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\") }(state) }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "package capture beside exact format", source: "package fixture\nimport safeformat \"fmt\"\nvar write = safeformat.Fprint\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\") }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "indirect package capture use beside exact format", source: "package fixture\nimport safeformat \"fmt\"\nvar write = safeformat.Fprint\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\") }\nfunc helper(state safeformat.State) { write(state, \"helper\") }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "grouped package captures beside exact format", source: "package fixture\nimport safeformat \"fmt\"\nvar (\nwrite = safeformat.Fprint\nrender = safeformat.Sprint\n)\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\") }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "cross function fmt use beside exact format", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\") }\nfunc helper(state safeformat.State) { safeformat.Fprint(state, \"helper\") }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "function local capture beside exact format", source: "package fixture\nimport safeformat \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\") }\nfunc helper() { write := safeformat.Fprint; _ = write }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "function alias type beside exact format", source: "package fixture\nimport safeformat \"fmt\"\ntype formatter func(safeformat.State, ...any) (int, error)\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state safeformat.State, verb rune) { safeformat.Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\") }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "blank import", source: "package fixture\nimport _ \"fmt\"\ntype JobCredentialLifecycle struct{}\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>"},
		{name: "dot import", source: "package fixture\nimport . \"fmt\"\ntype JobCredentialLifecycle struct{}\nfunc (JobCredentialLifecycle) Format(state State, verb rune) { Fprint(state, \"<sandboxruntime.JobCredentialLifecycle>\") }\n", requiredFormat: "<sandboxruntime.JobCredentialLifecycle>", wantDotImport: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			l8JobCredentialAssertFmtFixture(t, tt.source, tt.requiredFormat, tt.wantDotImport, true)
		})
	}
}

func l8JobCredentialAssertFmtFixture(t *testing.T, source, requiredFormat string, wantDotImport, wantIssue bool) {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	aliases, dotImport := l8JobCredentialImportAliases(file, "fmt")
	if dotImport != wantDotImport {
		t.Fatalf("fmt dot import = %t, want %t", dotImport, wantDotImport)
	}
	formatLiterals := map[string]string{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Name.Name == "Format" && function.Recv != nil {
			formatLiterals[l8ReceiverName(function.Recv.List[0].Type)] = requiredFormat
		}
	}
	issues := l8JobCredentialFmtFileIssues(file, aliases, formatLiterals)
	if wantIssue == (len(issues) == 0 && !dotImport) {
		t.Fatalf("fmt issues = %v, dot import = %t, want issue %t", issues, dotImport, wantIssue)
	}
}

func l8JobCredentialFormatLiterals() map[string]string {
	return map[string]string{
		"AuthenticatedWorkerPrincipalAuthority": "<sandboxruntime.AuthenticatedWorkerPrincipalAuthority>",
		"authenticatedWorkerPrincipal":          "<sandboxruntime.authenticatedWorkerPrincipal>",
		"JobCredentialLifecycle":                "<sandboxruntime.JobCredentialLifecycle>",
		"JobCredentialActiveProof":              "<sandboxruntime.JobCredentialActiveProof>",
		"JobCredentialCleanupProof":             "<sandboxruntime.JobCredentialCleanupProof>",
		"JobCredentialRuntimeBinder":            "<sandboxruntime.JobCredentialRuntimeBinder>",
		"JobCredentialRuntimeBinding":           "<sandboxruntime.JobCredentialRuntimeBinding>",
		"JobCredentialRuntimePreflightBinding":  "<sandboxruntime.JobCredentialRuntimePreflightBinding>",
	}
}

func l8JobCredentialImportAliases(file *ast.File, wantedPath string) (map[string]bool, bool) {
	aliases := map[string]bool{}
	dotImport := false
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || importPath != wantedPath {
			continue
		}
		alias := path.Base(importPath)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		switch alias {
		case ".":
			dotImport = true
		default:
			aliases[alias] = true
		}
	}
	return aliases, dotImport
}

func l8JobCredentialFmtFileIssues(file *ast.File, fmtAliases map[string]bool, formatLiterals map[string]string) []string {
	var issues []string
	allowedSelectors := map[*ast.SelectorExpr]bool{}
	approvedAliases := map[string]bool{}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "Format" || function.Recv == nil {
			continue
		}
		receiver := l8ReceiverName(function.Recv.List[0].Type)
		requiredFormat := formatLiterals[receiver]
		if requiredFormat == "" {
			continue
		}
		if !l8JobCredentialExactFormatMethod(function, fmtAliases, requiredFormat) {
			issues = append(issues, "Format method on "+receiver+" is not the exact single fixed-literal fmt.Fprint boundary")
			continue
		}
		stateSelector := function.Type.Params.List[0].Type.(*ast.SelectorExpr)
		call := function.Body.List[0].(*ast.ExprStmt).X.(*ast.CallExpr)
		allowedSelectors[stateSelector] = true
		allowedSelectors[call.Fun.(*ast.SelectorExpr)] = true
		approvedAliases[stateSelector.X.(*ast.Ident).Name] = true
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		identifier, ok := selector.X.(*ast.Ident)
		if !ok || !fmtAliases[identifier.Name] {
			return true
		}
		if !allowedSelectors[selector] {
			issues = append(issues, "uses fmt."+selector.Sel.Name+" outside an exact approved Format signature/body")
		}
		return true
	})
	for alias := range fmtAliases {
		if !approvedAliases[alias] {
			issues = append(issues, "imports fmt outside an exact approved Format method")
		}
	}
	return issues
}

func l8JobCredentialExactFormatMethod(function *ast.FuncDecl, fmtAliases map[string]bool, requiredFormat string) bool {
	if function.Type.Results != nil && len(function.Type.Results.List) != 0 || function.Type.Params == nil || len(function.Type.Params.List) != 2 {
		return false
	}
	stateField, verbField := function.Type.Params.List[0], function.Type.Params.List[1]
	if len(stateField.Names) != 1 || len(verbField.Names) != 1 {
		return false
	}
	stateType, ok := stateField.Type.(*ast.SelectorExpr)
	if !ok || stateType.Sel.Name != "State" {
		return false
	}
	fmtIdentifier, ok := stateType.X.(*ast.Ident)
	if !ok || !fmtAliases[fmtIdentifier.Name] || fmtIdentifier.Obj != nil {
		return false
	}
	verbType, ok := verbField.Type.(*ast.Ident)
	if !ok || verbType.Name != "rune" {
		return false
	}
	for _, name := range []string{stateField.Names[0].Name, verbField.Names[0].Name, l8JobCredentialReceiverIdentifier(function)} {
		if name != "" && fmtAliases[name] {
			return false
		}
	}
	if len(function.Body.List) != 1 {
		return false
	}
	expression, ok := function.Body.List[0].(*ast.ExprStmt)
	if !ok {
		return false
	}
	call, ok := expression.X.(*ast.CallExpr)
	if !ok || call.Ellipsis.IsValid() || len(call.Args) != 2 {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Fprint" {
		return false
	}
	qualifier, ok := selector.X.(*ast.Ident)
	if !ok || !fmtAliases[qualifier.Name] || qualifier.Name != fmtIdentifier.Name || qualifier.Obj != nil {
		return false
	}
	destination, ok := call.Args[0].(*ast.Ident)
	if !ok || destination.Name != stateField.Names[0].Name || destination.Obj != stateField.Names[0].Obj {
		return false
	}
	payload, ok := call.Args[1].(*ast.BasicLit)
	if !ok || payload.Kind != token.STRING {
		return false
	}
	literal, err := strconv.Unquote(payload.Value)
	return err == nil && literal == requiredFormat
}

func l8JobCredentialReceiverIdentifier(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) != 1 || len(function.Recv.List[0].Names) != 1 {
		return ""
	}
	return function.Recv.List[0].Names[0].Name
}

func l8CredentialLiveDeclarationName(name string) bool {
	return strings.HasPrefix(name, "JobCredential") ||
		strings.Contains(name, "AuthenticatedWorkerPrincipal") ||
		strings.Contains(name, "CredentialAdmission") ||
		strings.HasPrefix(name, "AuthorizedCredential") ||
		name == "LiveSecretSource" ||
		strings.HasPrefix(name, "ValidateJobCredential") ||
		strings.HasPrefix(name, "NewJobCredential")
}

func l8ReceiverName(expr ast.Expr) string {
	switch value := expr.(type) {
	case *ast.Ident:
		return value.Name
	case *ast.StarExpr:
		return l8ReceiverName(value.X)
	case *ast.IndexExpr:
		return l8ReceiverName(value.X)
	case *ast.IndexListExpr:
		return l8ReceiverName(value.X)
	default:
		return ""
	}
}
