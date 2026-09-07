package sandboxruntime

import (
	"strings"
	"testing"
)

func TestMinimalLaunchAuthorizerScopeRequiresSelectedIDSyntax(t *testing.T) {
	_, selection, _, _ := minimalLaunchAttemptFixture(t)
	for _, field := range []string{"policy", "principal", "worker", "host", "template", "workspace", "network"} {
		for _, value := range []string{"_invalid", ".invalid", "-invalid", strings.Repeat("x", 65)} {
			t.Run(field+"/"+value[:1], func(t *testing.T) {
				scope := selection.scope
				switch field {
				case "policy":
					scope.PolicyID = value
				case "principal":
					scope.PrincipalID = value
				case "worker":
					scope.WorkerID = value
				case "host":
					scope.HostID = value
				case "template":
					scope.TemplatePolicyID = value
				case "workspace":
					scope.WorkspacePolicyID = value
				case "network":
					scope.NetworkPolicyID = value
				}
				authorizer, err := NewMinimalLaunchAuthorizer(selection.authorizer.authority, selection.binding, []MinimalLaunchScope{scope})
				if authorizer != nil {
					authorizer.Close()
				}
				if authorizer != nil || err == nil {
					t.Fatalf("configured %s accepted guest-invalid selected ID", field)
				}
			})
		}
	}
}

func TestMinimalLaunchAuthorizerScopeIDSyntaxPositiveControls(t *testing.T) {
	_, selection, _, _ := minimalLaunchAttemptFixture(t)
	for _, value := range []string{"A", "0", "a._-", strings.Repeat("a", 64)} {
		scope := selection.scope
		scope.PolicyID, scope.PrincipalID, scope.WorkerID, scope.HostID = value, value, value, value
		scope.TemplatePolicyID, scope.WorkspacePolicyID, scope.NetworkPolicyID = value, value, value
		authorizer, err := NewMinimalLaunchAuthorizer(selection.authorizer.authority, selection.binding, []MinimalLaunchScope{scope})
		if err != nil || authorizer == nil {
			t.Fatal("valid selected scope ID rejected")
		}
		authorizer.Close()
	}
}
