package sandboxworker

import "testing"

// Enrollment adds audited roots, not exemptions. These fixtures deliberately
// have no v2 names: every declaration in each selected file must be inspected.
func TestMinimalLaunchSourceGuardEnrollsAuditedRoots(t *testing.T) {
	policy := l8WorkerV2ProductionGuardPolicy()
	for _, path := range []string{"minimal_launch_dispatch.go", "minimal_launch_file_other.go", "minimal_launch_file_unix.go", "minimal_launch_store.go"} {
		t.Run(path, func(t *testing.T) {
			if !policy.dedicated[path] || policy.mixed[path] {
				t.Fatal("selected file is not a dedicated audited root")
			}
			l8AssertWorkerV2GuardAllows(t, map[string]string{path: "package sandboxworker\nfunc selectedHelper() {}"}, policy)
			for _, fixture := range []struct{ name, source, reason string }{
				{"process", "package sandboxworker\nimport \"os\"\nfunc selectedHelper() { os.Exit(1) }", "os.Exit"},
				{"unbounded reader", "package sandboxworker\nimport \"io\"\nfunc selectedHelper(reader io.Reader) { _, _ = io.ReadAll(reader) }", "implicit interface callback"},
				{"callback", "package sandboxworker\ntype selectedDispatcher interface { Run() }\nfunc selectedHelper(value selectedDispatcher) { value.Run() }", "interface dispatch"},
				{"schema", "package sandboxworker\ntype selectedRecord struct { Value string `json:\"secretValue\"` }", `json:\"secret`},
			} {
				t.Run(fixture.name, func(t *testing.T) {
					l8AssertWorkerV2GuardRejects(t, map[string]string{path: fixture.source}, policy, fixture.reason)
				})
			}
			l8AssertWorkerV2GuardRejects(t, map[string]string{
				path:             "package sandboxworker\nfunc selectedHelper() { indirectHelper() }",
				"job_helpers.go": "package sandboxworker\nimport \"os\"\nfunc indirectHelper() { os.Exit(1) }",
			}, policy, "os.Exit")
		})
	}
	l8AssertWorkerV2GuardRejects(t, map[string]string{
		"minimal_launch_unlisted.go": "package sandboxworker\nfunc hiddenJobStartV2() {}",
	}, policy, "outside the exact allowlist")
}
