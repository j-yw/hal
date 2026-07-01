package taskgraph

import (
	"reflect"
	"strings"
	"testing"
)

func TestSchedule_RequestedParallelismIsMaximum(t *testing.T) {
	result := Schedule([]Task{
		parallelTask("task-c", 10, "c"),
		parallelTask("task-a", 20, "a"),
		parallelTask("task-b", 20, "b"),
	}, Options{Parallelism: 10})

	if got, want := taskIDs(result.Ready), []string{"task-c", "task-a", "task-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ready IDs = %v, want %v", got, want)
	}
	if len(result.Ready) >= 10 {
		t.Fatalf("ready batch filled requested parallelism: got %d", len(result.Ready))
	}
	if len(result.Blocked) != 0 {
		t.Fatalf("blocked = %v, want none", result.Blocked)
	}
}

func TestSchedule_ConflictDomainsLimitBatch(t *testing.T) {
	result := Schedule([]Task{
		parallelTask("winner", 10, "shared"),
		parallelTask("blocked", 20, "shared"),
		parallelTask("other", 30, "other"),
	}, Options{Parallelism: 10})

	if got, want := taskIDs(result.Ready), []string{"winner", "other"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ready IDs = %v, want %v", got, want)
	}
	assertBlockedReason(t, result.Blocked, "blocked", ReasonConflictDomainOverlap+":shared")
}

func TestSchedule_BarrierAndParallelUnsafeTasksRunAlone(t *testing.T) {
	barrierResult := Schedule([]Task{
		{
			ID:                 "barrier",
			Priority:           10,
			DomainHints:        []string{"review"},
			ConflictDomains:    []string{"repo"},
			ParallelSafe:       true,
			Barrier:            true,
			MetadataConfidence: MetadataConfidenceHigh,
		},
		parallelTask("next", 20, "next"),
	}, Options{Parallelism: 3})

	if got, want := taskIDs(barrierResult.Ready), []string{"barrier"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("barrier ready IDs = %v, want %v", got, want)
	}
	assertSerialReason(t, barrierResult.Serial, "barrier", ReasonBarrier)

	unsafeResult := Schedule([]Task{
		{
			ID:                 "unsafe",
			Priority:           10,
			DomainHints:        []string{"run"},
			ConflictDomains:    []string{"workspace"},
			ParallelSafe:       false,
			MetadataConfidence: MetadataConfidenceHigh,
		},
		parallelTask("next", 20, "next"),
	}, Options{Parallelism: 3})

	if got, want := taskIDs(unsafeResult.Ready), []string{"unsafe"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unsafe ready IDs = %v, want %v", got, want)
	}
	assertSerialReason(t, unsafeResult.Serial, "unsafe", ReasonParallelUnsafe)
}

func TestSchedule_DependenciesMustBeComplete(t *testing.T) {
	readyAfterComplete := parallelTask("ready-after-complete", 20, "ready")
	readyAfterComplete.DependsOn = []string{"done"}
	blockedAfterPending := parallelTask("blocked-after-pending", 10, "blocked")
	blockedAfterPending.DependsOn = []string{"ready-after-complete"}

	result := Schedule([]Task{
		parallelTaskWithStatus("done", 30, "done", TaskStatusComplete),
		readyAfterComplete,
		blockedAfterPending,
		parallelTaskWithStatus("running", 40, "running", TaskStatusRunning),
	}, Options{Parallelism: 10})

	if got, want := taskIDs(result.Ready), []string{"ready-after-complete"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ready IDs = %v, want %v", got, want)
	}
	assertBlockedReason(t, result.Blocked, "blocked-after-pending", ReasonDependencyIncomplete+":ready-after-complete")
	if containsTaskID(result.Ready, "running") {
		t.Fatalf("running task was selected in ready batch")
	}
}

func TestSchedule_MetadataConfidenceControlsSerialFallback(t *testing.T) {
	unknown := Task{
		ID:           "unknown",
		Priority:     30,
		ParallelSafe: true,
	}
	knownNoDomains := Task{
		ID:                 "known-no-domains",
		Priority:           10,
		ParallelSafe:       true,
		MetadataConfidence: MetadataConfidenceHigh,
	}

	defaultResult := Schedule([]Task{
		unknown,
		knownNoDomains,
		parallelTask("known", 20, "known"),
	}, Options{Parallelism: 3})

	if got, want := taskIDs(defaultResult.Ready), []string{"known-no-domains", "known"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default ready IDs = %v, want %v", got, want)
	}
	assertSerialReason(t, defaultResult.Serial, "unknown", ReasonUntrustedMetadata)

	unknown.Priority = 10
	fallbackResult := Schedule([]Task{
		unknown,
		parallelTask("known", 20, "known"),
	}, Options{Parallelism: 3, AllowConservativeFallback: true})

	if got, want := taskIDs(fallbackResult.Ready), []string{"unknown", "known"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fallback ready IDs = %v, want %v", got, want)
	}
	if len(fallbackResult.Serial) != 0 {
		t.Fatalf("fallback serial = %v, want none", fallbackResult.Serial)
	}

	hintsOnly := Task{
		ID:                 "hints-only",
		Priority:           10,
		DomainHints:        []string{"same-domain"},
		ParallelSafe:       true,
		MetadataConfidence: MetadataConfidenceLow,
	}
	alsoHintsOnly := hintsOnly
	alsoHintsOnly.ID = "also-hints-only"
	alsoHintsOnly.Priority = 20
	fallbackConflictResult := Schedule([]Task{
		hintsOnly,
		alsoHintsOnly,
	}, Options{Parallelism: 3, AllowConservativeFallback: true})

	if got, want := taskIDs(fallbackConflictResult.Ready), []string{"hints-only"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fallback conflict ready IDs = %v, want %v", got, want)
	}
	assertBlockedReason(t, fallbackConflictResult.Blocked, "also-hints-only", ReasonConflictDomainOverlap+":hint:same-domain")
}

func TestSchedule_BlocksCyclesAndInvalidDependencies(t *testing.T) {
	a := parallelTask("cycle-a", 30, "a")
	a.DependsOn = []string{"cycle-b"}
	b := parallelTask("cycle-b", 20, "b")
	b.DependsOn = []string{"cycle-a"}
	missing := parallelTask("missing-dep", 10, "missing")
	missing.DependsOn = []string{"does-not-exist"}

	result := Schedule([]Task{a, b, missing}, Options{Parallelism: 10})

	if len(result.Ready) != 0 {
		t.Fatalf("ready = %v, want none", taskIDs(result.Ready))
	}
	assertBlockedReason(t, result.Blocked, "cycle-a", ReasonDependencyCycle)
	assertBlockedReason(t, result.Blocked, "cycle-b", ReasonDependencyCycle)
	assertBlockedReason(t, result.Blocked, "missing-dep", ReasonInvalidDependency+":does-not-exist")
}

func parallelTask(id string, priority int, domain string) Task {
	return parallelTaskWithStatus(id, priority, domain, TaskStatusPending)
}

func parallelTaskWithStatus(id string, priority int, domain string, status TaskStatus) Task {
	return Task{
		ID:                 id,
		Priority:           priority,
		DomainHints:        []string{"hint-" + id},
		ConflictDomains:    []string{domain},
		ParallelSafe:       true,
		Status:             status,
		MetadataConfidence: MetadataConfidenceHigh,
	}
}

func taskIDs(tasks []Task) []string {
	ids := make([]string, 0, len(tasks))
	for _, task := range tasks {
		ids = append(ids, task.ID)
	}
	return ids
}

func containsTaskID(tasks []Task, id string) bool {
	for _, task := range tasks {
		if task.ID == id {
			return true
		}
	}
	return false
}

func assertBlockedReason(t *testing.T, blocked []BlockedTask, id, reason string) {
	t.Helper()

	for _, task := range blocked {
		if task.Task.ID != id {
			continue
		}
		if reasonsContain(task.Reasons, reason) {
			return
		}
		t.Fatalf("blocked reasons for %s = %v, want %q", id, task.Reasons, reason)
	}
	t.Fatalf("blocked task %s not found in %v", id, blocked)
}

func assertSerialReason(t *testing.T, serial []SerialTask, id, reason string) {
	t.Helper()

	for _, task := range serial {
		if task.Task.ID != id {
			continue
		}
		if reasonsContain(task.Reasons, reason) {
			return
		}
		t.Fatalf("serial reasons for %s = %v, want %q", id, task.Reasons, reason)
	}
	t.Fatalf("serial task %s not found in %v", id, serial)
}

func reasonsContain(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want || strings.HasPrefix(reason, want+":") {
			return true
		}
	}
	return false
}
