package taskgraph

import "sort"

// TaskStatus is the scheduler-visible lifecycle state for a task.
type TaskStatus string

const (
	TaskStatusPending  TaskStatus = "pending"
	TaskStatusRunning  TaskStatus = "running"
	TaskStatusComplete TaskStatus = "complete"
	TaskStatusFailed   TaskStatus = "failed"
)

// MetadataConfidence describes whether scheduling metadata is trusted enough
// to use for parallel selection.
type MetadataConfidence string

const (
	MetadataConfidenceUnknown MetadataConfidence = ""
	MetadataConfidenceLow     MetadataConfidence = "low"
	MetadataConfidenceHigh    MetadataConfidence = "high"
)

const (
	ReasonInvalidTaskID         = "invalid_task_id"
	ReasonDuplicateTaskID       = "duplicate_task_id"
	ReasonInvalidDependency     = "invalid_dependency"
	ReasonDependencyIncomplete  = "dependency_incomplete"
	ReasonDependencyCycle       = "dependency_cycle"
	ReasonConflictDomainOverlap = "conflict_domain_overlap"
	ReasonBarrier               = "barrier"
	ReasonParallelUnsafe        = "parallel_safe_false"
	ReasonUntrustedMetadata     = "metadata_untrusted"
)

// Task is the command-agnostic scheduler input model. Future adapters can
// translate engine.PRD stories into this shape without coupling this package to
// command or engine packages.
type Task struct {
	ID                 string
	Priority           int
	DomainHints        []string
	DependsOn          []string
	ConflictDomains    []string
	ParallelSafe       bool
	Barrier            bool
	Status             TaskStatus
	MetadataConfidence MetadataConfidence
}

// Options controls one scheduling decision.
type Options struct {
	// Parallelism is a maximum batch size. It does not require the scheduler to
	// fill every slot when dependencies, conflicts, or serial-only tasks prevent
	// safe selection.
	Parallelism int

	// AllowConservativeFallback lets low-confidence or empty metadata use
	// conservative derived conflict domains instead of forcing a serial run.
	AllowConservativeFallback bool
}

// Result describes one scheduling decision.
type Result struct {
	Ready   []Task
	Blocked []BlockedTask
	Serial  []SerialTask
}

type BlockedTask struct {
	Task    Task
	Reasons []string
}

type SerialTask struct {
	Task    Task
	Reasons []string
}

// Schedule selects one deterministic ready batch from tasks.
func Schedule(tasks []Task, opts Options) Result {
	parallelism := opts.Parallelism
	if parallelism < 1 {
		parallelism = 1
	}

	tasks = cloneTasks(tasks)
	sortTasks(tasks)

	countByID := make(map[string]int, len(tasks))
	byID := make(map[string]Task, len(tasks))
	for _, task := range tasks {
		if task.ID == "" {
			continue
		}
		countByID[task.ID]++
		if _, ok := byID[task.ID]; !ok {
			byID[task.ID] = task
		}
	}

	cyclic := cyclicPendingTasks(tasks, byID)
	var result Result
	var ready []Task

	for _, task := range tasks {
		if taskStatus(task) != TaskStatusPending {
			continue
		}

		reasons := blockingReasons(task, byID, countByID, cyclic)
		if len(reasons) > 0 {
			result.Blocked = append(result.Blocked, BlockedTask{
				Task:    task,
				Reasons: reasons,
			})
			continue
		}

		ready = append(ready, task)
		if serialReasons := serialReasons(task, opts); len(serialReasons) > 0 {
			result.Serial = append(result.Serial, SerialTask{
				Task:    task,
				Reasons: serialReasons,
			})
		}
	}

	if len(ready) == 0 {
		return result
	}

	serialByID := make(map[string]struct{}, len(result.Serial))
	for _, task := range result.Serial {
		serialByID[task.Task.ID] = struct{}{}
	}

	if _, ok := serialByID[ready[0].ID]; ok {
		result.Ready = []Task{ready[0]}
		return result
	}

	usedDomains := map[string]string{}
	for _, task := range ready {
		if len(result.Ready) >= parallelism {
			break
		}
		if _, ok := serialByID[task.ID]; ok {
			continue
		}

		if overlaps, domain := overlapsSelectedDomain(task, opts, usedDomains); overlaps {
			result.Blocked = append(result.Blocked, BlockedTask{
				Task:    task,
				Reasons: []string{ReasonConflictDomainOverlap + ":" + domain},
			})
			continue
		}

		result.Ready = append(result.Ready, task)
		for _, domain := range effectiveConflictDomains(task, opts) {
			usedDomains[domain] = task.ID
		}
	}

	return result
}

func blockingReasons(task Task, byID map[string]Task, countByID map[string]int, cyclic map[string]bool) []string {
	var reasons []string
	if task.ID == "" {
		reasons = append(reasons, ReasonInvalidTaskID)
		return reasons
	}
	if countByID[task.ID] > 1 {
		reasons = append(reasons, ReasonDuplicateTaskID)
	}
	if cyclic[task.ID] {
		reasons = append(reasons, ReasonDependencyCycle)
	}
	for _, dep := range task.DependsOn {
		depTask, ok := byID[dep]
		if !ok {
			reasons = append(reasons, ReasonInvalidDependency+":"+dep)
			continue
		}
		if taskStatus(depTask) != TaskStatusComplete {
			reasons = append(reasons, ReasonDependencyIncomplete+":"+dep)
		}
	}
	return reasons
}

func serialReasons(task Task, opts Options) []string {
	var reasons []string
	if task.Barrier {
		reasons = append(reasons, ReasonBarrier)
	}
	if !task.ParallelSafe {
		reasons = append(reasons, ReasonParallelUnsafe)
	}
	if !opts.AllowConservativeFallback && metadataUntrusted(task) {
		reasons = append(reasons, ReasonUntrustedMetadata)
	}
	return reasons
}

func metadataUntrusted(task Task) bool {
	return task.MetadataConfidence != MetadataConfidenceHigh || len(task.ConflictDomains) == 0
}

func overlapsSelectedDomain(task Task, opts Options, used map[string]string) (bool, string) {
	for _, domain := range effectiveConflictDomains(task, opts) {
		if _, ok := used[domain]; ok {
			return true, domain
		}
	}
	return false, ""
}

func effectiveConflictDomains(task Task, opts Options) []string {
	domains := uniqueStrings(task.ConflictDomains)
	if len(domains) == 0 && opts.AllowConservativeFallback {
		for _, hint := range uniqueStrings(task.DomainHints) {
			domains = append(domains, "hint:"+hint)
		}
	}
	if len(domains) == 0 && opts.AllowConservativeFallback && metadataUntrusted(task) {
		domains = append(domains, "metadata:unknown")
	}
	if opts.AllowConservativeFallback && task.MetadataConfidence != MetadataConfidenceHigh {
		domains = append(domains, "metadata:untrusted")
	}
	return uniqueStrings(domains)
}

func cyclicPendingTasks(tasks []Task, byID map[string]Task) map[string]bool {
	const (
		unvisited = 0
		visiting  = 1
		visited   = 2
	)

	state := map[string]int{}
	cyclic := map[string]bool{}
	var stack []string

	var visit func(string)
	visit = func(id string) {
		switch state[id] {
		case visiting:
			for i := len(stack) - 1; i >= 0; i-- {
				cyclic[stack[i]] = true
				if stack[i] == id {
					break
				}
			}
			return
		case visited:
			return
		}

		task, ok := byID[id]
		if !ok || taskStatus(task) != TaskStatusPending {
			return
		}

		state[id] = visiting
		stack = append(stack, id)
		for _, dep := range task.DependsOn {
			depTask, ok := byID[dep]
			if !ok || taskStatus(depTask) != TaskStatusPending {
				continue
			}
			visit(dep)
		}
		stack = stack[:len(stack)-1]
		state[id] = visited
	}

	for _, task := range tasks {
		if task.ID == "" || taskStatus(task) != TaskStatusPending {
			continue
		}
		visit(task.ID)
	}

	return cyclic
}

func sortTasks(tasks []Task) {
	sort.SliceStable(tasks, func(i, j int) bool {
		if tasks[i].Priority != tasks[j].Priority {
			return tasks[i].Priority < tasks[j].Priority
		}
		return tasks[i].ID < tasks[j].ID
	})
}

func cloneTasks(tasks []Task) []Task {
	cloned := make([]Task, len(tasks))
	for i, task := range tasks {
		cloned[i] = task
		cloned[i].DomainHints = append([]string(nil), task.DomainHints...)
		cloned[i].DependsOn = append([]string(nil), task.DependsOn...)
		cloned[i].ConflictDomains = append([]string(nil), task.ConflictDomains...)
	}
	return cloned
}

func taskStatus(task Task) TaskStatus {
	if task.Status == "" {
		return TaskStatusPending
	}
	return task.Status
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var unique []string
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	sort.Strings(unique)
	return unique
}
