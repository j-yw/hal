# Autoresearch Deferred Ideas

## Active / High Priority
- The 413 error path causes the model to retry/troubleshoot despite explicit "no retry" instruction. When it retries, it may bypass the mocked curl PATH. This is both a prompt compliance issue AND a mock isolation issue. Consider: (a) making mock curl a wrapper that logs every invocation, (b) adding even stronger "STOP IMMEDIATELY" language for 413, (c) accepting ~93% as the practical ceiling if 413 retries are an inherent model behavior.
- Add explicit prompt snapshot management for out-of-repo target skills (`SKILL.md.best` + restore-on-discard hook) so discard semantics remain faithful even when `log_experiment` cannot git-revert external paths.

## Completed / Stale (pruned)
- ~~Fix benchmark leak detector~~ — DONE in segment 2 (placeholder exclusion + scoped leak check)
- ~~Revisit per-scenario timeout budget~~ — DONE: tested 90s and 120s; 413 takes >120s sometimes due to model retry behavior, not raw latency
