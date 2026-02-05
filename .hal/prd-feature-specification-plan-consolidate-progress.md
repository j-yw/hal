I'll create a comprehensive PRD for this consolidation feature. Let me first check the current codebase structure to ensure accuracy.Now I have a good understanding of the codebase. Let me write the PRD.I've created the PRD at `.hal/prd-consolidate-progress-files.md`. 

The PRD includes 11 user stories ordered by dependency:
1. **US-001 to US-002**: Core constant removal and pipeline update (schema/config changes)
2. **US-003**: Migration logic (merges existing auto-progress.txt into progress.txt)
3. **US-004 to US-006**: Review enhancements (fixes the core bug + adds JSON PRD context)
4. **US-007 to US-009**: Archive system updates and tests
5. **US-010**: New `hal cleanup` command for removing orphaned files
6. **US-011**: Documentation

Key decisions based on your answers:
- **Merge strategy**: Appends auto-progress.txt content to progress.txt with a separator line
- **Optimal review context**: Added JSON PRD reading (both `prd.json` and `auto-prd.json`) to give the review prompt visibility into task completion status - this is the most valuable addition since the review can now see which tasks are marked `passes: true`
- **Cleanup command**: Included as US-010 with `--dry-run` support