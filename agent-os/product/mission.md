# Product Mission

## Problem

There is no good solution for letting AI agents work through task lists autonomously with proper git and testing integration. Developers currently have to manually orchestrate AI coding tools, losing time to context switching and repetitive supervision.

## Target Users

- **Solo developers** who want to delegate coding tasks to AI while focusing on architecture and review
- **Small teams** (2-10 developers) who want to parallelize work using AI agents
- **AI-first builders** who embrace AI-assisted development and want maximum automation

## Solution

Hal is an autonomous AI coding loop orchestration CLI that coordinates multiple AI engines to work through PRDs automatically. What makes it unique:

- **Multi-engine orchestration** — Coordinates multiple AI coding tools (Claude, Cursor, Codex, OpenCode, etc.) rather than locking into one
- **PRD-driven automation** — Converts product requirements directly into autonomous task execution loops
- **Git-native workflow** — Built around git worktrees, auto-commits, and merge conflict resolution
