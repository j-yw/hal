# Plan Contract v1

**Command:** `hal plan --json`  
**Contract Version:** 1  
**Stability:** Stable. New fields may be added with `omitempty`; existing fields will not be removed or renamed.

`hal plan --json` is the machine-readable result for agent-safe PRD generation. It is intentionally non-interactive and must be used with `--no-questions` plus explicit input (a positional feature description or `--input <path|->`). Editor mode is never used with `--json`.

`--format` controls the generated PRD artifact (`markdown` or `json`). `--json` controls this command-result contract.

## Top-Level Structure

| Field | Type | Description |
|-------|------|-------------|
| `contractVersion` | integer | Always `1` for this contract |
| `ok` | boolean | Whether planning completed successfully |
| `outputPath` | string | Path to the generated PRD artifact. Present on success. |
| `format` | string | Requested artifact format. Normally `"markdown"` or `"json"`; invalid input failures may echo the rejected value. |
| `inputSource` | string | Input source enum: `"argument"`, `"file"`, `"stdin"`, or `"editor"`. `"editor"` appears only for rejected `--json` requests that omitted explicit input; editor mode is never opened with `--json`. |
| `questionsAsked` | boolean | Whether interactive clarifying questions were asked. For successful `hal plan --json` v1 this is always `false` because `--no-questions` is required. |
| `nextSteps` | array | Suggested follow-up commands. Present on success. |
| `error` | string | Failure detail. Present when `ok` is `false`. |
| `summary` | string | Human-readable one-line summary suitable for logs |

## Input Rules

`hal plan --json` is deterministic and non-interactive:

- Must include `--no-questions`.
- Must include explicit input via positional `[feature-description]` or `--input <path|->`.
- Never opens `$EDITOR`.
- Keeps stdout as a single JSON object.
- Emits an `ok:false` JSON object on validation/input/generation failures, then exits non-zero.
- `--input -` reads stdin and requires `--no-questions` because stdin is consumed for the feature brief.

Valid machine-oriented examples:

```bash
hal plan "add user authentication" --no-questions --format json --json
hal plan --input .hal/input/auth.md --no-questions --format json --json
hal plan --input - --no-questions --format json --json < .hal/input/auth.md
```

## Success Example

See [`examples/plan-v1-success.json`](examples/plan-v1-success.json).

```json
{
  "contractVersion": 1,
  "ok": true,
  "outputPath": ".hal/prd.json",
  "format": "json",
  "inputSource": "file",
  "questionsAsked": false,
  "nextSteps": ["hal validate --json", "hal run --json"],
  "summary": "PRD created"
}
```

## Failure Example

See [`examples/plan-v1-failure.json`](examples/plan-v1-failure.json).

```json
{
  "contractVersion": 1,
  "ok": false,
  "format": "json",
  "inputSource": "file",
  "questionsAsked": false,
  "error": "PRD generation failed: engine prompt failed",
  "summary": "PRD generation failed"
}
```
