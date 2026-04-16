## hal product plan

Generate or update product context documents

### Synopsis

Generate or update durable product context files:
  - .hal/product/mission.md
  - .hal/product/roadmap.md
  - .hal/product/tech-stack.md

Use this command to maintain long-lived product context.
Use 'hal plan' to create feature-specific PRDs.

```
hal product plan [flags]
```

### Examples

```
  hal product plan
  hal product plan --engine claude
```

### Options

```
  -e, --engine string   Engine to use (claude, codex, pi) (default "codex")
  -h, --help            help for plan
```

### SEE ALSO

* [hal product](hal_product.md)	 - Plan and maintain durable product context

