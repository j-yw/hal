# Init Idempotency

`hal init` is safe to run repeatedly. It never destroys existing state.

## Rules

- **Directories**: Use `os.MkdirAll` — idempotent by design
- **Default files**: Only write if file doesn't exist (`os.Stat` check first)
- **Gitignore**: Only append `.hal/` if not already present
- **Skills**: Reinstalled every init (embedded files overwrite installed copies)
- **Template migrations**: Run every init via `migrateTemplates` (idempotent patches)
- **Symlinks**: Recreated every init for engine skill discovery

## Never Overwrite User Files

User customizations to `config.yaml`, `prompt.md`, and `progress.txt` are sacred. If the embedded template adds a new section, use `migrateTemplates` to surgically patch existing files rather than replacing them.

## Output Contract

Init reports what it did:
- "Created:" — lists newly written files
- "Already existed (preserved):" — lists skipped files
- "All files already exist. No changes made." — when nothing changed
