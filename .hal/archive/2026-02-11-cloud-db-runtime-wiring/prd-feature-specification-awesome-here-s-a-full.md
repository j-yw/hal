

I'll start by exploring the codebase to understand the current structure before generating the PRD.Now let me read the key files to understand the current factory pattern and how commands use stores.Now let me read the factory variable declarations to understand the full pattern.Now let me check how the "store not configured" error currently happens when factories are nil.I now have a thorough understanding of the codebase. Let me check the existing go.mod for current dependencies and the .env file.Now I have all the context I need. Let me generate the PRD.PRD saved to `.hal/prd-cloud-db-runtime-wiring.md`.

**10 user stories** covering the full wiring scope:

| Story | Summary |
|-------|---------|
| US-055 | Production driver registration (blank imports for libsql/pgx) |
| US-056 | Split `ValidateStore()` from `Validate()` |
| US-057 | Harden Turso DSN with `net/url` |
| US-058 | Cloud runtime composition root (`sync.Once`, dotenv, lazy init) |
| US-059 | Runtime unit tests |
| US-060 | Wire default factories for 6 cloud commands |
| US-061 | Wire default factories for 5 auth commands |
| US-062 | Load dotenv in `cloud env` command |
| US-063 | Update `deploy/.env.example` with complete key set |
| US-064 | Full test suite pass + integration verification |

The stories are ordered dependency-first (schema/infra changes before wiring) and each is scoped to one focused session. The test override pattern (`if factory == nil`) is preserved throughout.