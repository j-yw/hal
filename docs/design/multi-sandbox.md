# Multi-Sandbox Implementation Plan

**Status**: Approved, ready for implementation
**Author**: hal team
**Date**: 2026-03-20

---

## Problem

Hal manages one sandbox at a time. State lives in `.hal/sandbox.json` (project-scoped, single object). All commands assume one active sandbox. Users who want 3–12 simultaneous sandboxes — each on a different repo or task, all reachable from a phone via Tailscale — cannot do so.

## Goals

1. Manage N sandboxes from anywhere (not tied to a project directory).
2. Create individually or in batches (`--count N`).
3. Connect from phone via stable Tailscale hostnames (one per sandbox).
4. Auto-shutdown idle sandboxes (configurable per sandbox).
5. See cost estimates across all sandboxes.
6. Backward-compatible: existing single-sandbox users keep working.

---

## 1. Global Directory

All sandbox state moves from project `.hal/` to a global directory.

```
~/.config/hal/                          ← 0700
├── sandbox-config.yaml                 ← 0600
└── sandboxes/                          ← 0700
    ├── api-backend.json                ← 0600
    ├── frontend.json
    └── worker-01.json
```

**Resolution order**: `$HAL_CONFIG_HOME` → `$XDG_CONFIG_HOME/hal` → `~/.config/hal`

Tests use `t.Setenv("HAL_CONFIG_HOME", tmpDir)` for isolation, following the `codexHome()` pattern in `internal/skills/codex.go`.

---

## 2. Identity Model

Each sandbox instance has three identity layers:

```go
type SandboxState struct {
    // ── Identity ──
    ID                string     `json:"id"`                          // UUIDv7 — immutable, generated at creation
    Name              string     `json:"name"`                        // human-readable — file key, validated

    // ── Provider ──
    Provider          string     `json:"provider"`                    // "daytona", "hetzner", "digitalocean", "lightsail"
    WorkspaceID       string     `json:"workspaceId,omitempty"`       // provider-native ID (droplet ID, instance name, etc.)

    // ── Networking ──
    IP                string     `json:"ip"`
    TailscaleIP       string     `json:"tailscaleIp,omitempty"`
    TailscaleHostname string     `json:"tailscaleHostname,omitempty"` // "hal-{name}" — auto-generated

    // ── Lifecycle ──
    Status            string     `json:"status"`                      // "running", "stopped", "unknown"
    CreatedAt         time.Time  `json:"createdAt"`
    StoppedAt         *time.Time `json:"stoppedAt,omitempty"`         // for display ("stopped 2h ago")

    // ── Config ──
    AutoShutdown      bool       `json:"autoShutdown"`
    IdleHours         int        `json:"idleHours,omitempty"`         // 0 = use default (48)
    Size              string     `json:"size,omitempty"`              // provider size slug (for cost calc)

    // ── Labels ──
    Repo              string     `json:"repo,omitempty"`              // optional — informational only
    SnapshotID        string     `json:"snapshotId,omitempty"`        // daytona snapshot
}
```

**UUIDv7**: Generated with injectable clock + random source (no external dependency). Uses `crypto/rand` with proper error handling. Tests verify format, version bits (0x70), variant bits (0x80), monotonic ordering, and rand failure path.

---

## 3. Name Rules

One canonical validator for all contexts: filenames (`{name}.json`), cloud resource names, and Tailscale hostnames.

| Rule | Value |
|------|-------|
| Min length | 1 |
| Max length | **59** (63 minus `hal-` Tailscale prefix) |
| Charset | lowercase alphanumeric + hyphens |
| No leading/trailing hyphen | enforced |
| No consecutive hyphens | enforced |

```
ValidateName("api-backend")   → ok
ValidateName("My Server!")     → error: must be lowercase alphanumeric and hyphens
ValidateName("a]..60 chars")   → error: must be 1-59 chars
```

**Tailscale hostname**: always `hal-{name}`. Generated automatically, never user-specified.

**Batch names**: `--count N` generates `{base}-01` through `{base}-N` with dynamic zero-padding (width = `max(2, digits(N))`). So count=5 → `-01..-05`, count=100 → `-001..-100`. Each name is validated before any creation begins.

**Collision policy**: Creating a sandbox with an existing name fails with: `sandbox "X" already exists (use 'hal sandbox delete X' first, or use --force to replace)`. For batch, all names are pre-validated; if any collide, nothing is created.

---

## 4. Provider Interface Refactor

**Problem**: Current providers call `LoadState()` internally in SSH/Exec to get the IP. With global multi-sandbox state, providers must not know where state lives.

**Solution**: New `ConnectInfo` struct passed from command layer to provider. Providers become pure cloud-operation wrappers with no state file access.

```go
type ConnectInfo struct {
    Name        string // sandbox name
    IP          string // resolved preferred IP (tailscale or public)
    WorkspaceID string // provider-native ID
}

type Provider interface {
    Create(ctx context.Context, name string, env map[string]string, out io.Writer) (*SandboxResult, error)
    Stop(ctx context.Context, ref *ConnectInfo, out io.Writer) error
    Delete(ctx context.Context, ref *ConnectInfo, out io.Writer) error
    Status(ctx context.Context, ref *ConnectInfo, out io.Writer) error
    SSH(info *ConnectInfo) (*exec.Cmd, error)
    Exec(info *ConnectInfo, args []string) (*exec.Cmd, error)
}
```

**What changes per provider**:

| Provider | Removes | SSH uses | Stop/Delete uses |
|----------|---------|----------|-----------------|
| Daytona | — | `info.Name` | `info.Name` |
| Hetzner | `StateDir`, `LoadState()` calls | `info.IP` (user: root) | `info.Name` |
| DigitalOcean | `StateDir`, `resolveDropletTarget()`, `refreshIP()` | `info.IP` (user: root) | `info.WorkspaceID` |
| Lightsail | `StateDir`, `LoadState()` calls | `info.IP` (user: ubuntu) | `info.Name` |

**Command layer** builds ConnectInfo from registry:

```go
instance, _ := sandbox.LoadInstance(name)
info := &sandbox.ConnectInfo{
    Name:        instance.Name,
    IP:          sandbox.PreferredIP(instance),
    WorkspaceID: instance.WorkspaceID,
}
provider.SSH(info)
```

---

## 5. Global Config

Replaces the project-scoped `.hal/config.yaml` `sandbox:` and `daytona:` sections.

```yaml
# ~/.config/hal/sandbox-config.yaml

provider: digitalocean          # default: "daytona" (matches current codebase default)

defaults:
  autoShutdown: true
  idleHours: 48

env:
  ANTHROPIC_API_KEY: "sk-ant-..."
  OPENAI_API_KEY: "sk-..."
  GITHUB_TOKEN: "ghp_..."
  GIT_USER_NAME: "j-yw"
  GIT_USER_EMAIL: "32629001+j-yw@users.noreply.github.com"
  TAILSCALE_AUTHKEY: "tskey-auth-..."

tailscaleLockdown: true

daytona:
  apiKey: "..."
  serverURL: "https://app.daytona.io/api"

digitalocean:
  sshKey: "aa:bb:cc:..."
  size: "s-2vcpu-4gb"

hetzner:
  sshKey: "mine"
  serverType: "cx22"
  image: "ubuntu-24.04"

lightsail:
  keyPairName: "my-key"
  bundle: "small_3_0"
  region: "us-east-1"
  availabilityZone: "us-east-1a"
```

Default provider is `"daytona"` when no config exists, matching the three current fallback sites: `compound.LoadSandboxConfig()`, `sandbox.LoadState()` auto-migrate, and `cmd/sandbox.go` `resolveProviderFromName()`.

---

## 6. Migration

### Trigger

Every `hal sandbox *` command calls `sandbox.Migrate(projectDir)` at the top, before any other logic. The function is idempotent — safe to run repeatedly.

### Decision matrix

| Global config exists | Local `sandbox:`+`daytona:` | Local `sandbox.json` | Action |
|:---:|:---:|:---:|------|
| ✗ | ✗ | ✗ | No-op |
| ✗ | ✓ | ✗ | Copy both sections → global config |
| ✗ | ✗ | ✓ | Create global dir, copy state → registry |
| ✗ | ✓ | ✓ | Copy config + state → global |
| ✓ | ✗ | ✗ | No-op |
| ✓ | ✗ | ✓ | Copy state → registry (config already global) |
| ✓ | ✓ | ✗ | Skip config (global wins), print notice |
| ✓ | ✓ | ✓ | Copy state, skip config (global wins), print notice |

### Safety rules

1. **Config**: global file wins on conflict. Local config is never deleted — just ignored after migration.
2. **State**: `.hal/sandbox.json` is only deleted after the global registry write is verified (read-back check).
3. **Name collision**: if `sandboxes/{name}.json` already exists with the same provider + WorkspaceID → skip (already migrated). If different WorkspaceID → fail with message, preserve local file.
4. **Cross-device**: uses copy+remove (not `os.Rename`) for safety, following `internal/archive/move.go` pattern.

### Dedicated command

`hal sandbox migrate` — non-interactive, idempotent. Runs the same logic but with verbose output. Used by doctor remediation (see §11).

---

## 7. CLI Commands

### `hal sandbox setup`

Works from **any directory** — no `.hal/` required. Saves to `~/.config/hal/sandbox-config.yaml`.

Same interactive flow as today, plus new prompts at the end:

```
── Defaults ──
Auto-shutdown after idle? (y/n) [y]:
Idle timeout hours [48]:
```

### `hal sandbox start`

```bash
hal sandbox start -n api-backend                     # one sandbox
hal sandbox start -n worker --count 5                # worker-01..worker-05
hal sandbox start -n gpu --size s-4vcpu-8gb           # size override
hal sandbox start -n quick --idle-hours 4             # custom idle timeout
hal sandbox start -n long-run --no-auto-shutdown      # never auto-stop
hal sandbox start -n app --repo github.com/me/app     # repo label
hal sandbox start -n redo --force                     # replace existing
```

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-n, --name` | string | current git branch | Sandbox name |
| `--count` | int | 1 | Batch create (appends `-01` .. `-N`) |
| `-e, --env` | []string | — | Extra env vars `KEY=VALUE` |
| `--repo` | string | — | Repo label (stored, not used operationally) |
| `--size` | string | from config | Provider size override |
| `--auto-shutdown` | bool | from config | Enable idle shutdown |
| `--no-auto-shutdown` | — | — | Disable idle shutdown |
| `--idle-hours` | int | from config (48) | Idle hours before shutdown |
| `--force` | bool | false | Replace existing sandbox with same name |

**Tailscale**: Each sandbox automatically gets `TAILSCALE_HOSTNAME=hal-{name}` injected into env vars. User adds `hal-api-backend` to Termius once — hostname is stable across reboots and IP changes.

**Batch creation**: Sandboxes are created concurrently. Progress is streamed:

```
Creating 5 sandboxes (digitalocean)...
  ✓ worker-01  100.64.1.10  (hal-worker-01)
  ✓ worker-02  100.64.1.11  (hal-worker-02)
  ✗ worker-03  error: rate limit exceeded
  ✓ worker-04  100.64.1.13  (hal-worker-04)
  ✓ worker-05  100.64.1.14  (hal-worker-05)

4/5 created (1 failed). Failed sandboxes were not registered.
```

**Partial failure**: Successful instances are kept and registered. Failed instances are reported but not rolled back. Exit code 1 if any failed. User can `hal sandbox delete --pattern "worker-*"` to clean up.

### `hal sandbox list`

```
$ hal sandbox list

NAME           PROVIDER       STATUS    TAILSCALE         AGE    AUTO-OFF    EST.COST
api-backend    digitalocean   running   hal-api-backend   2h     48h idle    $0.07
frontend       digitalocean   running   hal-frontend      2h     48h idle    $0.07
worker-01      digitalocean   stopped   hal-worker-01     1d     48h idle    $0.84 ⚠
worker-02      digitalocean   stopped   hal-worker-02     1d     48h idle    $0.84 ⚠

4 sandboxes (2 running, 2 stopped)  •  Est. total: $1.82
⚠ = still billing while stopped (delete to stop charges)
```

| Flag | Type | Description |
|------|------|-------------|
| `--json` | bool | Machine-readable JSON (contract v1) |
| `--live` | bool | Query provider APIs for fresh status |
| `--running` | bool | Only show running sandboxes |
| `-q, --quiet` | bool | Names only, one per line (for scripting) |

**Status freshness**: `list` reads local registry files only (fast, <100ms). `list --live` queries each provider API (slow, seconds). `status NAME` always queries live.

### `hal sandbox stop`

```bash
hal sandbox stop api-backend            # one
hal sandbox stop worker-01 worker-02    # multiple
hal sandbox stop --all                  # all running
hal sandbox stop --pattern "worker-*"   # glob
hal sandbox stop                        # auto: if exactly 1 running → stop it; else error with choices
```

### `hal sandbox delete`

```bash
hal sandbox delete api-backend          # one
hal sandbox delete worker-01 worker-02  # multiple
hal sandbox delete --all                # all (prompts confirmation)
hal sandbox delete --all --yes          # skip confirmation
hal sandbox delete --pattern "worker-*" # glob
hal sandbox delete                      # auto: if exactly 1 → delete it; else error with choices
```

### `hal sandbox ssh`

```bash
hal sandbox ssh api-backend             # interactive shell
hal sandbox ssh api-backend -- ls -la   # remote command
hal sandbox ssh                         # auto: if exactly 1 → connect; else error with choices
```

Auto-connect hint when exactly one sandbox:
```
Connecting to only active sandbox "api-backend"...
(tip: use 'hal sandbox ssh <name>' when multiple sandboxes exist)
```

### `hal sandbox status [NAME]`

```bash
hal sandbox status api-backend   # detailed live query to provider
hal sandbox status               # no args = alias for 'hal sandbox list'
```

### `hal sandbox migrate`

```bash
hal sandbox migrate              # non-interactive, idempotent
```

---

## 8. Auto-Shutdown

### Scope

| Provider | Mechanism | v1 support |
|----------|-----------|------------|
| Hetzner | cloud-init systemd timer | ✅ |
| DigitalOcean | cloud-init systemd timer | ✅ |
| Lightsail | cloud-init systemd timer | ✅ |
| Daytona | Platform-managed idle timeout | ❌ skip — document only |

### Implementation

Cloud-init injects a systemd timer + idle-check script when `HAL_AUTO_SHUTDOWN=true`:

- Timer fires every 15 minutes.
- Script checks last SSH/PTY activity via `/var/run/utmp`.
- If idle longer than `HAL_IDLE_HOURS` (default 48), runs `shutdown -h now`.
- When `HAL_AUTO_SHUTDOWN=false`, no timer is installed.

New env vars injected at creation time:
```
HAL_AUTO_SHUTDOWN=true
HAL_IDLE_HOURS=48
```

---

## 9. Cost Tracking

### Billing reality

All VPS providers bill until the instance is **deleted**, regardless of stopped state:

| Provider | Charges when stopped | Why |
|----------|---------------------|-----|
| Hetzner | **Yes** | Server resources reserved |
| DigitalOcean | **Yes** | Disk and IP retained |
| Lightsail | **Yes** | Instance billed until deleted |
| Daytona | Platform-managed | No local tracking |

### Calculation

```
cost = hours_since_creation × hourly_rate
```

`StoppedAt` is used for display purposes ("stopped 2h ago") but not for cost — cost always accrues from `CreatedAt` until deletion removes the registry entry.

### Embedded price table

```go
var hourlyRates = map[string]map[string]float64{
    "digitalocean": {"s-1vcpu-1gb": 0.00893, "s-2vcpu-4gb": 0.03571, "s-4vcpu-8gb": 0.07143},
    "hetzner":      {"cx22": 0.0065, "cx32": 0.0125, "cx42": 0.0238},
    "lightsail":    {"nano_3_0": 0.00556, "small_3_0": 0.01389, "medium_3_0": 0.02778},
}
```

Unknown sizes show `—` in list output. Returns `-1` programmatically for unknown.

---

## 10. File Security

| Path | Permissions | Contents |
|------|-------------|----------|
| `~/.config/hal/` | 0700 | Directory |
| `~/.config/hal/sandboxes/` | 0700 | Directory |
| `~/.config/hal/sandbox-config.yaml` | 0600 | API keys, tokens |
| `~/.config/hal/sandboxes/*.json` | 0600 | IPs, workspace IDs |

All file writes use temp-file + `os.Rename` for atomicity. Batch `--count` writes to separate files (no shared file), so no locking is needed.

Secrets (API keys, tokens) are never printed to stdout. `list` output shows only IPs and hostnames.

---

## 11. Doctor + Legacy Cleanup

### Doctor check

```
ID:            legacy_sandbox_state
Severity:      warn
Scope:         migration
Message:       Legacy .hal/sandbox.json found — run 'hal sandbox migrate'
Remediation:   { Command: "hal sandbox migrate", Safe: true }
```

`hal sandbox migrate` is non-interactive and idempotent — safe for automated remediation via `hal repair`.

### Cleanup rules

`.hal/sandbox.json` is **not** added to `orphanedFiles` (which deletes blindly). Instead:

- Migration code removes it only after verified successful write to global registry.
- Doctor warns if it's still present (migration hasn't run or failed).
- `hal sandbox migrate` handles the conditional removal.

---

## 12. Machine-Readable Contract

### `docs/contracts/sandbox-list-v1.md`

```json
{
  "contractVersion": 1,
  "sandboxes": [
    {
      "id": "019513a4-7e2b-7c1a-8a3e-1f2b3c4d5e6f",
      "name": "api-backend",
      "provider": "digitalocean",
      "status": "running",
      "createdAt": "2026-03-20T22:00:36Z",
      "ip": "104.131.5.22",
      "tailscaleIp": "100.64.1.10",
      "tailscaleHostname": "hal-api-backend",
      "autoShutdown": true,
      "idleHours": 48,
      "size": "s-2vcpu-4gb",
      "estimatedCost": 0.07
    }
  ],
  "totals": {
    "total": 4,
    "running": 2,
    "stopped": 2,
    "estimatedCost": 1.82
  }
}
```

**Required fields** on each sandbox object: `id`, `name`, `provider`, `status`, `createdAt`.
**Optional fields** (omitempty): `ip`, `tailscaleIp`, `tailscaleHostname`, `workspaceId`, `stoppedAt`, `autoShutdown`, `idleHours`, `size`, `repo`, `estimatedCost`.

Locked by field-name tests in `cmd/machine_contracts_test.go` and doc-sync tests in `cmd/contracts_doc_test.go`.

---

## 13. Backward Compatibility

| Old command | Old behavior | New behavior |
|-------------|-------------|--------------|
| `hal sandbox start -n dev` | Creates one, saves to `.hal/sandbox.json` | Creates one, saves to `~/.config/hal/sandboxes/dev.json` |
| `hal sandbox ssh` (no name) | Loads `.hal/sandbox.json` | If exactly 1 sandbox → connect + hint. If 0 → error. If >1 → error listing choices. |
| `hal sandbox stop` (no name) | Loads `.hal/sandbox.json` | If exactly 1 running → stop + hint. If 0 → error. If >1 → error listing choices. |
| `hal sandbox delete` (no name) | Loads `.hal/sandbox.json` | If exactly 1 → delete + hint. If 0 → error. If >1 → error listing choices. |
| `hal sandbox status` (no name) | Loads `.hal/sandbox.json` | Alias for `hal sandbox list`. |
| `hal sandbox setup` | Requires `.hal/` | Works from any directory. |
| First run after upgrade | — | Auto-migrates `.hal/sandbox.json` + config to global. |

---

## 14. File Map

```
internal/sandbox/
├── global.go                ← GlobalDir(), SandboxesDir(), EnsureGlobalDir()
├── globalconfig.go          ← GlobalConfig type, Load/Save, DefaultGlobalConfig()
├── uuid.go                  ← UUIDSource (injectable clock+rand), NewV7()
├── name.go                  ← ValidateName (59 cap), SanitizeName, BatchNames (dynamic width),
│                              TailscaleHostname, SandboxNameFromBranch
├── registry.go              ← SaveInstance, LoadInstance, ListInstances, RemoveInstance,
│                              ForceWriteInstance, ResolveDefault
├── migrate.go               ← Migrate(), 8-case matrix, conditional state cleanup, cross-device safe
├── pricing.go               ← hourlyRates, EstimatedCost (all VPS charge when stopped)
├── provider.go              ← ConnectInfo, Provider interface (refactored signatures)
├── provider_daytona.go      ← uses ConnectInfo.Name (no StateDir)
├── provider_digitalocean.go ← uses ConnectInfo.IP + .WorkspaceID (no StateDir/resolveDropletTarget)
├── provider_hetzner.go      ← uses ConnectInfo.IP (no StateDir)
├── provider_lightsail.go    ← uses ConnectInfo.IP (no StateDir)
├── tailscale.go             ← unchanged
├── types.go                 ← expanded SandboxState
└── *_test.go

cmd/
├── sandbox.go               ← setup → saves globally, no .hal/ dep
├── sandbox_start.go         ← --count, --auto-shutdown, --size, --repo, --force, Tailscale hostname
├── sandbox_list.go          ← NEW: --json, --live, --running, --quiet
├── sandbox_stop.go          ← NAME args, --all, --pattern, no-name compat
├── sandbox_delete.go        ← NAME args, --all, --pattern, --yes, no-name compat
├── sandbox_ssh.go           ← NAME required (or auto if 1), ConnectInfo
├── sandbox_status.go        ← NAME → live; no NAME → list alias
├── sandbox_migrate.go       ← NEW: non-interactive migration
└── *_test.go

docs/
├── contracts/sandbox-list-v1.md  ← NEW: JSON contract spec
└── cli/hal_sandbox_*.md          ← regenerated
```

---

## 15. Implementation Order

| Step | Deliverable | Depends on | Size |
|------|------------|------------|------|
| **1** | `global.go`, `uuid.go`, `name.go` + tests | — | S |
| **2** | `registry.go` + tests | 1 | M |
| **3** | `globalconfig.go` + tests | 1 | M |
| **4** | `migrate.go` + tests | 2, 3 | M |
| **5** | Provider interface refactor (all `provider_*.go`) + tests | — | L |
| **6** | `cmd/sandbox.go` setup → global | 3 | M |
| **7** | `cmd/sandbox_start.go` (batch, auto-shutdown, Tailscale hostnames) | 2, 3, 5 | L |
| **8** | `cmd/sandbox_list.go` + `pricing.go` + tests | 2 | M |
| **9** | `cmd/sandbox_stop.go` + `cmd/sandbox_delete.go` updates | 2, 5 | M |
| **10** | `cmd/sandbox_ssh.go` + `cmd/sandbox_status.go` updates | 2, 5 | S |
| **11** | `cmd/sandbox_migrate.go` + doctor check | 4 | S |
| **12** | Contract doc + field-lock tests + CLI metadata + README | 8 | M |

Steps 5 and 1–4 can run in parallel. Steps 6–10 can run in parallel after their dependencies complete.
