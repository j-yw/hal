## hal sandbox create

Provision a new sandbox

### Synopsis

Provision a new sandbox using the configured provider (Daytona, Hetzner, DigitalOcean, or AWS Lightsail).

The sandbox name defaults to the current git branch (with slashes replaced by hyphens).
Use --name to override the default name.

Environment variables from global sandbox config are passed to the provider.
When no global sandbox config exists, legacy .hal/config.yaml sandbox.env values are used as a fallback.
Additional -e/--env flags overlay config values.

Use --size to override the provider-specific instance size from config:
  - Hetzner: server type (e.g., cx22, cx42)
  - DigitalOcean: droplet size (e.g., s-2vcpu-4gb)
  - Lightsail: bundle ID (e.g., small_3_0, medium_3_0)

Use --repo to tag the sandbox with a repository label (informational only).

Use --force to replace an existing sandbox with the same name (deletes the old one first).

Auto-shutdown injects HAL_AUTO_SHUTDOWN and HAL_IDLE_HOURS env vars into the sandbox
so that cloud-init can configure idle timers. Defaults come from global sandbox config.

Human output redacts public cloud and Tailscale addresses by default. Use
--show-addresses only when you intentionally need raw network addresses.

```
hal sandbox create [flags]
```

### Examples

```
  hal sandbox create
  hal sandbox create --name hal-dev
  hal sandbox create -n dev --size cx42
  hal sandbox create -n dev --force
  hal sandbox create -n dev --repo github.com/org/repo
  hal sandbox create -n dev -e TAILSCALE_AUTHKEY=tskey-auth-xxx -e ANTHROPIC_API_KEY=sk-ant-xxx
  hal sandbox create --no-auto-shutdown
  hal sandbox create --idle-hours 24
  hal sandbox create -n worker --count 5
```

### Options

```
      --auto-shutdown      enable auto-shutdown idle timer (default true)
      --count int          create N sandboxes with names {name}-01..{name}-N
  -e, --env stringArray    extra environment variables (KEY=VALUE, repeatable)
  -f, --force              replace existing sandbox with the same name
  -h, --help               help for create
      --idle-hours int     hours before idle shutdown (default from global config)
  -n, --name string        sandbox name (defaults to current git branch)
      --no-auto-shutdown   disable auto-shutdown idle timer
  -r, --repo string        repository label for the sandbox (informational)
  -s, --size string        override provider instance size (e.g., cx42, s-2vcpu-4gb)
```

### Options inherited from parent commands

```
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments
