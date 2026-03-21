## hal sandbox start

Create and start a sandbox

### Synopsis

Create and start a sandbox using the configured provider (Daytona, Hetzner, DigitalOcean, or AWS Lightsail).

The sandbox name defaults to the current git branch (with slashes replaced by hyphens).
Use --name to override the default name.

Environment variables from .hal/config.yaml sandbox.env section are passed to the provider.
Additional -e/--env flags overlay config values.

Use --size to override the provider-specific instance size from config:
  - Hetzner: server type (e.g., cx22, cx42)
  - DigitalOcean: droplet size (e.g., s-2vcpu-4gb)
  - Lightsail: bundle ID (e.g., small_3_0, medium_3_0)

Use --repo to tag the sandbox with a repository label (informational only).

Use --force to replace an existing sandbox with the same name (deletes the old one first).

Auto-shutdown injects HAL_AUTO_SHUTDOWN and HAL_IDLE_HOURS env vars into the sandbox
so that cloud-init can configure idle timers. Defaults come from global sandbox config.

```
hal sandbox start [flags]
```

### Examples

```
  hal sandbox start
  hal sandbox start --name hal-dev
  hal sandbox start -n dev --size cx42
  hal sandbox start -n dev --force
  hal sandbox start -n dev --repo github.com/org/repo
  hal sandbox start -n dev -e TAILSCALE_AUTHKEY=tskey-auth-xxx -e ANTHROPIC_API_KEY=sk-ant-xxx
  hal sandbox start --no-auto-shutdown
  hal sandbox start --idle-hours 24
  hal sandbox start -n worker --count 5
```

### Options

```
      --auto-shutdown      enable auto-shutdown idle timer (default true)
      --count int          create N sandboxes with names {name}-01..{name}-N
  -e, --env stringArray    extra environment variables (KEY=VALUE, repeatable)
  -f, --force              replace existing sandbox with the same name
  -h, --help               help for start
      --idle-hours int     hours before idle shutdown (default from global config)
  -n, --name string        sandbox name (defaults to current git branch)
      --no-auto-shutdown   disable auto-shutdown idle timer
  -r, --repo string        repository label for the sandbox (informational)
  -s, --size string        override provider instance size (e.g., cx42, s-2vcpu-4gb)
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

