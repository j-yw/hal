## hal sandbox start

Create and start a sandbox

### Synopsis

Create and start a sandbox using the configured provider (Daytona, Hetzner, DigitalOcean, or AWS Lightsail).

The sandbox name defaults to the current git branch (with slashes replaced by hyphens).
Use --name to override the default name.

Environment variables from .hal/config.yaml sandbox.env section are passed to the provider.
Additional -e/--env flags overlay config values.

```
hal sandbox start [flags]
```

### Examples

```
  hal sandbox start
  hal sandbox start --name hal-dev
  hal sandbox start -n dev -e TAILSCALE_AUTHKEY=tskey-auth-xxx -e ANTHROPIC_API_KEY=sk-ant-xxx
```

### Options

```
  -e, --env stringArray   environment variables (format: KEY=VALUE, can be repeated)
  -h, --help              help for start
  -n, --name string       sandbox name (defaults to current git branch)
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

