## hal sandbox setup

Configure sandbox credentials and environment

### Synopsis

Interactive setup for sandbox credentials and environment variables.

First prompts for a provider:
  (1) Daytona — managed cloud sandbox (prompts for API key, server URL)
  (2) Hetzner — self-managed VPS (prompts for SSH key name, server type)

Then prompts for shared environment variables:
  • API keys (Anthropic, OpenAI) — masked input
  • GitHub token — masked input
  • Git identity (name, email)
  • Tailscale auth key and hostname — for SSH from mobile

All values are saved to .hal/config.yaml. Re-running setup lets you update
individual values — press Enter to keep the current value.

After setup, 'hal sandbox start' injects all configured env vars automatically.

```
hal sandbox setup [flags]
```

### Examples

```
  hal sandbox setup
```

### Options

```
  -h, --help   help for setup
```

### SEE ALSO

* [hal sandbox](hal_sandbox.md)	 - Manage sandbox environments

