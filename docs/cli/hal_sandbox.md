## hal sandbox

Manage sandbox environments

### Synopsis

Manage sandbox environments for isolated development.

Supports multiple providers (Daytona, Hetzner, DigitalOcean, AWS Lightsail) — run
'hal sandbox setup' to choose a provider and configure credentials.

Human output redacts public cloud and Tailscale addresses by default. Use
--show-addresses only when you intentionally need raw network addresses.

Side effects:
- setup writes global sandbox config under HAL_CONFIG_HOME, XDG_CONFIG_HOME, or
  ~/.config/hal.
- Lifecycle commands may create, start, stop, connect to, or delete remote cloud
  resources and update the global sandbox registry.

Subcommands:
  setup       Configure provider, credentials, and environment
  create      Provision a new sandbox
  start       Start a stopped sandbox
  stop        Power off / shut down a running sandbox
  status      Show sandbox status
  delete      Delete a sandbox
  ssh         Open an interactive shell or run a remote command

### Examples

```
  hal sandbox setup
  hal sandbox create
  hal sandbox start my-sandbox
  hal sandbox status
```

### Options

```
  -h, --help             help for sandbox
      --show-addresses   show raw sandbox network addresses in human output
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
* [hal sandbox create](hal_sandbox_create.md)	 - Provision a new sandbox
* [hal sandbox delete](hal_sandbox_delete.md)	 - Delete one or more sandboxes permanently
* [hal sandbox list](hal_sandbox_list.md)	 - List all sandboxes
* [hal sandbox migrate](hal_sandbox_migrate.md)	 - Migrate legacy sandbox state to global config
* [hal sandbox setup](hal_sandbox_setup.md)	 - Configure sandbox credentials and environment
* [hal sandbox ssh](hal_sandbox_ssh.md)	 - Open an interactive shell or run a remote command
* [hal sandbox start](hal_sandbox_start.md)	 - Start stopped sandboxes
* [hal sandbox status](hal_sandbox_status.md)	 - Show sandbox status
* [hal sandbox stop](hal_sandbox_stop.md)	 - Power off / shut down one or more running sandboxes
