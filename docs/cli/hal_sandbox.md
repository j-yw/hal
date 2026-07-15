## hal sandbox

Manage sandbox environments

### Synopsis

Manage sandbox environments for isolated development.

Supports multiple providers (Hetzner, DigitalOcean, AWS Lightsail) and
registered sandboxd worker hosts. Run 'hal sandbox setup' to choose a provider
and configure cloud credentials.

Human output redacts public cloud and Tailscale addresses by default. Use
--show-addresses only when you intentionally need raw network addresses.

Side effects:
- setup writes global sandbox config under HAL_CONFIG_HOME, XDG_CONFIG_HOME, or
  ~/.config/hal.
- Lifecycle commands may create, start, stop, connect to, or delete remote cloud
  resources or worker runtime instances and update the global sandbox registry.

Subcommands:
  auth        Manage sandbox agent auth profiles
  apply       Apply one completed sandbox execution to the current worktree
  setup       Configure provider, credentials, and environment
  create      Provision a new sandbox
  start       Start a stopped sandbox
  stop        Power off / shut down a running sandbox
  status      Show sandbox status
  delete      Delete a sandbox
  host        Manage durable sandbox host records
  runtime     Inspect sandbox runtime metadata
  ssh         Open an interactive shell or run a remote command

### Examples

```
  hal sandbox setup
  hal sandbox create
  hal sandbox apply run-1784128525446734264
  hal sandbox auth sync my-sandbox
  hal sandbox runtime list local-worker
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
* [hal sandbox apply](hal_sandbox_apply.md)	 - Apply a completed sandbox execution to the current worktree
* [hal sandbox auth](hal_sandbox_auth.md)	 - Manage sandbox agent auth profiles
* [hal sandbox create](hal_sandbox_create.md)	 - Provision a new sandbox
* [hal sandbox delete](hal_sandbox_delete.md)	 - Delete one or more sandboxes permanently
* [hal sandbox host](hal_sandbox_host.md)	 - Manage sandbox host records
* [hal sandbox list](hal_sandbox_list.md)	 - List all sandboxes
* [hal sandbox migrate](hal_sandbox_migrate.md)	 - Migrate legacy sandbox state to global config
* [hal sandbox runtime](hal_sandbox_runtime.md)	 - Inspect sandbox runtime metadata
* [hal sandbox setup](hal_sandbox_setup.md)	 - Configure sandbox credentials and environment
* [hal sandbox ssh](hal_sandbox_ssh.md)	 - Open an interactive shell or run a remote command
* [hal sandbox start](hal_sandbox_start.md)	 - Start stopped sandboxes
* [hal sandbox status](hal_sandbox_status.md)	 - Show sandbox status
* [hal sandbox stop](hal_sandbox_stop.md)	 - Power off / shut down one or more running sandboxes
