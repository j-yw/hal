## hal sandbox

Manage sandbox environments

### Synopsis

Manage sandbox environments for isolated development.

Supports multiple providers (Daytona, Hetzner, DigitalOcean, AWS Lightsail) — run
'hal sandbox setup' to choose a provider and configure credentials.

Subcommands:
  setup       Configure provider, credentials, and environment
  start       Create and start a sandbox
  stop        Stop a running sandbox
  status      Show sandbox status
  delete      Delete a sandbox
  ssh         Open an interactive shell or run a remote command

### Examples

```
  hal sandbox setup
  hal sandbox start
  hal sandbox status
```

### Options

```
  -h, --help   help for sandbox
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
* [hal sandbox delete](hal_sandbox_delete.md)	 - Delete one or more sandboxes permanently
* [hal sandbox list](hal_sandbox_list.md)	 - List all sandboxes
* [hal sandbox migrate](hal_sandbox_migrate.md)	 - Migrate legacy sandbox state to global config
* [hal sandbox setup](hal_sandbox_setup.md)	 - Configure sandbox credentials and environment
* [hal sandbox ssh](hal_sandbox_ssh.md)	 - Open an interactive shell or run a remote command
* [hal sandbox start](hal_sandbox_start.md)	 - Create and start a sandbox
* [hal sandbox status](hal_sandbox_status.md)	 - Show sandbox status
* [hal sandbox stop](hal_sandbox_stop.md)	 - Stop one or more running sandboxes

