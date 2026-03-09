## hal standards

Manage project standards

### Synopsis

Manage project-specific standards that guide AI agents during hal run.

Standards are concise, codebase-specific rules stored in .hal/standards/.
They are automatically injected into the agent prompt on every hal run iteration,
ensuring consistent code quality and pattern adherence.

Use 'hal standards discover' to interactively extract standards from your codebase.
Use 'hal standards list' to see what's currently configured.

### Examples

```
  hal standards list
  hal standards discover
```

### Options

```
  -h, --help   help for standards
```

### SEE ALSO

* [hal](hal.md)	 - Hal - Autonomous task executor using AI coding agents
* [hal standards discover](hal_standards_discover.md)	 - Discover and document standards from your codebase
* [hal standards list](hal_standards_list.md)	 - List configured standards

