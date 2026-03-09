## hal archive create

Archive current feature state

### Synopsis

Archive all feature state files from .hal/ into .hal/archive/<date>-<name>/.

Use --name/-n to set the archive name, or omit it to be prompted interactively.

```
hal archive create [flags]
```

### Examples

```
  hal archive create
  hal archive create --name checkout-flow
```

### Options

```
  -h, --help          help for create
  -n, --name string   Archive name (default: derived from branch name)
```

### SEE ALSO

* [hal archive](hal_archive.md)	 - Archive current feature state

