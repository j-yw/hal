# Pointer-Based YAML Defaults

Use pointer fields (`*string`, `*int`) in raw YAML config structs to distinguish missing keys from explicit values.

## Problem

Plain `string`/`int` fields unmarshal to zero values (`""`, `0`) whether the key is missing or explicitly empty. This breaks two things:
- **Defaults**: Can't tell "unset → use default" from "set to empty"
- **Validation**: Can't tell `maxIterations: 0` (user error) from omitted (should default to 25)

## Pattern

```go
// Raw struct for YAML unmarshaling — pointer fields
type rawAutoConfig struct {
    ReportsDir    *string  `yaml:"reportsDir"`
    MaxIterations *int     `yaml:"maxIterations"`
}

// Clean struct for application use — value fields
type AutoConfig struct {
    ReportsDir    string
    MaxIterations int
}

// Merge: nil → default, non-nil → use value (then validate)
defaults := DefaultAutoConfig()
if raw.ReportsDir != nil {
    defaults.ReportsDir = *raw.ReportsDir
}
```

## Rules

- Raw config structs are **only** for unmarshaling — never pass them around
- Always merge into a defaults struct, then validate the merged result
- Validate() checks the **merged** values, catching both missing-and-defaulted and explicitly-invalid cases
