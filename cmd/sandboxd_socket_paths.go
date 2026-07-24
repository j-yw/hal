package cmd

type sandboxdRuntimePaths struct {
	socketPath  string
	jobStateDir string
}

func defaultSandboxdSocketPath() string {
	return defaultSandboxdRuntimePaths().socketPath
}

func defaultSandboxdJobStateDir() string {
	return defaultSandboxdRuntimePaths().jobStateDir
}
