package main

import (
	"os"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost"
)

func main() {
	os.Exit(firecrackerhost.RunPrivateL8RuntimeOwnerExecutable(os.Args[1:], os.NewFile))
}
