package sandboxexecution

import (
	"io/fs"
	"os"
	"sync/atomic"
)

type atomicStoreFileWriter func(*os.File) error

type atomicStoreFilePublishHook func(string, string)

var atomicStoreFileBeforePublish atomic.Value

func init() {
	atomicStoreFileBeforePublish.Store(atomicStoreFilePublishHook(func(_, _ string) {}))
}

func runAtomicStoreFileBeforePublish(tempPath, destinationPath string) {
	atomicStoreFileBeforePublish.Load().(atomicStoreFilePublishHook)(tempPath, destinationPath)
}

func setAtomicStoreFileBeforePublishForTest(hook atomicStoreFilePublishHook) func() {
	if hook == nil {
		hook = func(_, _ string) {}
	}
	previous := atomicStoreFileBeforePublish.Load().(atomicStoreFilePublishHook)
	atomicStoreFileBeforePublish.Store(hook)
	return func() {
		atomicStoreFileBeforePublish.Store(previous)
	}
}

func writeStoreBytesAtomic(
	root string,
	components []string,
	displayPath string,
	data []byte,
	mode fs.FileMode,
	createParents bool,
) (fs.FileInfo, error) {
	return publishStoreFileAtomic(root, components, displayPath, mode, createParents, func(file *os.File) error {
		_, err := file.Write(data)
		return err
	})
}
