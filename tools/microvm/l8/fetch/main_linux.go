//go:build linux

// fetch acquires the immutable L8 extension; it never installs or builds it.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	interrupt, cancelInterrupt := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancelInterrupt()
	ctx, cancel := context.WithTimeout(interrupt, 15*time.Minute)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func readManifestFile(name string) (map[string]lockedFile, error) {
	fd, err := unix.Open(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errCache
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxManifestBytes {
		return nil, errCache
	}
	return parseManifest(f)
}

func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("l8-cache", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cache := flags.String("cache", "", "absolute cache destination")
	l5cache := flags.String("l5-cache", "", "signature-verified L5 cache")
	l5manifest := flags.String("l5-manifest", "", "checked-in L5 manifest")
	l8manifest := flags.String("l8-manifest", "", "checked-in L8 manifest")
	verifyOnly := flags.Bool("verify-only", false, "read-only exact cache validation")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *cache == "" || *l5manifest == "" || *l8manifest == "" || (!*verifyOnly && *l5cache == "") {
		return errCache
	}
	l5, err := readManifestFile(*l5manifest)
	if err != nil {
		return err
	}
	l8, err := readManifestFile(*l8manifest)
	if err != nil {
		return err
	}
	if *verifyOnly {
		all, err := combineLocks(l5, l8)
		if err != nil {
			return err
		}
		return verifyCache(ctx, *cache, all)
	}
	client := newHTTPClient(nil)
	defer client.CloseIdleConnections()
	return acquireCache(ctx, *cache, *l5cache, l5, l8, client)
}
