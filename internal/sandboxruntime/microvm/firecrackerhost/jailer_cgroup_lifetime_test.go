package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestJailerCgroupLaunchCallbackSerializesQuiescence(t *testing.T) {
	lease := testJailerCgroupLease(t, "run-1")
	entered, release := make(chan struct{}), make(chan struct{})
	launchDone, cleanupDone := make(chan error, 1), make(chan error, 1)
	var borrowed *os.File
	go func() {
		launchDone <- lease.withLaunchFD(context.Background(), "run-1", func(fd *os.File) error { borrowed = fd; close(entered); <-release; return nil })
	}()
	<-entered
	go func() { cleanupDone <- lease.quiesce(context.Background()) }()
	select {
	case <-cleanupDone:
		t.Fatal("cleanup raced the launch callback")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-launchDone; err != nil {
		t.Fatal(err)
	}
	if err := <-cleanupDone; err != nil {
		t.Fatal(err)
	}
	if _, err := borrowed.Stat(); err == nil {
		t.Fatal("launch descriptor survived callback")
	}
	if lease.release() != nil {
		t.Fatal("serialized release failed")
	}
}

func TestJailerCgroupCallbackFailureCancellationAndPanicCloseFD(t *testing.T) {
	for _, name := range []string{"failure", "cancel", "panic", "close failure"} {
		t.Run(name, func(t *testing.T) {
			lease := testJailerCgroupLease(t, "run-1")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var borrowed *os.File
			var recovered any
			var err error
			func() {
				defer func() { recovered = recover() }()
				err = lease.withLaunchFD(ctx, "run-1", func(fd *os.File) error {
					borrowed = fd
					switch name {
					case "cancel":
						cancel()
						return nil
					case "panic":
						panic("fixture callback")
					case "close failure":
						_ = fd.Close()
						return nil
					}
					return errors.New("fixture failure")
				})
			}()
			if name == "panic" {
				if recovered == nil {
					t.Fatal("fixture panic not exercised")
				}
			} else if err == nil {
				t.Fatal("callback failure ignored")
			}
			if borrowed == nil {
				t.Fatal("callback not entered")
			}
			if _, err := borrowed.Stat(); err == nil {
				t.Fatal("failed callback leaked descriptor")
			}
			if lease.withLaunchFD(context.Background(), "run-1", func(*os.File) error { return nil }) == nil {
				t.Fatal("spent launch authority replayed")
			}
		})
	}
}
