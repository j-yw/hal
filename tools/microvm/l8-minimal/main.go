//go:build linux

// l8-minimal is an offline staged-input image publisher, not a runtime command.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/minimalprofile"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout, minimalprofile.Publish); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer, publish func(context.Context, minimalprofile.PublishRequest) (minimalprofile.Receipt, error)) error {
	flags := flag.NewFlagSet("l8-minimal", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	request := flags.String("request", "", "trusted producer request JSON")
	digest := flags.String("request-sha256", "", "independent expected request SHA-256")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *request == "" || *digest == "" {
		return errors.New("usage: l8-minimal -request ABS_JSON -request-sha256 TRUSTED_SHA256")
	}
	input, err := minimalprofile.ReadPublishRequest(*request, *digest)
	if err != nil {
		return errors.New("minimal image: trusted request rejected")
	}
	receipt, err := publish(ctx, input)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(receipt)
}
