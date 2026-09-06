//go:build linux

package rootlesspodman

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
)

// runExecProcess owns the output pipes so output draining does not require
// cmd.Wait to reap the leader. In particular, a descendant can retain stdout
// after the leader exits: cancellation must still be observable then, while the
// unreaped leader continues to pin the process-group ID used for signaling.
func runExecProcess(ctx context.Context, cmd *exec.Cmd) (cancelled bool, err error) {
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return false, err
	}
	defer stdoutReader.Close()
	defer stdoutWriter.Close()
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		return false, err
	}
	defer stderrReader.Close()
	defer stderrWriter.Close()
	stdout, stderr := cmd.Stdout, cmd.Stderr
	cmd.Stdout, cmd.Stderr = stdoutWriter, stderrWriter
	if err := cmd.Start(); err != nil {
		return false, err
	}
	// Only the children retain the write ends after Start. Each copy owns its
	// read end until completion; cancellation may also close it to stop waiting
	// for an inherited descriptor outside the terminated process group.
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	outputCh := make(chan error, 2)
	copyOutput := func(reader *os.File, destination io.Writer) {
		if destination == nil {
			destination = io.Discard
		}
		_, copyErr := io.Copy(destination, reader)
		_ = reader.Close()
		outputCh <- copyErr
	}
	go copyOutput(stdoutReader, stdout)
	go copyOutput(stderrReader, stderr)
	completionCh := observeExecProcess(cmd)
	remainingOutputs := 2
	var outputErr error
	finishOutput := func() error {
		_ = stdoutReader.Close()
		_ = stderrReader.Close()
		for remainingOutputs > 0 {
			outputErr = errors.Join(outputErr, <-outputCh)
			remainingOutputs--
		}
		return outputErr
	}
	for completionCh != nil || remainingOutputs > 0 {
		select {
		case <-ctx.Done():
			if completionCh == nil {
				// Successful WNOWAIT observation was already consumed. Preserve
				// that proof for termination without reaping or observing again.
				observed := make(chan error, 1)
				observed <- nil
				completionCh = observed
			}
			err := terminateExecProcessGroup(cmd, completionCh)
			return true, errors.Join(err, finishOutput())
		case observationErr := <-completionCh:
			if observationErr != nil {
				// Observation failure provides no process-group identity proof.
				// The existing waiter kills only the tracked process and reaps it.
				err := waitExecProcess(cmd, observationErr)
				return false, errors.Join(err, finishOutput())
			}
			completionCh = nil
		case copyErr := <-outputCh:
			outputErr = errors.Join(outputErr, copyErr)
			remainingOutputs--
		}
	}
	return false, errors.Join(waitExecProcess(cmd, nil), outputErr)
}
