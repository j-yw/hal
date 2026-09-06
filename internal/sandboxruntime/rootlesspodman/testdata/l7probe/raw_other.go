//go:build !linux

package main

import "errors"

func requireRawIPDenied() error {
	return errors.New("raw socket probe unsupported")
}

func requireRawPacketDenied() error {
	return errors.New("raw socket probe unsupported")
}
