//go:build linux

package main

import (
	"errors"
	"syscall"
)

func requireRawIPDenied() error {
	return requireRawDenied(syscall.AF_INET, syscall.IPPROTO_ICMP)
}

func requireRawPacketDenied() error {
	return requireRawDenied(syscall.AF_PACKET, int(htons(0x0003)))
}

func requireRawDenied(family, protocol int) error {
	fd, err := syscall.Socket(family, syscall.SOCK_RAW, protocol)
	if err == syscall.EPERM || err == syscall.EACCES {
		return nil
	}
	if err != nil {
		return err
	}
	_ = syscall.Close(fd)
	return errors.New("raw socket unexpectedly opened")
}

func htons(value uint16) uint16 { return value<<8 | value>>8 }
