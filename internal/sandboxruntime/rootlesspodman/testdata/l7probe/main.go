package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(64)
	}
	var err error
	switch os.Args[1] {
	case "http":
		err = probeHTTP(os.Args[2])
	case "connect":
		err = probeCONNECT(os.Args[2])
	case "tcp":
		err = requireTCPDenied(os.Args[2])
	case "udp":
		err = requireUDPDenied(os.Args[2])
	case "icmp":
		err = requireRawIPDenied()
	case "packet":
		err = requireRawPacketDenied()
	default:
		err = errors.New("unsupported probe")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe failed")
		os.Exit(1)
	}
}

func probeHTTP(target string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(target)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || string(body) != "fixture-ok" {
		return errors.New("unexpected response")
	}
	return nil
}

func probeCONNECT(target string) error {
	proxyValue := os.Getenv("HTTPS_PROXY")
	if proxyValue == "" {
		return errors.New("proxy missing")
	}
	parsed, err := url.Parse(proxyValue)
	if err != nil {
		return err
	}
	connection, err := net.DialTimeout("tcp", parsed.Host, 3*time.Second)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = fmt.Fprintf(connection, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("connect denied")
	}
	if _, err = connection.Write([]byte("ping")); err != nil {
		return err
	}
	reply := make([]byte, 4)
	_, err = io.ReadFull(connection, reply)
	if err != nil || string(reply) != "ping" {
		return errors.New("echo failed")
	}
	return nil
}

func requireTCPDenied(target string) error {
	connection, err := net.DialTimeout("tcp", target, 750*time.Millisecond)
	if err != nil {
		return nil
	}
	_ = connection.Close()
	return errors.New("direct tcp unexpectedly connected")
}

func requireUDPDenied(target string) error {
	connection, err := net.DialTimeout("udp", target, 750*time.Millisecond)
	if err != nil {
		return nil
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(750 * time.Millisecond))
	if _, err = connection.Write([]byte("deny")); err != nil {
		return nil
	}
	buffer := make([]byte, 1)
	if _, err = connection.Read(buffer); err != nil {
		return nil
	}
	return errors.New("direct udp unexpectedly replied")
}
