//go:build linux && network_enforcement_live

package policyproxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestL6PolicyProxyLiveHTTPAndConnect(t *testing.T) {
	if os.Getenv("HAL_NETWORK_ENFORCEMENT_LIVE") != "1" {
		t.Fatal("HAL_NETWORK_ENFORCEMENT_LIVE=1 is required")
	}
	if os.Getenv("HAL_NETWORK_ENFORCEMENT_LIVE_PROXY") != "1" {
		t.Fatal("HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=1 is required")
	}

	httpFixture := newHTTPFixture(t)
	echoFixture := newTCPEchoFixture(t)
	var dials atomic.Int32
	var decisions atomic.Int32
	adapter := newTestAdapter(t, testAdapterOptions{
		dial: mappingDialer(t, map[string]string{
			"93.184.216.34:80":  httpFixture,
			"93.184.216.34:443": echoFixture,
		}, &dials),
		sink: func(record networkenforcement.PolicyProxyDecisionLogRecord) {
			if record.Action == "" || record.ReasonCode == "" {
				t.Errorf("unsafe empty decision record: %#v", record)
			}
			decisions.Add(1)
		},
	})
	endpoint := startAdapter(t, adapter)
	t.Cleanup(func() { stopAdapter(t, adapter) })

	response, err := proxyClient(t, endpoint).Get("http://allowed.test/ok")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "upstream-ok" {
		t.Fatalf("HTTP live result = %d %q", response.StatusCode, body)
	}
	deniedHTTP, err := proxyClient(t, endpoint).Get("http://denied.test/no")
	if err != nil {
		t.Fatal(err)
	}
	_ = deniedHTTP.Body.Close()
	if deniedHTTP.StatusCode != http.StatusForbidden {
		t.Fatalf("denied HTTP live status = %d, want 403", deniedHTTP.StatusCode)
	}

	conn, reader := openCONNECT(t, endpoint)
	if _, err := io.WriteString(conn, "live"); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(reader, reply); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if string(reply) != "live" {
		t.Fatalf("CONNECT live reply = %q", reply)
	}

	deniedCONNECT, err := net.Dial(l6TestNetwork, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer deniedCONNECT.Close()
	if _, err := io.WriteString(deniedCONNECT, "CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	deniedResponse, err := http.ReadResponse(bufio.NewReader(deniedCONNECT), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = deniedResponse.Body.Close()
	if deniedResponse.StatusCode != http.StatusForbidden {
		t.Fatalf("denied CONNECT live status = %d, want 403", deniedResponse.StatusCode)
	}
	if dials.Load() != 2 || decisions.Load() != 4 {
		t.Fatalf("live counts = dials:%d decisions:%d, want 2/4", dials.Load(), decisions.Load())
	}
}
